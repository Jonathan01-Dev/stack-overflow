# /share /home/koffi/Bureau/PHOTOS/BBOX EDF.jpg
import argparse
import socket
import struct
import threading
import time
import json
import os
import nacl.signing
import nacl.encoding
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    load_dotenv = None

from peer_table import PeerTable
from tlv import (
    encode_tlv, decode_tlv, TYPE_PEER_LIST, TYPE_PING, TYPE_PONG,
    TYPE_HANDSHAKE_HELLO, TYPE_HANDSHAKE_REPLY, TYPE_HANDSHAKE_AUTH,
    TYPE_HANDSHAKE_OK, TYPE_SECURE_MSG, TYPE_CHAT_MSG,
    TYPE_MANIFEST, TYPE_CHUNK_REQ, TYPE_CHUNK_DATA, TYPE_CHUNK_ACK
)
from crypto_manager import CryptoManager, CryptoSession, generate_ephemeral_keypair, compute_shared_secret
from file_manager import FileManager
from storage_manager import StorageManager
from transfer_manager import TransferManager

MCAST_GRP = '239.255.42.99'
MCAST_PORT = 6000
TCP_PORT = int(os.environ.get("TCP_PORT", 7777))

# Parser les arguments pour supporter plusieurs instances locales pour le test S1
parser = argparse.ArgumentParser(description="P2P Discovery Node")
parser.add_argument('--port', type=int, help="Override TCP port", default=None)
parser.add_argument('--key', type=str, help="Override path to node.key for multiple instances", default="node.key")
args = parser.parse_args()

if args.port:
    TCP_PORT = args.port

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KEY_PATH = os.path.join(PROJECT_ROOT, args.key)

def get_private_key():
    if not os.path.exists(KEY_PATH):
        print(f"[-] Fichier node.key introuvable ({KEY_PATH}). Veuillez exécuter src/crypto/generate_identity.py au préalable.")
        return None
    
    try:
        with open(KEY_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception as e:
        print(f"[-] Erreur de lecture de l'identité : {e}")
        return None

NODE_PRIVATE_HEX = get_private_key()
if NODE_PRIVATE_HEX:
    _tmp_signer = nacl.signing.SigningKey(NODE_PRIVATE_HEX, encoder=nacl.encoding.HexEncoder)
    NODE_ID = _tmp_signer.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
else:
    NODE_ID = "UNKNOWN_NODE"

class DiscoveryNode:
    def __init__(self):
        self.node_id = NODE_ID  # Rendre l'ID accessible aux autres managers
        self.peer_table = PeerTable()
        self.crypto = CryptoManager(NODE_PRIVATE_HEX)
        self.active_sessions = {} # {node_id: CryptoSession}
        self.active_connections = {} # {node_id: socket}
        self.connections_lock = threading.Lock()
        
        self.file_mgr = FileManager()
        # Isolation du stockage par port pour les tests locaux (ex: .archipel_7777)
        storage_root = os.path.join(PROJECT_ROOT, f".archipel_{TCP_PORT}")
        self.storage_mgr = StorageManager(root_dir=storage_root)
        self.transfer_mgr = TransferManager(self)
        
        # Manifests reçus du réseau : {file_id: manifest}
        self.network_manifests = {}

    def start_beacon(self):
        """Envoie un paquet HELLO toutes les 30 secondes"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        def run():
            while True:
                hello = {
                    "type": "HELLO",
                    "node_id": NODE_ID,
                    "tcp_port": TCP_PORT,
                    "timestamp": time.time()
                }
                packet = json.dumps(hello).encode('utf-8')
                
                # Forcer l'envoi sur TOUTES les cartes réseau (VirtualBox, Wi-Fi, Ethernet...)
                try:
                    host_name = socket.gethostname()
                    local_ips = socket.gethostbyname_ex(host_name)[2]
                except Exception:
                    local_ips = []
                local_ips.append("0.0.0.0") # Toujours tenter le comportement par défaut
                
                for ip in set(local_ips):
                    try:
                        if ip != "0.0.0.0":
                            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))
                        sock.sendto(packet, (MCAST_GRP, MCAST_PORT))
                    except Exception:
                        pass

                # Fallback: Envoi en Broadcast (Très utile pour les Hotspots Android)
                try:
                    sock.sendto(packet, ('<broadcast>', MCAST_PORT))
                except Exception:
                    pass
                try:
                    sock.sendto(packet, ('255.255.255.255', MCAST_PORT))
                except Exception:
                    pass

                print(f"[*] HELLO envoyé (Multicast + Broadcast fallback)")
                time.sleep(30)
        
        threading.Thread(target=run, daemon=True).start()

    def start_listener(self):
        """Écoute les paquets HELLO des autres"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        # Liaison au port multicast
        try:
            # Sous Windows, l'écoute sur '' (0.0.0.0) écoute partout
            sock.bind(('', MCAST_PORT))
        except OSError:
            pass
        
        # Rejoindre le groupe multicast sur TOUTES les interfaces réseau actives simultanément
        group = socket.inet_aton(MCAST_GRP)
        
        try:
            host_name = socket.gethostname()
            local_ips = socket.gethostbyname_ex(host_name)[2]
        except Exception:
            local_ips = []
        local_ips.append("0.0.0.0") # Comportement INADDR_ANY par défaut
        
        for ip in set(local_ips):
            try:
                if ip == "0.0.0.0":
                    mreq = struct.pack('4sL', group, socket.INADDR_ANY)
                else:
                    mreq = struct.pack('4s4s', group, socket.inet_aton(ip))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except Exception:
                pass

        def run():
            print(f"[+] Écoute Multicast sur {MCAST_GRP}:{MCAST_PORT}...")
            while True:
                data, addr = sock.recvfrom(1024)
                pkt = json.loads(data.decode('utf-8'))
                
                if pkt['node_id'] != NODE_ID:
                    # Mise à jour ou ajout dans la Peer Table
                    is_new = self.peer_table.add_or_update_peer(
                        pkt['node_id'], addr[0], int(pkt['tcp_port'])
                    )
                    
                    if is_new:
                        print(f"[!] Nouveau pair détecté par HELLO : {pkt['node_id']} à {addr[0]}")
                        # Essayer d'établir une connexion persistante
                        self.connect_to_peer(pkt['node_id'], addr[0], int(pkt['tcp_port']))
        
        threading.Thread(target=run, daemon=True).start()

    def connect_to_peer(self, peer_id, target_ip, target_port):
        """Tente d'établir une connexion persistante et d'initier le Handshake"""
        with self.connections_lock:
            if peer_id in self.active_connections:
                return 
                
        def run():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5.0)
                s.connect((target_ip, target_port))
                s.settimeout(None)
                
                # Séquence de Handshake (Alice)
                session = self._perform_handshake_alice(s, peer_id)
                if session:
                    with self.connections_lock:
                        self.active_connections[peer_id] = s
                        self.active_sessions[peer_id] = session
                    
                    print(f"[+] Tunnel E2EE établi avec {peer_id[:8]} (X25519 + AES-GCM)")
                    self._send_secure_tlv(peer_id, TYPE_PEER_LIST, self._build_peer_list_payload())
                    
                    # Sync : Envoyer nos manifests locaux au nouveau pair
                    self._sync_manifests_with_peer(peer_id)
                    
                    # Listener dédié
                    threading.Thread(target=self._handle_client, args=(s, peer_id), daemon=True).start()
                else:
                    s.close()
            except Exception:
                pass 
                
        threading.Thread(target=run, daemon=True).start()

    def _perform_handshake_alice(self, sock, peer_id):
        """Alice initie le handshake."""
        try:
            # 1. HELLO (e_A_pub)
            e_priv, e_pub = generate_ephemeral_keypair()
            from cryptography.hazmat.primitives import serialization
            e_pub_bytes = e_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            
            sock.sendall(encode_tlv(TYPE_HANDSHAKE_HELLO, {"e_pub": e_pub_bytes.hex(), "timestamp": time.time()}))
            
            # 2. Recevoir HELLO_REPLY (e_B_pub, sig_B)
            m_type, resp = decode_tlv(sock)
            if m_type != TYPE_HANDSHAKE_REPLY: return None
            
            e_b_pub_hex = resp['e_pub']
            sig_b_hex = resp['sig']
            e_b_pub_bytes = bytes.fromhex(e_b_pub_hex)
            sig_b_bytes = bytes.fromhex(sig_b_hex)
            
            # Vérifier signature de Bob (Web of Trust / TOFU)
            if not self.crypto.verify(e_b_pub_bytes, sig_b_bytes, peer_id):
                print(f"[!] Échec Handshake : Signature de Bob invalide !")
                return None
            
            # 3. Calculer secret et envoyer AUTH
            shared = compute_shared_secret(e_priv, e_b_pub_bytes)
            import hashlib
            shared_hash = hashlib.sha256(shared).digest()
            sig_a = self.crypto.sign(shared_hash)
            
            session = CryptoSession(shared)
            # On envoie AUTH chiffré (contient notre NODE_ID et la signature)
            auth_payload = json.dumps({"node_id": NODE_ID, "sig": sig_a.hex()}).encode('utf-8')
            nonce, encrypted_auth = session.encrypt(auth_payload)
            sock.sendall(encode_tlv(TYPE_HANDSHAKE_AUTH, {"nonce": nonce.hex(), "auth": encrypted_auth.hex()}))
            
            # 4. Recevoir OK
            m_type, resp = decode_tlv(sock)
            if m_type == TYPE_HANDSHAKE_OK:
                return session
        except Exception as e:
            print(f"[-] Erreur Handshake Alice : {e}")
        return None

    def _build_peer_list_payload(self):
        peers_to_send = {}
        for pid, info in self.peer_table.get_all().items():
            peers_to_send[pid] = {"ip": info["ip"], "port": info["tcp_port"]}
        return {"sender_id": NODE_ID, "peers": peers_to_send}

    def _send_secure_tlv(self, peer_id, msg_type, payload):
        """Encapsule un message TLV dans un tunnel AES-GCM"""
        with self.connections_lock:
            sock = self.active_connections.get(peer_id)
            session = self.active_sessions.get(peer_id)
            
        if not sock or not session: return
        
        try:
            # On encode le sous-message TLV interne
            inner_data = encode_tlv(msg_type, payload)
            nonce, ciphertext = session.encrypt(inner_data)
            
            # On envoie le paquet TYPE_SECURE_MSG
            sock.sendall(encode_tlv(TYPE_SECURE_MSG, {
                "nonce": nonce.hex(),
                "data": ciphertext.hex()
            }))
        except Exception:
            pass
        
    def start_tcp_server(self):
        """Serveur TCP pour recevoir les PEER_LIST en unicast"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Sur certaines machines, binding sur un port spécifique pose problème si non dispo
        # Mais le test S1 exige l'écoute.
        sock.bind(('0.0.0.0', TCP_PORT))
        sock.listen(20) # Min 10 connections parallèles exigées par S1, 20 c'est safe.
        
        def run():
            print(f"[+] Serveur TCP (Unicast/Persistant) démarré sur le port {TCP_PORT}...")
            while True:
                conn, addr = sock.accept()
                threading.Thread(target=self._handle_client, args=(conn, None), daemon=True).start()
                        
        threading.Thread(target=run, daemon=True).start()

    def _handle_client(self, conn, initial_peer_id=None):
        """Gère une connexion TCP sécurisée (Bob)"""
        peer_id = initial_peer_id
        session = None
        
        try:
            # 1. Si on est Bob (initial_peer_id is None), on commence par le handshake
            if peer_id is None:
                session, peer_id = self._perform_handshake_bob(conn)
                if not session:
                    conn.close()
                    return
                with self.connections_lock:
                    self.active_sessions[peer_id] = session
                    self.active_connections[peer_id] = conn
                print(f"[+] Tunnel E2EE établi avec {peer_id[:8]} (X25519 + AES-GCM)")
                
                # Sync : Envoyer nos manifests locaux au nouveau pair
                self._sync_manifests_with_peer(peer_id)
            else:
                with self.connections_lock:
                    session = self.active_sessions.get(peer_id)

            # 2. Boucle de réception sécurisée
            while True:
                msg_type, payload = decode_tlv(conn)
                if msg_type is None: break
                
                if msg_type == TYPE_SECURE_MSG:
                    nonce = bytes.fromhex(payload['nonce'])
                    ciphertext = bytes.fromhex(payload['data'])
                    plaintext = session.decrypt(nonce, ciphertext)
                    if plaintext is None: 
                        print(f"[!] Erreur de déchiffrement (Tunnel compromis ?)")
                        break
                    
                    i_type, i_payload = self._decode_tlv_from_bytes(plaintext)
                    self._process_message(peer_id, i_type, i_payload)
                
                elif msg_type == TYPE_PING:
                    conn.sendall(encode_tlv(TYPE_PONG, {}))
                    
        except Exception as e:
            pass
        finally:
            conn.close()
            with self.connections_lock:
                if peer_id and peer_id in self.active_connections:
                    del self.active_connections[peer_id]
                if peer_id and peer_id in self.active_sessions:
                    del self.active_sessions[peer_id]

    def _perform_handshake_bob(self, conn):
        """Bob répond au handshake Alice."""
        try:
            # 1. Recevoir HELLO (e_A_pub)
            m_type, req = decode_tlv(conn)
            if m_type != TYPE_HANDSHAKE_HELLO: return None, None
            e_a_pub_hex = req['e_pub']
            e_a_pub_bytes = bytes.fromhex(e_a_pub_hex)
            
            # 2. Générer e_B, calculer secret et envoyer REPLY
            e_priv, e_pub = generate_ephemeral_keypair()
            from cryptography.hazmat.primitives import serialization
            e_pub_bytes = e_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            
            sig_b = self.crypto.sign(e_pub_bytes)
            conn.sendall(encode_tlv(TYPE_HANDSHAKE_REPLY, {"e_pub": e_pub_bytes.hex(), "sig": sig_b.hex()}))
            
            shared = compute_shared_secret(e_priv, e_a_pub_bytes)
            session = CryptoSession(shared)
            
            # 3. Attendre AUTH
            m_type, req = decode_tlv(conn)
            if m_type != TYPE_HANDSHAKE_AUTH: 
                print(f"[-] Handshake : Attendu AUTH, reçu type {m_type}")
                return None, None
            
            if 'nonce' not in req or 'auth' not in req:
                print(f"[-] Handshake : Payload AUTH invalide (version incompatible ?)")
                return None, None

            nonce = bytes.fromhex(req['nonce'])
            encrypted_auth = bytes.fromhex(req['auth'])
            auth_json_data = session.decrypt(nonce, encrypted_auth)
            if auth_json_data is None: 
                print(f"[-] Handshake : Échec déchiffrement AUTH")
                return None, None
            
            try:
                auth_info = json.loads(auth_json_data.decode('utf-8'))
                a_node_id = auth_info['node_id']
                a_sig = bytes.fromhex(auth_info['sig'])
            except (json.JSONDecodeError, KeyError) as e:
                print(f"[-] Handshake : Erreur structure AUTH : {e}")
                return None, None
            
            # 4. Vérifier signature de Alice (TOFU)
            import hashlib
            shared_hash = hashlib.sha256(shared).digest()
            if not self.crypto.verify(shared_hash, a_sig, a_node_id):
                print(f"[!] Échec Handshake : Signature de Alice invalide !")
                return None, None
            
            conn.sendall(encode_tlv(TYPE_HANDSHAKE_OK, {}))
            return session, a_node_id
        except Exception as e:
            print(f"[-] Erreur Handshake Bob : {e}")
            return None, None

    def _decode_tlv_from_bytes(self, data):
        """Version statique de decode_tlv pour les données en mémoire."""
        if len(data) < 5: return None, None
        msg_type, length = struct.unpack('!BI', data[:5])
        payload_data = data[5:5+length]
        try:
            return msg_type, json.loads(payload_data.decode('utf-8'))
        except:
            return None, None

    def _process_message(self, peer_id, msg_type, payload):
        """Traite un message reçu et déchiffré."""
        if msg_type == TYPE_PEER_LIST:
            new_peers = payload.get('peers', {})
            added = 0
            for pid, info in new_peers.items():
                if pid != NODE_ID:
                    if self.peer_table.add_or_update_peer(pid, info["ip"], info["port"]):
                        added += 1
            if added > 0:
                print(f"[*] Reçu PEER_LIST chiffrée : {added} nouveaux pairs.")

        elif msg_type == TYPE_CHAT_MSG:
            sender_id = payload.get('sender_id', 'Inconnu')
            msg = payload.get('text', '')
            print(f"\n[E2EE MSG] {sender_id[:8]} > {msg}\n")

        elif msg_type == TYPE_MANIFEST:
            self._handle_manifest(peer_id, payload)

        elif msg_type == TYPE_CHUNK_REQ:
            self._handle_chunk_req(peer_id, payload)

        elif msg_type == TYPE_CHUNK_DATA:
            self.transfer_mgr.handle_chunk_data(payload)

        elif msg_type == TYPE_CHUNK_ACK:
            # Gérer les erreurs NOT_FOUND si besoin
            pass
            
        elif msg_type == TYPE_PING:
            # Répondre avec un PONG sécurisé
            self._send_secure_tlv(peer_id, TYPE_PONG, {})
            
        elif msg_type == TYPE_PONG:
            pass # Keep-alive validé

    def send_chat_message(self, target_pid, text):
        """Envoie un message de chat sécurisé à un pair spécifique."""
        payload = {
            "sender_id": NODE_ID,
            "text": text,
            "timestamp": time.time()
        }
        self._send_secure_tlv(target_pid, TYPE_CHAT_MSG, payload)

    def _handle_manifest(self, peer_id, manifest):
        """Reçoit un manifest d'un pair."""
        file_id = manifest.get('file_id')
        if not file_id: return
        
        # Vérification de la signature du manifest
        manifest_copy = manifest.copy()
        sig_hex = manifest_copy.pop('signature', None)
        if not sig_hex: return
        
        manifest_content = json.dumps(manifest_copy, sort_keys=True).encode('utf-8')
        manifest_hash = hashlib.sha256(manifest_content).digest()
        
        if self.crypto.verify(manifest_hash, bytes.fromhex(sig_hex), manifest['sender_id']):
            self.network_manifests[file_id] = manifest
            print(f"[*] [SYNC] Nouveau Manifest reçu : {manifest['filename']} ({manifest['size'] // 1024} KB) de {peer_id[:8]}")
        else:
            print(f"[!] [SYNC] Manifest invalide (signature KO) reçu de {peer_id[:8]}")

    def _handle_chunk_req(self, peer_id, payload):
        """Répond à une demande de chunk."""
        file_id = payload.get('file_id')
        chunk_idx = payload.get('chunk_idx')
        
        # Chercher le chunk localement
        # On peut avoir le chunk soit via un fichier partagé, soit via le stockage
        index = self.storage_mgr._load_index()
        chunk_info = None
        
        # Optimisation : On cherche le hash du chunk dans le manifest correspondant
        manifest = None
        if file_id in index["files"]:
            manifest = index["files"][file_id]["manifest"]
        
        if not manifest: return # On ne l'a pas
        
        chunk_hash = manifest["chunks"][chunk_idx]["hash"]
        data = self.storage_mgr.get_chunk_data(chunk_hash)
        
        if data:
            reply = {
                "file_id": file_id,
                "chunk_idx": chunk_idx,
                "data": data.hex(),
                "chunk_hash": chunk_hash,
                "signature": self.crypto.sign(data).hex() # Signature du fournisseur
            }
            self._send_secure_tlv(peer_id, TYPE_CHUNK_DATA, reply)
        else:
            # Envoyer un ACK négatif
            self._send_secure_tlv(peer_id, TYPE_CHUNK_ACK, {
                "chunk_idx": chunk_idx,
                "status": 0x02 # NOT_FOUND
            })

    def share_file(self, filepath):
        """Prépare un fichier pour le partage et broadcast le manifest."""
        # Résolution intelligente du chemin
        if not os.path.exists(filepath):
            # Tenter de trouver le fichier à la racine du projet
            root_attempt = os.path.join(PROJECT_ROOT, filepath)
            if os.path.exists(root_attempt):
                filepath = root_attempt
            else:
                print(f"[-] Impossible de trouver le fichier : {filepath}")
                return

        manifest = self.file_mgr.create_manifest(filepath, self.crypto)
        if not manifest:
            print(f"[-] Erreur lors de la création du manifest pour {filepath}")
            return
        
        self.storage_mgr.register_file(manifest, local_path=filepath)
        # Ajouter à nos propres manifests connus pour pouvoir faire /download localement si on veut
        self.network_manifests[manifest['file_id']] = manifest
        
        print(f"[+] Fichier prêt pour le partage : {manifest['filename']} (ID: {manifest['file_id'][:16]})")
        
        # Broadcaster le manifest à tous les pairs connectés
        with self.connections_lock:
            targets = list(self.active_sessions.keys())
            
        for tid in targets:
            self._send_secure_tlv(tid, TYPE_MANIFEST, manifest)
        
        print(f"[*] Manifest broadcasté à {len(targets)} pairs.")

    def _sync_manifests_with_peer(self, peer_id):
        """Envoie tous les manifests locaux à un pair spécifique (lors de la connexion)."""
        index = self.storage_mgr._load_index()
        local_files = index.get("files", {})
        
        if not local_files: return
        
        print(f"[*] [SYNC] Envoi de {len(local_files)} manifests vers {peer_id[:8]}...")
        for file_id, info in local_files.items():
            manifest = info.get("manifest")
            if manifest:
                self._send_secure_tlv(peer_id, TYPE_MANIFEST, manifest)

    def keep_alive_connections(self):
        """Envoie un PING toutes les 15s sur chaque connexion active"""
        while True:
            time.sleep(15) # Keep-alive spec S1
            with self.connections_lock:
                conns = list(self.active_connections.items())
            
            for pid, conn in conns:
                try:
                    self._send_secure_tlv(pid, TYPE_PING, {})
                except Exception:
                    # En cas d'erreur (socket fermé), on nettoie
                    with self.connections_lock:
                        if pid in self.active_connections:
                            del self.active_connections[pid]
                        if pid in self.active_sessions:
                            del self.active_sessions[pid]

    def clean_peers(self):
        """Supprime les pairs qui n'ont pas donné de signe de vie depuis 90s"""
        while True:
            deleted = self.peer_table.cleanup_inactive(timeout=90)
            for pid in deleted:
                print(f"[-] Pair déconnecté (timeout) : {pid}")
            
            # Affichage de l'état de la table (très pratique pour S1)
            print(f"\r--- Peer Table ({len(self.peer_table.get_all())} nœuds découverts) ---")
            time.sleep(10)

    def start_cli(self):
        """Interface de chat interactive en ligne de commande"""
        def run():
            time.sleep(2) # Attendre que le serveur démarre
            print("\n" + "="*50)
            print("🚀 TERMINAL CHAT ARCHIPEL (Sprint 3 - P2P Transfer)")
            print("Commandes :")
            print("  /list     - Liste les pairs sécurisés connectés")
            print("  /msg <txt> - Envoie un message à TOUS les pairs")
            print("  /ls       - Liste les fichiers locaux (utile pour /share)")
            print("  /share <path> - Partage un fichier local")
            print("  /files    - Liste les fichiers disponibles sur le réseau")
            print("  /status   - Affiche l'état des téléchargements")
            print("  /quit     - Quitte le nœud")
            print("="*50 + "\n")
            
            while True:
                try:
                    cmd = input("Archipel> ").strip()
                    if not cmd: continue
                    
                    if cmd == "/list":
                        with self.connections_lock:
                            count = len(self.active_sessions)
                            print(f"[*] {count} pairs sécurisés connectés :")
                            for pid in self.active_sessions:
                                print(f"  - {pid[:16]}...")
                    
                    elif cmd == "/debug":
                        with self.connections_lock:
                            print(f"[DEBUG] active_sessions: {list(self.active_sessions.keys())}")
                            print(f"[DEBUG] active_connections: {list(self.active_connections.keys())}")
                            print(f"[DEBUG] peer_table: {len(self.peer_table.get_all())} nodes")

                    elif cmd.startswith("/msg "):
                        text = cmd[5:]
                        with self.connections_lock:
                            targets = list(self.active_sessions.keys())
                        
                        if not targets:
                            print("[!] Aucun pair connecté pour envoyer le message.")
                        else:
                            for tid in targets:
                                self.send_chat_message(tid, text)
                            print(f"[OK] Message envoyé à {len(targets)} pairs.")
                    
                    elif cmd.startswith("/share "):
                        path = cmd[7:].strip().replace("<", "").replace(">", "")
                        self.share_file(path)

                    elif cmd == "/ls":
                        print(f"\n--- Répertoire actuel : {os.getcwd()} ---")
                        files = [f for f in os.listdir('.') if os.path.isfile(f)]
                        for f in sorted(files):
                            size = os.path.getsize(f) // 1024
                            print(f"  {f} ({size} KB)")
                        
                        # Afficher aussi ce qu'il y a à la racine si on y est pas
                        if os.getcwd() != PROJECT_ROOT:
                            print(f"\n--- Racine du projet : {PROJECT_ROOT} ---")
                            root_files = [f for f in os.listdir(PROJECT_ROOT) if os.path.isfile(f)]
                            for f in sorted(root_files):
                                size = os.path.getsize(os.path.join(PROJECT_ROOT, f)) // 1024
                                print(f"  {f} ({size} KB)")

                    elif cmd == "/files":
                        print("\n--- Fichiers disponibles sur le réseau ---")
                        if not self.network_manifests:
                            print("Aucun fichier détecté pour le moment.")
                        else:
                            for fid, m in self.network_manifests.items():
                                print(f"  [{fid[:16]}] {m['filename']} ({m['size'] // 1024} KB) - {m['nb_chunks']} chunks")
                        
                        print("\n--- Vos fichiers partagés ---")
                        local_files = self.storage_mgr.get_available_files()
                        for fid, info in local_files.items():
                            print(f"  [{fid[:16]}] {info['manifest']['filename']} (Local)")
                            
                    elif cmd == "/status":
                        print("\n--- État des téléchargements ---")
                        with self.transfer_mgr.download_lock:
                            if not self.transfer_mgr.active_downloads:
                                print("Aucun téléchargement en cours.")
                            for fid, info in self.transfer_mgr.active_downloads.items():
                                status = info["status"]
                                prog = (info["received_count"] / info["total_chunks"]) * 100
                                print(f"  [{fid[:16]}] {info['manifest']['filename']} : {prog:.1f}% ({status})")

                    elif cmd.startswith("/download "):
                        # Nettoyer l'id (enlever les espaces et les éventuels < > tapés par erreur)
                        file_id_prefix = cmd[10:].strip().replace("<", "").replace(">", "")
                        # Trouver le file_id complet à partir du préfixe
                        target_fid = None
                        for fid in self.network_manifests:
                            if fid.startswith(file_id_prefix):
                                target_fid = fid
                                break
                        
                        if target_fid:
                            self.transfer_mgr.start_download(target_fid)
                        else:
                            print(f"[-] Aucun fichier trouvé commençant par {file_id_prefix}")

                    elif cmd == "/quit":
                        print("[!] Arrêt demandé...")
                        os._exit(0)
                    else:
                        print("[?] Commande inconnue. Utilisez /msg message_ici")
                except EOFError:
                    break
                except Exception as e:
                    print(f"[-] Erreur CLI : {e}")

        threading.Thread(target=run, daemon=True).start()

if __name__ == "__main__":
    if NODE_ID == "UNKNOWN_NODE":
        print("Erreur critique: Node ID introuvable. Arrêt.")
        exit(1)
        
    node = DiscoveryNode()
    
    print(f"[*] Démarrage du nœud : {NODE_ID}")
    
    # Lancement des threads
    node.start_beacon()
    node.start_listener()
    node.start_tcp_server()
    
    threading.Thread(target=node.clean_peers, daemon=True).start()
    threading.Thread(target=node.keep_alive_connections, daemon=True).start()
    
    # Nouveau : Démarrer l'interface interactive
    node.start_cli()
    
    try:
        # On garde le thread principal en vie
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Arrêt du nœud...")