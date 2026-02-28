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

# Couleurs ANSI pour le CLI Premium
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_GREEN = "\033[92m"
CLR_CYAN = "\033[96m"
CLR_YELLOW = "\033[93m"
CLR_RED = "\033[91m"
CLR_BLUE = "\033[94m"

# Configuration par défaut (peut être surchargée par des variables d'environnement)
MCAST_GRP = '239.255.42.99'
MCAST_PORT = 6000
TCP_PORT = int(os.environ.get("TCP_PORT", 7777))
ARG_KEY = os.environ.get("NODE_KEY", "node.key")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KEY_PATH = os.path.join(PROJECT_ROOT, ARG_KEY)

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
        
        # Historique des messages : {peer_id: [ {sender, text, timestamp, type} ]}
        self.message_history = {}
        self.history_lock = threading.Lock()

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
            
        # Tie-breaker P2P : Pour éviter que deux nœuds n'initient simultanément
        # On décide arbitrairement que seul le nœud avec l'ID le plus petit initie.
        if NODE_ID > peer_id:
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
                    
                    # Sync : Envoyer nos manifests locaux au nouveau pair (Alice side)
                    self._sync_manifests_with_peer(peer_id)
                    
                    # Listener dédié - On passe la session directement !
                    threading.Thread(target=self._handle_client, args=(s, peer_id, session), daemon=True).start()
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
            
        if not sock or not session:
            print(f"[-] [DEBUG] Echec envoi type {msg_type} : Pas de session active pour {peer_id[:8]}")
            return
        
        try:
            # On encode le sous-message TLV interne
            inner_data = encode_tlv(msg_type, payload)
            nonce, ciphertext = session.encrypt(inner_data)
            
            # On envoie le paquet TYPE_SECURE_MSG
            envelope = encode_tlv(TYPE_SECURE_MSG, {
                "nonce": nonce.hex(),
                "data": ciphertext.hex()
            })
            print(f"[*] [DEBUG] Envoi sécurisé type {msg_type} vers {peer_id[:8]}")
            sock.sendall(envelope)
        except Exception as e:
            print(f"[-] [DEBUG] Erreur critique envoi sécurisé vers {peer_id[:8]}: {e}")
        
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
                threading.Thread(target=self._handle_client, args=(conn, None, None), daemon=True).start()
                        
        threading.Thread(target=run, daemon=True).start()

    def _handle_client(self, conn, initial_peer_id=None, initial_session=None):
        """Gère une connexion TCP sécurisée (Bob ou Alice client)"""
        peer_id = initial_peer_id
        session = initial_session
        
        try:
            # 1. Si on est Bob (initial_session is None), on commence par le handshake
            if session is None:
                session, peer_id = self._perform_handshake_bob(conn)
                if not session:
                    conn.close()
                    return
                with self.connections_lock:
                    # On vérifie si on n'a pas déjà une connexion plus "légitime"
                    if peer_id in self.active_connections:
                        # On garde la connexion existante (celle initiée par le plus petit ID)
                        conn.close()
                        return
                    self.active_sessions[peer_id] = session
                    self.active_connections[peer_id] = conn
                print(f"[+] Tunnel E2EE établi avec {peer_id[:8]} (X25519 + AES-GCM)")
                
                # Sync : Envoyer nos manifests locaux au nouveau pair (Bob side)
                self._sync_manifests_with_peer(peer_id)
            # Sinon, session et peer_id sont déjà fournis pour le mode Alice client


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
            print(f"[-] Erreur critique Tunnel ({peer_id[:8] if peer_id else 'Handshake'}): {e}")
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
        except Exception as e:
            print(f"[-] [DEBUG] Erreur de décodage message interne (type {msg_type}): {e}")
            return None, None

    def _process_message(self, peer_id, msg_type, payload):
        """Traite un message reçu et déchiffré."""
        print(f"[*] [DEBUG] Réception message type {msg_type} de {peer_id[:8]}")
        
        try:
            if msg_type == TYPE_PEER_LIST:
                new_peers = payload.get('peers', {})
                added = 0
                for pid, info in new_peers.items():
                    if pid != NODE_ID:
                        # Correction : Utiliser 'port' car c'est ce qui est envoyé dans _build_peer_list_payload
                        if self.peer_table.add_or_update_peer(pid, info["ip"], info["port"]):
                            added += 1
                if added > 0:
                    print(f"[*] Reçu PEER_LIST chiffrée : {added} nouveaux pairs.")

            elif msg_type == TYPE_CHAT_MSG:
                sender_id = payload.get('sender_id', 'Inconnu')
                msg = payload.get('text', '')
                print(f"\n[E2EE MSG] {sender_id[:8]} > {msg}\n")
                
                with self.history_lock:
                    if peer_id not in self.message_history:
                        self.message_history[peer_id] = []
                    self.message_history[peer_id].append({
                        "sender": sender_id,
                        "text": msg,
                        "timestamp": payload.get('timestamp', time.time()),
                        "type": "in"
                    })

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
            
        except Exception as e:
            print(f"[-] Erreur lors du traitement d'un message ({msg_type}) de {peer_id[:8]} : {e}")

    def send_chat_message(self, target_pid, text):
        """Envoie un message de chat sécurisé à un pair spécifique."""
        ts = time.time()
        payload = {
            "sender_id": NODE_ID,
            "text": text,
            "timestamp": ts
        }
        
        # Stocker dans l'historique local
        with self.history_lock:
            if target_pid not in self.message_history:
                self.message_history[target_pid] = []
            self.message_history[target_pid].append({
                "sender": NODE_ID,
                "text": text,
                "timestamp": ts,
                "type": "out"
            })
            
        self._send_secure_tlv(target_pid, TYPE_CHAT_MSG, payload)

    def _handle_manifest(self, peer_id, manifest):
        """Reçoit un manifest d'un pair."""
        file_id = manifest.get('file_id')
        if not file_id: 
            print(f"[-] [DEBUG] Manifest reçu de {peer_id[:8]} sans file_id")
            return
        
        # Vérification de la signature du manifest
        manifest_copy = manifest.copy()
        sig_hex = manifest_copy.pop('signature', None)
        if not sig_hex: 
            print(f"[-] [DEBUG] Manifest reçu de {peer_id[:8]} sans signature")
            return
        
        manifest_content = json.dumps(manifest_copy, sort_keys=True, separators=(',', ':')).encode('utf-8')
        manifest_hash = hashlib.sha256(manifest_content).digest()
        sender_id = manifest.get('sender_id')
        
        if self.crypto.verify(manifest_hash, bytes.fromhex(sig_hex), sender_id):
            self.network_manifests[file_id] = manifest
            print(f"[*] [SYNC] Nouveau Manifest reçu : {manifest['filename']} ({manifest['size'] // 1024} KB) de {peer_id[:8]}")
        else:
            print(f"[!] [SYNC] Manifest invalide (signature KO) de {peer_id[:8]} (signé par {sender_id[:8]})")


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
            
            # Affichage de l'état de la table moins fréquent (30s au lieu de 10s)
            print(f"--- Peer Table ({len(self.peer_table.get_all())} nœuds découverts) ---")
            time.sleep(30)

    def start_cli(self):
        """Interface interactive 'Premium' pour la démo (Sprint 4)"""
        def run():
            time.sleep(1.5)
            banner = f"""
{CLR_CYAN}{CLR_BOLD}
   ┌──────────────────────────────────────────────────┐
   │  {CLR_YELLOW}⚓ ARCHIPEL - PROTOCOLE P2P SOUVERAIN (v1.0) {CLR_CYAN}    │
   │  {CLR_RESET}Sécurité: Ed25519 + X25519 + AES-256-GCM {CLR_CYAN}     │
   └──────────────────────────────────────────────────┘
{CLR_RESET}"""
            print(banner)
            print(f"{CLR_GREEN}[*] Nœud prêt. Tapez 'help' pour les commandes.{CLR_RESET}\n")
            
            while True:
                try:
                    line = input(f"{CLR_BOLD}Archipel>{CLR_RESET} ").strip()
                    if not line: continue
                    
                    parts = line.split()
                    cmd = parts[0].lower()
                    args = parts[1:]

                    if cmd == "archipel" and len(args) > 0:
                        cmd = args[0].lower()
                        args = args[1:]

                    if cmd in ["help", "?", "/help"]:
                        print(f"\n{CLR_BOLD}Commandes disponibles :{CLR_RESET}")
                        print(f"  {CLR_CYAN}peers{CLR_RESET}             - Lister les pairs sécurisés connectés")
                        print(f"  {CLR_CYAN}msg <id> <txt>{CLR_RESET}   - Envoyer un message chiffré")
                        print(f"  {CLR_CYAN}msg all <txt>{CLR_RESET}    - Diffuser un message à tous")
                        print(f"  {CLR_CYAN}send <path>{CLR_RESET}      - Partager un fichier local")
                        print(f"  {CLR_CYAN}receive{CLR_RESET}           - Voir les fichiers disponibles sur le réseau")
                        print(f"  {CLR_CYAN}download <id>{CLR_RESET}     - Télécharger un fichier")
                        print(f"  {CLR_CYAN}status{CLR_RESET}            - État du nœud + stats réseau")
                        print(f"  {CLR_CYAN}ls{CLR_RESET}                - Lister les fichiers du répertoire actuel")
                        print(f"  {CLR_CYAN}trust <id>{CLR_RESET}        - Approuver un pair (Web of Trust)")
                        print(f"  {CLR_CYAN}quit{CLR_RESET}             - Arrêter le nœud\n")

                    elif cmd == "peers":
                        with self.connections_lock:
                            count = len(self.active_sessions)
                            print(f"\n{CLR_BOLD}[*] {count} pairs connectés :{CLR_RESET}")
                            if not count:
                                print(f"  {CLR_RED}(Aucune session active){CLR_RESET}")
                            for pid in self.active_sessions:
                                peer_info = self.peer_table.get_peer(pid)
                                trust_icon = "🔰" if peer_info and peer_info.get("trusted") else "❓"
                                print(f"  {trust_icon} {CLR_CYAN}{pid[:16]}...{CLR_RESET}")
                        print("")

                    elif cmd == "msg":
                        if len(args) < 2:
                            print(f"{CLR_RED}[!] Syntaxe: msg <node_id|all> <texte>{CLR_RESET}")
                            continue
                        target = args[0]
                        text = " ".join(args[1:])
                        with self.connections_lock:
                            active_pids = list(self.active_sessions.keys())
                        if target == "all":
                            for pid in active_pids:
                                self.send_chat_message(pid, text)
                            print(f"{CLR_GREEN}[OK] Message diffusé à {len(active_pids)} pairs.{CLR_RESET}")
                        else:
                            full_target = None
                            for pid in active_pids:
                                if pid.startswith(target):
                                    full_target = pid
                                    break
                            if full_target:
                                self.send_chat_message(full_target, text)
                                print(f"{CLR_GREEN}[OK] Message envoyé à {full_target[:16]}...{CLR_RESET}")
                            else:
                                print(f"{CLR_RED}[!] Pair {target} introuvable ou non connecté.{CLR_RESET}")

                    elif cmd == "send":
                        if not args:
                            print(f"{CLR_RED}[!] Syntaxe: send <filepath>{CLR_RESET}")
                            continue
                        path = " ".join(args).replace("<", "").replace(">", "").strip()
                        self.share_file(path)

                    elif cmd in ["receive", "files"]:
                        print(f"\n{CLR_BOLD}--- Catalogue Réseau ---{CLR_RESET}")
                        if not self.network_manifests:
                            print(f"  {CLR_YELLOW}Aucun fichier détecté.{CLR_RESET}")
                        else:
                            for fid, m in self.network_manifests.items():
                                print(f"  📄 [{CLR_CYAN}{fid[:8]}{CLR_RESET}] {m['filename']} ({m['size'] // 1024} KB)")
                        print(f"\n{CLR_BOLD}--- Vos Fichiers ---{CLR_RESET}")
                        local_files = self.storage_mgr.get_available_files()
                        for fid, info in local_files.items():
                            print(f"  🏠 [{CLR_GREEN}{fid[:8]}{CLR_RESET}] {info['manifest']['filename']} (Local)")
                        print("")

                    elif cmd == "download":
                        if not args:
                            print(f"{CLR_RED}[!] Syntaxe: download <file_id_prefix>{CLR_RESET}")
                            continue
                        prefix = args[0]
                        target_fid = None
                        for fid in self.network_manifests:
                            if fid.startswith(prefix):
                                target_fid = fid
                                break
                        if target_fid:
                            print(f"{CLR_BLUE}[*] Requête de téléchargement pour {target_fid[:8]}...{CLR_RESET}")
                            self.transfer_mgr.start_download(target_fid)
                        else:
                            print(f"{CLR_RED}[!] Aucun fichier réseau trouvé pour '{prefix}'.{CLR_RESET}")

                    elif cmd == "status":
                        print(f"\n{CLR_BOLD}--- État du Nœud ---{CLR_RESET}")
                        print(f"  Identité : {CLR_CYAN}{NODE_ID}{CLR_RESET}")
                        print(f"  Port TCP : {CLR_YELLOW}{TCP_PORT}{CLR_RESET}")
                        with self.transfer_mgr.download_lock:
                            if self.transfer_mgr.active_downloads:
                                print(f"\n{CLR_BOLD}Téléchargements :{CLR_RESET}")
                                for fid, info in self.transfer_mgr.active_downloads.items():
                                    prog = (info["received_count"] / info["total_chunks"]) * 100
                                    bar_len = 20
                                    filled = int(prog / 100 * bar_len)
                                    bar = "█" * filled + "░" * (bar_len - filled)
                                    print(f"  [{fid[:8]}] {info['manifest']['filename']:<20} |{CLR_GREEN}{bar}{CLR_RESET}| {prog:5.1f}%")
                            else:
                                print("\n  (Aucun transfert actif)")
                        print("")

                    elif cmd == "trust":
                        if not args:
                            print(f"{CLR_RED}[!] Syntaxe: trust <node_id_prefix>{CLR_RESET}")
                            continue
                        prefix = args[0]
                        found = False
                        for pid in list(self.peer_table.get_all().keys()):
                            if pid.startswith(prefix):
                                if pid in self.peer_table.peers:
                                    self.peer_table.peers[pid]["trusted"] = True
                                    self.peer_table.save()
                                    print(f"{CLR_GREEN}[WOT] Pair {pid[:16]}... marqué comme de CONFIANCE.{CLR_RESET}")
                                    found = True
                                    break
                        if not found:
                            print(f"{CLR_RED}[!] Aucun pair connu avec le préfixe {prefix}.{CLR_RESET}")

                    elif cmd == "ls":
                        print(f"\n{CLR_BOLD}Recherche dans : {os.getcwd()}{CLR_RESET}")
                        if os.path.exists('.'):
                            for f in sorted(os.listdir('.')):
                                if os.path.isfile(f):
                                    print(f"  - {f}")
                        print("")

                    elif cmd == "quit":
                        print(f"{CLR_YELLOW}[!] Fermeture d'Archipel...{CLR_RESET}")
                        os._exit(0)
                    else:
                        print(f"{CLR_RED}[?] Commande inconnue. Tapez 'help'.{CLR_RESET}")
                except EOFError:
                    break
                except Exception as e:
                    print(f"{CLR_RED}[!] Erreur CLI : {e}{CLR_RESET}")


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