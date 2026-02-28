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
from protocol import ArchipelPacket, json_to_payload, payload_to_json
from crypto_manager import CryptoManager, CryptoSession, generate_ephemeral_keypair, compute_shared_secret
from file_manager import FileManager
from storage_manager import StorageManager
from transfer_manager import TransferManager

# HMAC Key for packet integrity (In a real scenario, this would be derived or shared)
# For the hackathon, we can use a fixed key or derive it from the node's identity.
HMAC_KEY = b'archipel-v1-integrity-key-2026'

# ===== Configuration du nœud =====
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TCP_PORT = int(os.environ.get("TCP_PORT", 7777))

MCAST_GRP = '239.255.0.1'
MCAST_PORT = 5007

# Chargement de l'identité depuis le fichier de clé
KEY_FILE = os.environ.get("NODE_KEY", "node.key")
KEY_PATH = os.path.join(PROJECT_ROOT, KEY_FILE)

import hashlib as _hashlib

def _load_identity():
    """Charge ou génère l'identité du nœud depuis le fichier de clé."""
    try:
        if os.path.exists(KEY_PATH):
            with open(KEY_PATH, 'rb') as f:
                raw = f.read()
            if len(raw) == 64:
                # Format: 32 bytes private seed + 32 bytes public key
                priv_seed = raw[:32]
                signing_key = nacl.signing.SigningKey(priv_seed)
                pub_key = signing_key.verify_key
                node_id = pub_key.encode(nacl.encoding.HexEncoder).decode()
                node_priv_hex = priv_seed.hex()
                return node_id, node_priv_hex
            elif len(raw) == 32:
                priv_seed = raw
                signing_key = nacl.signing.SigningKey(priv_seed)
                pub_key = signing_key.verify_key
                node_id = pub_key.encode(nacl.encoding.HexEncoder).decode()
                node_priv_hex = priv_seed.hex()
                return node_id, node_priv_hex
        return "UNKNOWN_NODE", ""
    except Exception as e:
        print(f"[!] Erreur chargement identité : {e}")
        return "UNKNOWN_NODE", ""

NODE_ID, NODE_PRIVATE_HEX = _load_identity()

# ===== Couleurs CLI =====
CLR_RESET  = "\033[0m"
CLR_BOLD   = "\033[1m"
CLR_RED    = "\033[91m"
CLR_GREEN  = "\033[92m"
CLR_YELLOW = "\033[93m"
CLR_BLUE   = "\033[94m"
CLR_CYAN   = "\033[96m"

class DiscoveryNode:
    def __init__(self):
        self.node_id = NODE_ID
        self.peer_table = PeerTable()
        self.crypto = CryptoManager(NODE_PRIVATE_HEX)
        self.active_sessions = {}
        self.active_connections = {}
        self.connections_lock = threading.Lock()
        
        self.file_mgr = FileManager()
        storage_root = os.path.join(PROJECT_ROOT, f".archipel_{TCP_PORT}")
        self.storage_mgr = StorageManager(root_dir=storage_root)
        self.transfer_mgr = TransferManager(self)
        
        self.network_manifests = {}
        self.message_history = {}
        self.history_lock = threading.Lock()

    def start_beacon(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        def run():
            while True:
                hello_data = {
                    "tcp_port": TCP_PORT,
                    "timestamp": time.time()
                }
                # Wrap in ArchipelPacket v1
                packet_obj = ArchipelPacket(
                    msg_type=ArchipelPacket.TYPE_HELLO,
                    node_id=bytes.fromhex(NODE_ID),
                    payload=json_to_payload(hello_data)
                )
                packet_bin = packet_obj.serialize(HMAC_KEY)
                
                try:
                    host_name = socket.gethostname()
                    local_ips = socket.gethostbyname_ex(host_name)[2]
                except Exception:
                    local_ips = []
                local_ips.append("0.0.0.0")
                
                for ip in set(local_ips):
                    try:
                        if ip != "0.0.0.0":
                            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))
                        sock.sendto(packet_bin, (MCAST_GRP, MCAST_PORT))
                    except Exception:
                        pass

                # Fallback: Broadcast
                for addr in ['<broadcast>', '255.255.255.255']:
                    try:
                        sock.sendto(packet_bin, (addr, MCAST_PORT))
                    except Exception:
                        pass

                print(f"[*] HELLO (Packet v1) envoyé")
                time.sleep(30)
        
        threading.Thread(target=run, daemon=True).start()

    def start_listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        try:
            sock.bind(('', MCAST_PORT))
        except OSError:
            pass
        
        group = socket.inet_aton(MCAST_GRP)
        try:
            local_ips = socket.gethostbyname_ex(socket.gethostname())[2]
        except:
            local_ips = []
        local_ips.append("0.0.0.0")
        
        for ip in set(local_ips):
            try:
                if ip == "0.0.0.0":
                    mreq = struct.pack('4sL', group, socket.INADDR_ANY)
                else:
                    mreq = struct.pack('4s4s', group, socket.inet_aton(ip))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except:
                pass

        def run():
            print(f"[+] Écoute Multicast (Packet v1) sur {MCAST_GRP}:{MCAST_PORT}...")
            while True:
                data, addr = sock.recvfrom(2048)
                packet_obj, err = ArchipelPacket.deserialize(data, HMAC_KEY)
                
                if packet_obj and packet_obj.msg_type == ArchipelPacket.TYPE_HELLO:
                    node_id_hex = packet_obj.node_id.hex()
                    if node_id_hex != NODE_ID:
                        pkt_payload = payload_to_json(packet_obj.payload)
                        is_new = self.peer_table.add_or_update_peer(
                            node_id_hex, addr[0], int(pkt_payload['tcp_port'])
                        )
                        
                        if is_new:
                            print(f"[!] Nouveau pair détecté par HELLO v1 : {node_id_hex[:16]} à {addr[0]}")
                            self.connect_to_peer(node_id_hex, addr[0], int(pkt_payload['tcp_port']))
                elif err:
                    # On ignore silencieusement les paquets invalides ou anciens JSON
                    pass
        
        threading.Thread(target=run, daemon=True).start()

    def connect_to_peer(self, peer_id, target_ip, target_port):
        with self.connections_lock:
            if peer_id in self.active_connections:
                return 
        
        if NODE_ID > peer_id:
            return 
                
        def run():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5.0)
                s.connect((target_ip, target_port))
                s.settimeout(None)
                
                session = self._perform_handshake_alice(s, peer_id)
                if session:
                    with self.connections_lock:
                        self.active_connections[peer_id] = s
                        self.active_sessions[peer_id] = session
                    
                    print(f"[+] Tunnel E2EE établi avec {peer_id[:8]} (X25519 + AES-GCM + Packet v1)")
                    self._send_secure_v1(peer_id, ArchipelPacket.TYPE_PEER_LIST, self._build_peer_list_payload())
                    self._sync_manifests_with_peer(peer_id)
                    threading.Thread(target=self._handle_client, args=(s, peer_id, session), daemon=True).start()
                else:
                    s.close()
            except Exception:
                pass 
                
        threading.Thread(target=run, daemon=True).start()

    def _perform_handshake_alice(self, sock, peer_id):
        try:
            # 1. HELLO (e_A_pub)
            e_priv, e_pub = generate_ephemeral_keypair()
            from cryptography.hazmat.primitives import serialization
            e_pub_bytes = e_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            
            hello_pkt = ArchipelPacket(ArchipelPacket.TYPE_HELLO, bytes.fromhex(NODE_ID), 
                                     json_to_payload({"e_pub": e_pub_bytes.hex(), "timestamp": time.time()}))
            sock.sendall(hello_pkt.serialize(HMAC_KEY))
            
            # 2. Recevoir HELLO_REPLY (via Type-Length-Value ?) non, on utilise ArchipelPacket
            data = self._recv_packet(sock)
            if not data: return None
            resp_pkt, err = ArchipelPacket.deserialize(data, HMAC_KEY)
            
            if not resp_pkt or resp_pkt.msg_type != ArchipelPacket.TYPE_HELLO: return None
            
            resp = payload_to_json(resp_pkt.payload)
            e_b_pub_hex = resp['e_pub']
            sig_b_hex = resp['sig']
            e_b_pub_bytes = bytes.fromhex(e_b_pub_hex)
            sig_b_bytes = bytes.fromhex(sig_b_hex)
            
            if not self.crypto.verify(e_b_pub_bytes, sig_b_bytes, peer_id):
                print(f"[!] Échec Handshake : Signature de Bob invalide !")
                return None
            
            # 3. Calculer secret et envoyer AUTH
            shared = compute_shared_secret(e_priv, e_b_pub_bytes)
            import hashlib
            shared_hash = hashlib.sha256(shared).digest()
            sig_a = self.crypto.sign(shared_hash)
            
            session = CryptoSession(shared)
            auth_data = json.dumps({"node_id": NODE_ID, "sig": sig_a.hex()}).encode('utf-8')
            nonce, encrypted_auth = session.encrypt(auth_data)
            
            auth_pkt = ArchipelPacket(ArchipelPacket.TYPE_HANDSHAKE_AUTH if hasattr(ArchipelPacket, 'TYPE_HANDSHAKE_AUTH') else 0x08, # Placeholder
                                    bytes.fromhex(NODE_ID),
                                    json_to_payload({"nonce": nonce.hex(), "auth": encrypted_auth.hex()}))
            # Correcting type for Handshake Auth (Not in spec 0x01-0x07, using TYPE_MSG for now or extending)
            # Actually spec says 0x03 MSG - let's use a private range or just MSG for handshake auth if needed
            # But let's stick to the spec types if possible. MSG 0x03 is flexible.
            auth_pkt.msg_type = 0x03 # MSG used for handshake auth
            sock.sendall(auth_pkt.serialize(HMAC_KEY))
            
            # 4. Recevoir ACK (0x07)
            data = self._recv_packet(sock)
            if not data: return None
            ack_pkt, _ = ArchipelPacket.deserialize(data, HMAC_KEY)
            if ack_pkt and ack_pkt.msg_type == ArchipelPacket.TYPE_ACK:
                return session
        except Exception as e:
            print(f"[-] Erreur Handshake Alice : {e}")
        return None

    def _recv_packet(self, sock):
        """Helper to read a full ArchipelPacket from a stream."""
        header = self._recv_exact(sock, ArchipelPacket.HEADER_SIZE)
        if not header: return None
        
        payload_len = struct.unpack('!I', header[37:41])[0]
        full_data = header + self._recv_exact(sock, payload_len + ArchipelPacket.FOOTER_SIZE)
        return full_data

    def _recv_exact(self, sock, n):
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet: return None
            data.extend(packet)
        return bytes(data)

    def _send_secure_v1(self, peer_id, inner_type, payload):
        """Encapsule un message chiffré dans un ArchipelPacket v1 MSG."""
        with self.connections_lock:
            sock = self.active_connections.get(peer_id)
            session = self.active_sessions.get(peer_id)
            
        if not sock or not session: return
        
        try:
            # Sous-payload chiffré
            inner_json = json.dumps({"type": inner_type, "payload": payload}).encode('utf-8')
            nonce, ciphertext = session.encrypt(inner_json)
            
            # Paquet ArchipelPacket Type 0x03 (MSG)
            pkt = ArchipelPacket(
                msg_type=ArchipelPacket.TYPE_MSG,
                node_id=bytes.fromhex(NODE_ID),
                payload=json_to_payload({"nonce": nonce.hex(), "data": ciphertext.hex()})
            )
            sock.sendall(pkt.serialize(HMAC_KEY))
        except Exception as e:
            print(f"[-] Erreur envoi sécurisé v1 : {e}")

    def start_tcp_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', TCP_PORT))
        sock.listen(20)
        
        def run():
            print(f"[+] Serveur TCP (Packet v1) démarré sur le port {TCP_PORT}...")
            while True:
                conn, addr = sock.accept()
                threading.Thread(target=self._handle_client, args=(conn, None, None), daemon=True).start()
                        
        threading.Thread(target=run, daemon=True).start()

    def _handle_client(self, conn, initial_peer_id=None, initial_session=None):
        peer_id = initial_peer_id
        session = initial_session
        
        try:
            if session is None:
                session, peer_id = self._perform_handshake_bob(conn)
                if not session:
                    conn.close()
                    return
                with self.connections_lock:
                    if peer_id in self.active_connections:
                        conn.close()
                        return
                    self.active_sessions[peer_id] = session
                    self.active_connections[peer_id] = conn
                print(f"[+] Tunnel E2EE établi avec {peer_id[:8]} (X25519 + AES-GCM + Packet v1)")
                self._sync_manifests_with_peer(peer_id)

            while True:
                data = self._recv_packet(conn)
                if not data: break
                
                pkt_obj, err = ArchipelPacket.deserialize(data, HMAC_KEY)
                if not pkt_obj: continue
                
                if pkt_obj.msg_type == ArchipelPacket.TYPE_MSG:
                    pkt_payload = payload_to_json(pkt_obj.payload)
                    nonce = bytes.fromhex(pkt_payload['nonce'])
                    ciphertext = bytes.fromhex(pkt_payload['data'])
                    plaintext = session.decrypt(nonce, ciphertext)
                    
                    if plaintext:
                        inner = json.loads(plaintext.decode('utf-8'))
                        self._process_message(peer_id, inner['type'], inner['payload'])
                
                elif pkt_obj.msg_type == 0x08: # Custom Ping for internal use
                     ping_ack = ArchipelPacket(0x09, bytes.fromhex(NODE_ID), b'')
                     conn.sendall(ping_ack.serialize(HMAC_KEY))
                    
        except Exception:
            pass
        finally:
            conn.close()
            with self.connections_lock:
                if peer_id and peer_id in self.active_connections:
                    del self.active_connections[peer_id]
                if peer_id and peer_id in self.active_sessions:
                    del self.active_sessions[peer_id]

    def _perform_handshake_bob(self, conn):
        try:
            # 1. Recevoir HELLO
            data = self._recv_packet(conn)
            if not data: return None, None
            hello_pkt, _ = ArchipelPacket.deserialize(data, HMAC_KEY)
            if not hello_pkt or hello_pkt.msg_type != ArchipelPacket.TYPE_HELLO: return None, None
            
            req = payload_to_json(hello_pkt.payload)
            e_a_pub_hex = req['e_pub']
            e_a_pub_bytes = bytes.fromhex(e_a_pub_hex)
            
            # 2. Générer e_B, calculer secret et envoyer REPLY (HELLO type 0x01)
            e_priv, e_pub = generate_ephemeral_keypair()
            from cryptography.hazmat.primitives import serialization
            e_pub_bytes = e_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            
            sig_b = self.crypto.sign(e_pub_bytes)
            reply_pkt = ArchipelPacket(ArchipelPacket.TYPE_HELLO, bytes.fromhex(NODE_ID),
                                     json_to_payload({"e_pub": e_pub_bytes.hex(), "sig": sig_b.hex()}))
            conn.sendall(reply_pkt.serialize(HMAC_KEY))
            
            shared = compute_shared_secret(e_priv, e_a_pub_bytes)
            session = CryptoSession(shared)
            
            # 3. Attendre AUTH (via MSG type 0x03)
            data = self._recv_packet(conn)
            if not data: return None, None
            auth_pkt, _ = ArchipelPacket.deserialize(data, HMAC_KEY)
            
            if not auth_pkt or auth_pkt.msg_type != 0x03: return None, None
            
            req = payload_to_json(auth_pkt.payload)
            nonce = bytes.fromhex(req['nonce'])
            encrypted_auth = bytes.fromhex(req['auth'])
            auth_json_data = session.decrypt(nonce, encrypted_auth)
            
            if auth_json_data:
                auth_info = json.loads(auth_json_data.decode('utf-8'))
                a_node_id = auth_info['node_id']
                a_sig = bytes.fromhex(auth_info['sig'])
                
                import hashlib
                shared_hash = hashlib.sha256(shared).digest()
                if self.crypto.verify(shared_hash, a_sig, a_node_id):
                    ack_pkt = ArchipelPacket(ArchipelPacket.TYPE_ACK, bytes.fromhex(NODE_ID), b'')
                    conn.sendall(ack_pkt.serialize(HMAC_KEY))
                    return session, a_node_id
            
        except Exception:
            pass
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
                        if self.peer_table.add_or_update_peer(pid, info["ip"], info["port"]):
                            added += 1
                if added > 0:
                    print(f"[*] Reçu PEER_LIST v1 : {added} nouveaux pairs.")

            elif msg_type == TYPE_CHAT_MSG:
                sender_id = payload.get('sender_id', 'Inconnu')
                msg = payload.get('text', '')
                print(f"\n[E2EE v1 MSG] {sender_id[:8]} > {msg}\n")
                
                with self.history_lock:
                    if peer_id not in self.message_history:
                        self.message_history[peer_id] = []
                    self.message_history[peer_id].append({
                        "sender": sender_id,
                        "text": msg,
                        "timestamp": payload.get('timestamp', time.time()),
                        "type": "in"
                    })
                    
                # Déclencheur IA automatique (Sprint 4.2)
                if getattr(self, "ai_enabled", False) and getattr(self, "ai_key", None):
                    if "@archipel-ai" in msg.lower() or msg.lower().startswith("/ask"):
                        print(f"[*] [AI] Requête détectée de {sender_id[:8]}...")
                        threading.Thread(target=self._process_ai_request, args=(peer_id, msg), daemon=True).start()


            elif msg_type == TYPE_MANIFEST:
                self._handle_manifest(peer_id, payload)

            elif msg_type == TYPE_CHUNK_REQ:
                self._handle_chunk_req(peer_id, payload)

            elif msg_type == TYPE_CHUNK_DATA:
                self.transfer_mgr.handle_chunk_data(payload)

            elif msg_type == TYPE_CHUNK_ACK:
                pass
                
            elif msg_type == TYPE_PING:
                self._send_secure_v1(peer_id, TYPE_PONG, {})
            
        except Exception as e:
            print(f"[-] Erreur traitement message v1 ({msg_type}) : {e}")

    def send_chat_message(self, target_pid, text):
        """Envoie un message de chat sécurisé à un pair spécifique."""
        ts = time.time()
        payload = {"sender_id": NODE_ID, "text": text, "timestamp": ts}
        
        with self.history_lock:
            if target_pid not in self.message_history:
                self.message_history[target_pid] = []
            self.message_history[target_pid].append({
                "sender": NODE_ID, "text": text, "timestamp": ts, "type": "out"
            })
            
        self._send_secure_v1(target_pid, TYPE_CHAT_MSG, payload)
        
        # Auto-déclencheur pour nous-mêmes (si on tape @archipel-ai)
        if getattr(self, "ai_enabled", False) and getattr(self, "ai_key", None):
            if "@archipel-ai" in text.lower() or text.lower().startswith("/ask"):
                print(f"[*] [AI] Traitement de notre propre requête...")
                threading.Thread(target=self._process_ai_request, args=(target_pid, text), daemon=True).start()

    def _process_ai_request(self, peer_id, query):
        """Traite une question envoyée à l'IA en local et diffuse la réponse au pair."""
        try:
            from ai.gemini_service import GeminiService
            gemini = GeminiService(api_key=self.ai_key, enabled=True)
            
            with self.history_lock:
                history = self.message_history.get(peer_id, [])[-10:]
                
            # Extraire les fichiers RAG (accès direct au storage local)
            files_context = {}
            local_files = self.storage_mgr.get_available_files()
            for fid, info in local_files.items():
                if info.get("local_path") and os.path.exists(info["local_path"]):
                    try:
                        # Limite à 50KB par fichier pour le contexte prompt
                        with open(info["local_path"], 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(50_000)
                            if content.strip():
                                files_context[info["manifest"]["filename"]] = content
                    except:
                        pass
            
            # Formater la requête pour Gemini (retirer le trigger si besoin)
            clean_query = query.replace("@archipel-ai", "").replace("/ask", "").strip()
            if not clean_query: clean_query = "Que puis-je faire pour toi ?"
            
            result = gemini.query(history, clean_query, files_context)
            
            if "text" in result:
                response_text = f"🤖 [Archipel-AI] : {result['text']}"
                # Envoyer la réponse au pair
                self.send_chat_message(peer_id, response_text)
                print(f"[+] [AI] Réponse envoyée à {peer_id[:8]}")
            else:
                print(f"[-] [AI] Erreur: {result.get('error', 'Inconnue')}")
        except Exception as e:
            print(f"[-] [AI] Erreur fatale processing : {e}")

    def _handle_manifest(self, peer_id, manifest):
        """Reçoit un manifest d'un pair."""
        file_id = manifest.get('file_id')
        if not file_id: return
        
        manifest_copy = manifest.copy()
        sig_hex = manifest_copy.pop('signature', None)
        if not sig_hex: return
        
        manifest_content = json.dumps(manifest_copy, sort_keys=True, separators=(',', ':')).encode('utf-8')
        manifest_hash = hashlib.sha256(manifest_content).digest()
        sender_id = manifest.get('sender_id')
        
        if self.crypto.verify(manifest_hash, bytes.fromhex(sig_hex), sender_id):
            self.network_manifests[file_id] = manifest
            print(f"[*] [SYNC] Manifest reçu : {manifest['filename']} de {peer_id[:8]}")
        else:
            print(f"[!] Manifest invalide de {peer_id[:8]}")


    def _handle_chunk_req(self, peer_id, payload):
        """Répond à une demande de chunk."""
        file_id = payload.get('file_id')
        chunk_idx = payload.get('chunk_idx')
        index = self.storage_mgr._load_index()
        
        manifest = index["files"].get(file_id, {}).get("manifest")
        if not manifest: return
        
        chunk_hash = manifest["chunks"][chunk_idx]["hash"]
        data = self.storage_mgr.get_chunk_data(chunk_hash)
        
        if data:
            reply = {
                "file_id": file_id,
                "chunk_idx": chunk_idx,
                "data": data.hex(),
                "chunk_hash": chunk_hash,
                "signature": self.crypto.sign(data).hex()
            }
            self._send_secure_v1(peer_id, TYPE_CHUNK_DATA, reply)
        else:
            self._send_secure_v1(peer_id, TYPE_CHUNK_ACK, {"chunk_idx": chunk_idx, "status": 0x02})

    def share_file(self, filepath):
        """Prépare un fichier pour le partage et broadcast le manifest."""
        if not os.path.exists(filepath):
            root_attempt = os.path.join(PROJECT_ROOT, filepath)
            if os.path.exists(root_attempt): filepath = root_attempt
            else: return

        manifest = self.file_mgr.create_manifest(filepath, self.crypto)
        if not manifest: return
        
        self.storage_mgr.register_file(manifest, local_path=filepath)
        self.network_manifests[manifest['file_id']] = manifest
        
        with self.connections_lock:
            targets = list(self.active_sessions.keys())
            
        for tid in targets:
            self._send_secure_v1(tid, TYPE_MANIFEST, manifest)

    def _sync_manifests_with_peer(self, peer_id):
        """Envoie tous les manifests locaux à un pair spécifique."""
        index = self.storage_mgr._load_index()
        local_files = index.get("files", {})
        for file_id, info in local_files.items():
            manifest = info.get("manifest")
            if manifest:
                self._send_secure_v1(peer_id, TYPE_MANIFEST, manifest)

    def keep_alive_connections(self):
        """Envoie un PING toutes les 15s sur chaque connexion active"""
        while True:
            time.sleep(15)
            with self.connections_lock:
                conns = list(self.active_connections.keys())
            for pid in conns:
                try:
                    self._send_secure_v1(pid, TYPE_PING, {})
                except Exception:
                    with self.connections_lock:
                        if pid in self.active_connections: del self.active_connections[pid]
                        if pid in self.active_sessions: del self.active_sessions[pid]

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