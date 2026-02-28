import argparse
import socket
import struct
import threading
import time
import json
import os
import nacl.signing
import nacl.encoding
from dotenv import load_dotenv
from peer_table import PeerTable
from tlv import encode_tlv, decode_tlv, TYPE_PEER_LIST, TYPE_PING, TYPE_PONG

load_dotenv()

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

def get_node_id():
    if not os.path.exists(KEY_PATH):
        print(f"[-] Fichier node.key introuvable ({KEY_PATH}). Veuillez exécuter src/crypto/generate_identity.py au préalable.")
        return "UNKNOWN_NODE"
    
    try:
        with open(KEY_PATH, "r", encoding="utf-8") as f:
            private_hex = f.read().strip()
        private_key = nacl.signing.SigningKey(private_hex, encoder=nacl.encoding.HexEncoder)
        public_key = private_key.verify_key
        return public_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
    except Exception as e:
        print(f"[-] Erreur de lecture de l'identité : {e}")
        return "UNKNOWN_NODE"

NODE_ID = get_node_id()

class DiscoveryNode:
    def __init__(self):
        self.peer_table = PeerTable()
        self.active_connections = {} # {node_id: socket}
        self.connections_lock = threading.Lock()

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
        """Tente d'établir une connexion persistante et d'envoyer la Peer List"""
        with self.connections_lock:
            if peer_id in self.active_connections:
                return # Déjà connecté
                
        def run():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5.0)
                s.connect((target_ip, target_port))
                s.settimeout(None) # Remettre en bloquant une fois connecté
                
                with self.connections_lock:
                    self.active_connections[peer_id] = s
                    
                print(f"[+] Connexion persistante établie avec {peer_id[:8]}...")
                self._send_peer_list(s)
                
                # Démarrer le listener dédié à ce socket
                threading.Thread(target=self._handle_client, args=(s, peer_id), daemon=True).start()
                
            except Exception as e:
                pass # Échec de connexion TCP
                
        threading.Thread(target=run, daemon=True).start()

    def _send_peer_list(self, sock):
        peers_to_send = {}
        for pid, info in self.peer_table.get_all().items():
            peers_to_send[pid] = {"ip": info["ip"], "port": info["tcp_port"]}
            
        reply = {
            "sender_id": NODE_ID,
            "peers": peers_to_send
        }
        try:
            sock.sendall(encode_tlv(TYPE_PEER_LIST, reply))
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
        """Gère une connexion TCP persistante avec le protocole TLV"""
        remote_peer_id = initial_peer_id
        
        try:
            while True:
                msg_type, payload = decode_tlv(conn)
                if msg_type is None:
                    break # Connexion fermée par le pair
                    
                if msg_type == TYPE_PEER_LIST:
                    sender_id = payload.get('sender_id')
                    if not remote_peer_id and sender_id:
                        remote_peer_id = sender_id
                        with self.connections_lock:
                            self.active_connections[remote_peer_id] = conn
                    
                    new_peers = payload.get('peers', {})
                    added = 0
                    for pid, info in new_peers.items():
                        if pid != NODE_ID and self.peer_table.get_peer(pid) is None:
                            self.peer_table.add_or_update_peer(pid, info["ip"], info["port"])
                            added += 1
                    if added > 0:
                        print(f"[*] Reçu PEER_LIST via TCP : {added} nouveaux pairs ajoutés.")
                        
                elif msg_type == TYPE_PING:
                    # Renvoyer PONG
                    conn.sendall(encode_tlv(TYPE_PONG, {}))
                    
                elif msg_type == TYPE_PONG:
                    # On ignore, on sait juste que la connexion est vivante
                    pass
        except Exception as e:
            pass
        finally:
            conn.close()
            with self.connections_lock:
                if remote_peer_id in self.active_connections and self.active_connections[remote_peer_id] == conn:
                    del self.active_connections[remote_peer_id]

    def keep_alive_connections(self):
        """Envoie un PING toutes les 15s sur chaque connexion active"""
        while True:
            time.sleep(15) # Keep-alive spec S1
            with self.connections_lock:
                conns = list(self.active_connections.items())
            
            for pid, conn in conns:
                try:
                    conn.sendall(encode_tlv(TYPE_PING))
                except Exception:
                    # En cas d'erreur (socket fermé), on nettoie
                    with self.connections_lock:
                        if pid in self.active_connections:
                            del self.active_connections[pid]

    def clean_peers(self):
        """Supprime les pairs qui n'ont pas donné de signe de vie depuis 90s"""
        while True:
            deleted = self.peer_table.cleanup_inactive(timeout=90)
            for pid in deleted:
                print(f"[-] Pair déconnecté (timeout) : {pid}")
            
            # Affichage de l'état de la table (très pratique pour S1)
            print(f"\r--- Peer Table ({len(self.peer_table.get_all())} nœuds découverts) ---")
            time.sleep(10)

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
    
    try:
        # On garde le thread principal en vie pour que les daemons tournent
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Arrêt du nœud...")