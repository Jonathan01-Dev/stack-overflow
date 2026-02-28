import socket
import struct
import threading
import time
import json
import os
import nacl.signing
import nacl.encoding

MCAST_GRP = '239.255.42.99'
MCAST_PORT = 6000
TCP_PORT = 7777

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KEY_PATH = os.path.join(PROJECT_ROOT, "node.key")

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
        self.peer_table = {} # {node_id: {"ip": ip, "port": port, "last_seen": timestamp}}

    def start_beacon(self):
        """Envoie un paquet HELLO toutes les 30 secondes"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        
        def run():
            while True:
                hello = {
                    "type": "HELLO",
                    "node_id": NODE_ID,
                    "tcp_port": TCP_PORT,
                    "timestamp": time.time()
                }
                packet = json.dumps(hello).encode('utf-8')
                sock.sendto(packet, (MCAST_GRP, MCAST_PORT))
                print(f"[*] HELLO envoyé sur {MCAST_GRP}")
                time.sleep(30)
        
        threading.Thread(target=run, daemon=True).start()

    def start_listener(self):
        """Écoute les paquets HELLO des autres"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Liaison au port multicast
        sock.bind(('', MCAST_PORT))
        
        # Rejoindre le groupe multicast
        group = socket.inet_aton(MCAST_GRP)
        mreq = struct.pack('4sL', group, socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        def run():
            print(f"[+] Écoute Multicast sur {MCAST_GRP}:{MCAST_PORT}...")
            while True:
                data, addr = sock.recvfrom(1024)
                pkt = json.loads(data.decode('utf-8'))
                
                if pkt['node_id'] != NODE_ID:
                    # Mise à jour ou ajout dans la Peer Table
                    self.peer_table[pkt['node_id']] = {
                        "ip": addr[0],
                        "port": pkt['tcp_port'],
                        "last_seen": time.time()
                    }
                    print(f"[!] Nouveau pair détecté : {pkt['node_id']} à {addr[0]}")
                    # Ici, tu devrais normalement répondre avec PEER_LIST via TCP
        
        threading.Thread(target=run, daemon=True).start()

    def clean_peers(self):
        """Supprime les pairs qui n'ont pas donné de signe de vie depuis 90s"""
        while True:
            now = time.time()
            to_delete = [id for id, info in self.peer_table.items() if now - info['last_seen'] > 90]
            for id in to_delete:
                print(f"[-] Pair déconnecté (timeout) : {id}")
                del self.peer_table[id]
            time.sleep(10)

if __name__ == "__main__":
    node = DiscoveryNode()
    
    print(f"[*] Démarrage du nœud : {NODE_ID}")
    
    # Lancement des threads
    node.start_beacon()
    node.start_listener()
    
    # Thread de nettoyage (non-daemon si on veut l'utiliser comme boucle principale, 
    # ou on peut le mettre en thread séparé et garder la boucle ici)
    threading.Thread(target=node.clean_peers, daemon=True).start()
    
    try:
        # On garde le thread principal en vie pour que les daemons tournent
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Arrêt du nœud...")