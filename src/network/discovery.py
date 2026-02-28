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
                    is_new = pkt['node_id'] not in self.peer_table
                    self.peer_table[pkt['node_id']] = {
                        "ip": addr[0],
                        "port": int(pkt['tcp_port']),
                        "last_seen": time.time()
                    }
                    if is_new:
                        print(f"[!] Nouveau pair détecté par HELLO : {pkt['node_id']} à {addr[0]}")
                    
                    # Répondre avec PEER_LIST via TCP en Unicast
                    self.reply_with_peer_list(addr[0], int(pkt['tcp_port']))
        
        threading.Thread(target=run, daemon=True).start()

    def reply_with_peer_list(self, target_ip, target_port):
        """Envoi en unicast TCP de la liste des nœuds connus"""
        def run():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2.0)
                    s.connect((target_ip, target_port))
                    
                    # Préparer la liste (sans les objets non-sérialisables)
                    peers_to_send = {}
                    for pid, info in self.peer_table.items():
                        peers_to_send[pid] = {"ip": info["ip"], "port": info["port"]}
                        
                    reply = {
                        "type": "PEER_LIST",
                        "sender_id": NODE_ID,
                        "peers": peers_to_send
                    }
                    
                    s.sendall(json.dumps(reply).encode('utf-8'))
            except Exception as e:
                pass # Échec de connexion TCP (nœud potentiellement hors-ligne ou port fermé)
                
        threading.Thread(target=run, daemon=True).start()
        
    def start_tcp_server(self):
        """Serveur TCP pour recevoir les PEER_LIST en unicast"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', TCP_PORT))
        sock.listen(5)
        
        def run():
            print(f"[+] Serveur TCP (Unicast) démarré sur le port {TCP_PORT}...")
            while True:
                conn, addr = sock.accept()
                with conn:
                    try:
                        data = conn.recv(4096)
                        if data:
                            pkt = json.loads(data.decode('utf-8'))
                            if pkt.get('type') == 'PEER_LIST':
                                new_peers = pkt.get('peers', {})
                                added = 0
                                for pid, info in new_peers.items():
                                    if pid != NODE_ID and pid not in self.peer_table:
                                        self.peer_table[pid] = {
                                            "ip": info["ip"],
                                            "port": info["port"],
                                            "last_seen": time.time()
                                        }
                                        added += 1
                                if added > 0:
                                    print(f"[*] Reçu PEER_LIST de {pkt['sender_id']} : {added} nouveaux pairs ajoutés.")
                    except Exception:
                        pass
                        
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
    node.start_tcp_server()
    
    # Thread de nettoyage (non-daemon si on veut l'utiliser comme boucle principale, 
    # ou on peut le mettre en thread séparé et garder la boucle ici)
    threading.Thread(target=node.clean_peers, daemon=True).start()
    
    try:
        # On garde le thread principal en vie pour que les daemons tournent
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Arrêt du nœud...")