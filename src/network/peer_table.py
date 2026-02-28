import json
import time
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PEERS_FILE = os.path.join(PROJECT_ROOT, "peers.json")

class PeerTable:
    def __init__(self):
        self.peers = {} # {node_id: {"ip": ip, "tcp_port": port, "last_seen": timestamp, "shared_files": [], "reputation": 1.0}}
        self.load()

    def get_peer(self, node_id):
        return self.peers.get(node_id)
        
    def get_all(self):
        return self.peers

    def add_or_update_peer(self, node_id, ip, tcp_port, shared_files=None):
        """Met à jour un pair existant ou ajoute un nouveau pair"""
        is_new = node_id not in self.peers
        
        if is_new:
            self.peers[node_id] = {
                "ip": ip,
                "tcp_port": tcp_port,
                "last_seen": time.time(),
                "shared_files": shared_files if shared_files is not None else [],
                "reputation": 1.0 # Score de fiabilité initial
            }
        else:
            self.peers[node_id]["ip"] = ip
            self.peers[node_id]["tcp_port"] = tcp_port
            self.peers[node_id]["last_seen"] = time.time()
            if shared_files is not None:
                self.peers[node_id]["shared_files"] = shared_files
                
        self.save()
        return is_new

    def update_reputation(self, node_id, success):
        """Met à jour le ratio succès/échecs des chunks"""
        if node_id in self.peers:
            if success:
                # Augmentation modérée de la réputation
                self.peers[node_id]["reputation"] = min(5.0, self.peers[node_id]["reputation"] + 0.1)
            else:
                # Baisse de la réputation en cas d'échec
                self.peers[node_id]["reputation"] = max(0.0, self.peers[node_id]["reputation"] - 0.2)
            self.save()

    def update_shared_files(self, node_id, files_list):
        if node_id in self.peers:
            self.peers[node_id]["shared_files"] = files_list
            self.save()

    def cleanup_inactive(self, timeout=90):
        """Supprime les nœuds inactifs depuis plus de `timeout` secondes"""
        now = time.time()
        to_delete = [pid for pid, info in self.peers.items() if now - info['last_seen'] > timeout]
        
        for pid in to_delete:
            del self.peers[pid]
            
        if to_delete:
            self.save()
            
        return to_delete

    def save(self):
        """Sauvegarde persistante sur le disque"""
        try:
            with open(PEERS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.peers, f, indent=4)
        except Exception as e:
            print(f"[-] Erreur de sauvegarde de la table des pairs : {e}")

    def load(self):
        """Chargement de la table depuis le disque"""
        if os.path.exists(PEERS_FILE):
            try:
                with open(PEERS_FILE, "r", encoding="utf-8") as f:
                    self.peers = json.load(f)
                print(f"[+] Table des pairs chargée depuis le disque ({len(self.peers)} pairs)")
            except Exception as e:
                print(f"[-] Erreur de lecture de la table des pairs : {e}")
                self.peers = {}
