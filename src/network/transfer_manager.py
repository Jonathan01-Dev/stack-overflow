import threading
import time
import os
import hashlib
from tlv import TYPE_CHUNK_REQ

class TransferManager:
    def __init__(self, node):
        self.node = node # Instance de DiscoveryNode
        self.active_downloads = {} # {file_id: {status, progress, chunks_received, sources}}
        self.download_lock = threading.Lock()
        self.chunk_waiters = {} # {chunk_hash: threading.Event()}
        self.chunk_data = {} # {chunk_hash: data}

    def start_download(self, file_id):
        """Initie le téléchargement d'un fichier à partir de son manifest."""
        manifest = self.node.network_manifests.get(file_id)
        if not manifest:
            print(f"[-] Manifest inconnu pour {file_id}")
            return False
            
        with self.download_lock:
            if file_id in self.active_downloads:
                return True
            
            self.active_downloads[file_id] = {
                "manifest": manifest,
                "received_count": 0,
                "total_chunks": manifest["nb_chunks"],
                "missing_indices": list(range(manifest["nb_chunks"])),
                "status": "downloading"
            }
            
        threading.Thread(target=self._download_loop, args=(file_id,), daemon=True).start()
        return True

    def _download_loop(self, file_id):
        """Boucle de téléchargement pour un fichier."""
        with self.download_lock:
            info = self.active_downloads[file_id]
            manifest = info["manifest"]
            
        print(f"[*] Début du téléchargement : {manifest['filename']}...")
        
        while info["missing_indices"]:
            # Stratégie simplifiée : On prend les 3 premiers chunks manquants
            # Et on les demande à 3 pairs différents (si dispo)
            with self.node.connections_lock:
                peers = list(self.node.active_sessions.keys())
            
            if not peers:
                time.sleep(2)
                continue
                
            # Pipeline parallèle (limité à 3 chunks à la fois pour la démo)
            batch = info["missing_indices"][:3]
            threads = []
            
            for i, chunk_idx in enumerate(batch):
                peer = peers[i % len(peers)]
                chunk_info = manifest["chunks"][chunk_idx]
                t = threading.Thread(target=self._request_chunk, args=(file_id, chunk_idx, chunk_info, peer))
                t.start()
                threads.append(t)
                
            for t in threads:
                t.join()
                
            # Vérification du progrès
            with self.download_lock:
                if info["received_count"] == info["total_chunks"]:
                    info["status"] = "completed"
                    print(f"[+] Téléchargement terminé : {manifest['filename']}")
                    self._finalize_file(file_id)
                    break
            
            time.sleep(0.1)

    def _request_chunk(self, file_id, chunk_idx, chunk_info, peer_id):
        """Demande et attend un chunk spécifique."""
        chunk_hash = chunk_info["hash"]
        event = threading.Event()
        
        with self.download_lock:
            self.chunk_waiters[chunk_hash] = event
            
        # Envoyer la requête
        payload = {
            "file_id": file_id,
            "chunk_idx": chunk_idx,
            "requester": self.node.NODE_ID
        }
        self.node._send_secure_tlv(peer_id, TYPE_CHUNK_REQ, payload)
        
        # Attendre la réponse (timeout 5s)
        if event.wait(timeout=5.0):
            data = self.chunk_data.pop(chunk_hash, None)
            if data:
                # Stocker le chunk
                self.node.storage_mgr.store_chunk(file_id, chunk_idx, chunk_hash, data)
                with self.download_lock:
                    info = self.active_downloads[file_id]
                    if chunk_idx in info["missing_indices"]:
                        info["missing_indices"].remove(chunk_idx)
                        info["received_count"] += 1
                return True
        
        return False

    def handle_chunk_data(self, payload):
        """Appelé par DiscoveryNode quand un TYPE_CHUNK_DATA arrive."""
        chunk_hash = payload.get('chunk_hash')
        data_hex = payload.get('data')
        if not chunk_hash or not data_hex: return
        
        data = bytes.fromhex(data_hex)
        
        # Vérification d'intégrité
        if hashlib.sha256(data).hexdigest() == chunk_hash:
            with self.download_lock:
                self.chunk_data[chunk_hash] = data
                event = self.chunk_waiters.pop(chunk_hash, None)
                if event:
                    event.set()
        else:
            print(f"[!] Chunk corrompu reçu ! Hash mismatch pour {chunk_hash[:8]}")

    def _finalize_file(self, file_id):
        """Réassemble le fichier final."""
        with self.download_lock:
            info = self.active_downloads[file_id]
            manifest = info["manifest"]
            
        downloads_dir = os.path.join(self.node.storage_mgr.root_dir, "downloads")
        os.makedirs(downloads_dir, exist_ok=True)
        
        final_path = os.path.join(downloads_dir, manifest["filename"])
        
        with open(final_path, "wb") as f_out:
            for chunk_info in manifest["chunks"]:
                data = self.node.storage_mgr.get_chunk_data(chunk_info["hash"])
                if data:
                    f_out.write(data)
                else:
                    print(f"[!] Erreur critique : Chunk {chunk_info['index']} manquant lors de l'assemblage !")
                    return
        
        print(f"[+] Fichier réassemblé : {final_path}")
        # Vérifier le SHA-256 final du fichier réassemblé
        file_hash = hashlib.sha256()
        with open(final_path, "rb") as f:
            while chunk := f.read(8192):
                file_hash.update(chunk)
        
        if file_hash.hexdigest() == file_id:
            print(f"[VERIF] SHA-256 OK : {file_id[:16]}")
            self.node.storage_mgr.register_file(manifest, local_path=final_path)
        else:
            print(f"[!] ALERTE : SHA-256 final invalide ! Fichier corrompu.")
