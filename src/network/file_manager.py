import os
import hashlib
import json
import math

class FileManager:
    def __init__(self, chunk_size=524288): # 512 KB
        self.chunk_size = chunk_size

    def create_manifest(self, filepath, crypto_manager):
        """Crée un manifest pour un fichier donné."""
        if not os.path.exists(filepath):
            return None

        filename = os.path.basename(filepath)
        size = os.path.getsize(filepath)
        nb_chunks = math.ceil(size / self.chunk_size)
        
        file_hash = hashlib.sha256()
        chunks_info = []

        with open(filepath, "rb") as f:
            for i in range(nb_chunks):
                chunk_data = f.read(self.chunk_size)
                if not chunk_data:
                    break
                
                chunk_hash = hashlib.sha256(chunk_data).hexdigest()
                file_hash.update(chunk_data)
                
                chunks_info.append({
                    "index": i,
                    "hash": chunk_hash,
                    "size": len(chunk_data)
                })

        full_file_id = file_hash.hexdigest()
        
        manifest = {
            "file_id": full_file_id,
            "filename": filename,
            "size": size,
            "chunk_size": self.chunk_size,
            "nb_chunks": nb_chunks,
            "chunks": chunks_info,
            "sender_id": crypto_manager.get_node_id()
        }

        # Signature du manifest (sur le hash du contenu JSON standardisé)
        manifest_content = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')
        manifest_hash = hashlib.sha256(manifest_content).digest()
        manifest["signature"] = crypto_manager.sign(manifest_hash).hex()

        return manifest

    @staticmethod
    def verify_chunk(data, expected_hash):
        """Vérifie l'intégrité d'un chunk."""
        actual_hash = hashlib.sha256(data).hexdigest()
        return actual_hash == expected_hash

    def get_chunk(self, filepath, chunk_index):
        """Récupère les octets d'un chunk spécifique dans un fichier."""
        if not os.path.exists(filepath):
            return None
        
        with open(filepath, "rb") as f:
            f.seek(chunk_index * self.chunk_size)
            return f.read(self.chunk_size)
