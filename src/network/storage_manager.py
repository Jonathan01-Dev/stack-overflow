import os
import json
import shutil

class StorageManager:
    def __init__(self, root_dir=None):
        if root_dir is None:
            # Par défaut dans le home de l'utilisateur ou dossier du projet
            self.root_dir = os.path.join(os.getcwd(), ".archipel")
        else:
            self.root_dir = root_dir
            
        self.storage_path = os.path.join(self.root_dir, "storage")
        self.index_file = os.path.join(self.root_dir, "index.json")
        
        os.makedirs(self.storage_path, exist_ok=True)
        self._init_index()

    def _init_index(self):
        if not os.path.exists(self.index_file):
            with open(self.index_file, "w") as f:
                json.dump({"files": {}, "chunks": {}}, f)

    def _load_index(self):
        try:
            with open(self.index_file, "r") as f:
                return json.load(f)
        except:
            return {"files": {}, "chunks": {}}

    def _save_index(self, index):
        with open(self.index_file, "w") as f:
            json.dump(index, f, indent=4)

    def register_file(self, manifest, local_path=None):
        """Enregistre un fichier (complet ou en cours) dans l'index."""
        index = self._load_index()
        file_id = manifest["file_id"]
        
        index["files"][file_id] = {
            "manifest": manifest,
            "local_path": local_path,
            "completed": local_path is not None and os.path.exists(local_path)
        }
        
        # Si le fichier est complet localement, on indexe ses chunks
        if local_path and os.path.exists(local_path):
            chunk_size = manifest["chunk_size"]
            for chunk in manifest["chunks"]:
                index["chunks"][chunk["hash"]] = {
                    "file_id": file_id,
                    "index": chunk["index"],
                    "path": local_path,
                    "offset": chunk["index"] * chunk_size
                }
        
        self._save_index(index)

    def store_chunk(self, file_id, chunk_index, chunk_hash, data):
        """Stocke un chunk individuel dans le dossier de stockage."""
        chunk_filename = f"chunk_{chunk_hash}"
        chunk_path = os.path.join(self.storage_path, chunk_filename)
        
        with open(chunk_path, "wb") as f:
            f.write(data)
            
        index = self._load_index()
        index["chunks"][chunk_hash] = {
            "file_id": file_id,
            "index": chunk_index,
            "path": chunk_path,
            "offset": 0
        }
        self._save_index(index)
        return chunk_path

    def get_chunk_data(self, chunk_hash):
        """Récupère les données d'un chunk à partir de son hash."""
        index = self._load_index()
        chunk_info = index["chunks"].get(chunk_hash)
        if not chunk_info:
            return None
            
        path = chunk_info["path"]
        offset = chunk_info.get("offset", 0)
        
        # On ne connaît pas forcément la taille ici, on la récupère du manifest si besoin
        # Mais simplifions : on relit depuis le manifest lié au file_id
        file_id = chunk_info["file_id"]
        manifest = index["files"].get(file_id, {}).get("manifest")
        if not manifest: return None
        
        # Trouver la taille du chunk dans le manifest
        chunk_size = 0
        for c in manifest["chunks"]:
            if c["index"] == chunk_info["index"]:
                chunk_size = c["size"]
                break
        
        if chunk_size == 0: return None

        with open(path, "rb") as f:
            f.seek(offset)
            return f.read(chunk_size)

    def has_chunk(self, chunk_hash):
        index = self._load_index()
        return chunk_hash in index["chunks"]

    def get_available_files(self):
        index = self._load_index()
        return index["files"]
