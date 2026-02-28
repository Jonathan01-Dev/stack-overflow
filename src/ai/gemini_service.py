import os
import json
import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

class GeminiService:
    """Service to interact with the Google Gemini API."""
    
    def __init__(self, api_key=None, enabled=True):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.enabled = enabled
        self.model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        self.api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"

    def build_prompt(self, conversation_context, user_query, files_context=None):
        """Constructs a prompt with history and file context."""
        prompt = "Tu es Archipel-AI, un assistant intelligent intégré au protocole P2P Archipel.\n"
        prompt += "Utilise le contexte suivant pour répondre à l'utilisateur de manière précise.\n\n"
        
        if files_context:
            text_files = {k: v for k, v in files_context.items() if not (isinstance(v, dict) and v.get("type") == "gemini_file")}
            if text_files:
                prompt += "--- CONTENU DES FICHIERS ---\n"
                for filename, content in text_files.items():
                    prompt += f"Fichier: {filename}\nContenu:\n{content}\n---\n"
                prompt += "\n"

        prompt += "--- HISTORIQUE DES DISCUSSIONS ---\n"
        for msg in conversation_context:
            role = "Utilisateur" if msg.get("type") == "in" else "Moi (Archipel-AI)"
            prompt += f"{role}: {msg.get('text')}\n"
        
        prompt += f"\nNouvelle question: {user_query}\n"
        prompt += "Réponse:"
        return prompt

    def query(self, conversation_context, user_query, files_context=None):
        """Queries Gemini with the provided context."""
        if not self.enabled:
            return {"error": "L'IA est actuellement désactivée (--no-ai)."}
        
        if not self.api_key:
            return {"error": "Clé API Gemini manquante. Configurez GEMINI_API_KEY."}

        parts = []
        if files_context:
            for filename, content in files_context.items():
                if isinstance(content, dict) and content.get("type") == "gemini_file":
                    parts.append({
                        "fileData": {
                            "mimeType": content["mimeType"],
                            "fileUri": content["fileUri"]
                        }
                    })

        prompt_text = self.build_prompt(conversation_context, user_query, files_context)
        parts.append({"text": prompt_text})
        
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": parts
                }
            ]
        }
        
        try:
            response = requests.post(
                self.api_url,
                headers={'Content-Type': 'application/json'},
                data=json.dumps(payload),
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if "candidates" in result and result["candidates"]:
                    text = result["candidates"][0]["content"]["parts"][0]["text"]
                    return {"text": text}
                else:
                    return {"error": "Réponse vide de Gemini."}
            else:
                return {"error": f"Erreur API Gemini ({response.status_code}): {response.text}"}
                
        except requests.exceptions.RequestException as e:
            return {"error": f"Impossible de contacter Gemini : {str(e)}"}
        except Exception as e:
            return {"error": f"Erreur inattendue : {str(e)}"}

    def upload_file_chunked(self, file_path, mime_type=None, display_name=None):
        """Uploads a file in chunks to the Gemini API."""
        if not self.api_key:
            return {"error": "Clé API manquante."}
            
        if not mime_type:
            import mimetypes
            mime_type, _ = mimetypes.guess_type(file_path)
            
        supported_prefixes = ("text/", "image/", "audio/", "video/")
        supported_exact = (
            "application/pdf", 
            "application/json", 
            "application/x-javascript", 
            "application/x-python",
            "application/x-typescript",
            "application/xml",
            "application/rtf"
        )
        
        if mime_type:
            if not (mime_type.startswith(supported_prefixes) or mime_type in supported_exact):
                mime_type = "text/plain"
        else:
            mime_type = "text/plain"
                
        if not display_name:
            display_name = os.path.basename(file_path)
            
        try:
            file_size = os.path.getsize(file_path)
            
            # 1. Start Resumable Upload
            init_url = f"https://generativelanguage.googleapis.com/upload/v1beta/files?key={self.api_key}"
            headers = {
                "X-Goog-Upload-Protocol": "resumable",
                "X-Goog-Upload-Command": "start",
                "X-Goog-Upload-Header-Content-Length": str(file_size),
                "X-Goog-Upload-Header-Content-Type": mime_type,
                "Content-Type": "application/json"
            }
            data = {"file": {"display_name": display_name}}
            
            res_init = requests.post(init_url, headers=headers, json=data, timeout=10)
            if res_init.status_code != 200:
                return {"error": f"Erreur d'initialisation de l'upload ({res_init.status_code}): {res_init.text}"}
                
            upload_url = res_init.headers.get("X-Goog-Upload-URL")
            if not upload_url:
                return {"error": "URL d'upload non retournée par l'API."}
                
            # 2. Upload Chunks (8MB chunks)
            chunk_size = 8 * 1024 * 1024
            offset = 0
            
            with open(file_path, "rb") as f:
                while offset < file_size:
                    chunk = f.read(chunk_size)
                    is_last = (offset + len(chunk)) >= file_size
                    command = "upload, finalize" if is_last else "upload"
                    
                    upload_headers = {
                        "X-Goog-Upload-Offset": str(offset),
                        "X-Goog-Upload-Command": command,
                        "Content-Length": str(len(chunk))
                    }
                    
                    res_chunk = requests.post(upload_url, headers=upload_headers, data=chunk, timeout=60)
                    if res_chunk.status_code != 200:
                        return {"error": f"Erreur lors de l'envoi du chunk ({res_chunk.status_code}): {res_chunk.text}"}
                    
                    offset += len(chunk)
            
            # The last response contains the JSON info about the File
            return res_chunk.json()
            
        except requests.exceptions.RequestException as e:
            return {"error": f"Erreur réseau pendant l'upload: {str(e)}"}
        except Exception as e:
            return {"error": f"Erreur inattendue pendant l'upload: {str(e)}"}
