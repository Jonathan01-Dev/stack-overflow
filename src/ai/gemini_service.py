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
            prompt += "--- CONTENU DES FICHIERS ---\n"
            for filename, content in files_context.items():
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

        prompt = self.build_prompt(conversation_context, user_query, files_context)
        
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}]
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
