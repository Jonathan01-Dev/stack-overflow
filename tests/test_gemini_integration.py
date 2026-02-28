import sys
import os
import json
import unittest
from unittest.mock import MagicMock, patch

# Ajouter src au path
sys.path.append(os.path.join(os.getcwd(), "src"))
sys.path.append(os.path.join(os.getcwd(), "src", "ai"))

from gemini_service import GeminiService

class TestGeminiIntegration(unittest.TestCase):
    def setUp(self):
        self.api_key = "test_key"
        self.service = GeminiService(api_key=self.api_key, enabled=True)

    def test_no_ai_flag(self):
        """Vérifie que le service respecte l'activation/désactivation."""
        disabled_service = GeminiService(enabled=False)
        result = disabled_service.query([], "Hello")
        self.assertIn("error", result)
        self.assertEqual(result["error"], "L'IA est actuellement désactivée (--no-ai).")

    def test_missing_api_key(self):
        """Vérifie le message d'erreur si la clé est absente."""
        with patch.dict(os.environ, {}, clear=True):
            missing_key_service = GeminiService(api_key=None, enabled=True)
            result = missing_key_service.query([], "Hello")
            self.assertIn("error", result)
            self.assertEqual(result["error"], "Clé API Gemini manquante. Configurez GEMINI_API_KEY.")

    def test_prompt_construction(self):
        """Vérifie que le prompt contient l'historique et le RAG."""
        history = [
            {"type": "in", "text": "Comment ça va ?"},
            {"type": "out", "text": "Très bien et toi ?"}
        ]
        files = {"README": "C'est un projet P2P."}
        query = "C'est quoi le but ?"
        
        prompt = self.service.build_prompt(history, query, files)
        
        self.assertIn("Archipel-AI", prompt)
        self.assertIn("Comment ça va ?", prompt)
        self.assertIn("Très bien et toi ?", prompt)
        self.assertIn("README", prompt)
        self.assertIn("C'est un projet P2P.", prompt)
        self.assertIn("C'est quoi le but ?", prompt)

    @patch('requests.post')
    def test_successful_query(self, mock_post):
        """Teste une réponse API réussie (mockée)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": "Je suis ton assistant Archipel."}]
                    }
                }
            ]
        }
        mock_post.return_value = mock_response
        
        result = self.service.query([], "Qui es-tu ?")
        self.assertEqual(result["text"], "Je suis ton assistant Archipel.")

    @patch('requests.post')
    def test_api_error_handling(self, mock_post):
        """Teste la gestion des erreurs API."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "Invalid API Key"
        mock_post.return_value = mock_response
        
        result = self.service.query([], "Hello")
        self.assertIn("error", result)
        self.assertIn("403", result["error"])

if __name__ == "__main__":
    unittest.main()
