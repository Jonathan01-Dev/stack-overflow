import nacl.signing
import nacl.encoding
import binascii
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KEY_PATH = os.path.join(PROJECT_ROOT, "node.key")

def generate_keys():
    # 1. Générer une clé de signature (Clé Privée)
    private_key = nacl.signing.SigningKey.generate()
    
    # 2. Dériver la clé de vérification (Clé Publique)
    public_key = private_key.verify_key

    # 3. Convertir en format Hexadécimal pour l'affichage et le réseau
    node_id = public_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
    private_hex = private_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')

    # 4. Sauvegarder la clé privée dans un fichier sécurisé (.key)
    # Note: Ajoutez *.key à votre .gitignore !
    with open(KEY_PATH, "w", encoding="utf-8") as f:
        f.write(private_hex)

    print(f"✅ IDENTITÉ GÉNÉRÉE")
    print(f"Votre NODE_ID (Public) : {node_id}")
    print(f"Clé sauvegardée dans : {KEY_PATH}")
    
    return node_id

if __name__ == "__main__":
    generate_keys()