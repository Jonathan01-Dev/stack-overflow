import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import nacl.signing
import nacl.encoding

class CryptoManager:
    """Gère les primitives cryptographiques globales et les clés permanentes."""
    def __init__(self, private_key_hex):
        # Clé permanente Ed25519 (pour signature/identité)
        self.signing_key = nacl.signing.SigningKey(private_key_hex, encoder=nacl.encoding.HexEncoder)
        self.verify_key = self.signing_key.verify_key
        self.public_key_hex = self.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')

    def sign(self, message_bytes):
        return self.signing_key.sign(message_bytes).signature

    def verify(self, message_bytes, signature_bytes, public_key_hex):
        verify_key = nacl.signing.VerifyKey(public_key_hex, encoder=nacl.encoding.HexEncoder)
        try:
            verify_key.verify(message_bytes, signature_bytes)
            return True
        except Exception:
            return False

class CryptoSession:
    """Gère une session sécurisée éphémère (Tunnel AES-GCM) entre deux nœuds."""
    def __init__(self, shared_key):
        # Dériver la clé de session AES-256 via HKDF
        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'archipel-v1',
        ).derive(shared_key)
        self.aesgcm = AESGCM(self.session_key)

    def encrypt(self, plaintext_bytes):
        """Chiffre les données avec AES-256-GCM et un nonce aléatoire."""
        nonce = secrets.token_bytes(12) # 96-bit nonce
        ciphertext = self.aesgcm.encrypt(nonce, plaintext_bytes, None)
        return nonce, ciphertext

    def decrypt(self, nonce, ciphertext_bytes):
        """Déchiffre les données et vérifie l'intégrité (Tag GCM)."""
        try:
            return self.aesgcm.decrypt(nonce, ciphertext_bytes, None)
        except Exception:
            return None

def generate_ephemeral_keypair():
    """Génère une paire de clés X25519 éphémère pour le handshake."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def compute_shared_secret(private_key, remote_public_key_bytes):
    """Calcule le secret partagé Diffie-Hellman (X25519)."""
    remote_public_key = x25519.X25519PublicKey.from_public_bytes(remote_public_key_bytes)
    return private_key.exchange(remote_public_key)
