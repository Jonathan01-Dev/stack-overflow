import os

def generate_file(filename, size_mb):
    """Génère un fichier de test binaire de la taille spécifiée en Mo."""
    size_bytes = size_mb * 1024 * 1024
    print(f"[*] Génération de {filename} ({size_mb} Mo)...")
    with open(filename, "wb") as f:
        f.write(os.urandom(size_bytes))
    print(f"[+] Fichier généré avec succès.")

if __name__ == "__main__":
    generate_file("test_50mb.bin", 50)
