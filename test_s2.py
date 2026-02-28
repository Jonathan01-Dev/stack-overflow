import time
import threading
import sys
import os

# Ajouter le chemin pour importer les modules
sys.path.append(os.path.join(os.path.dirname(__file__), "src/network"))

from discovery import DiscoveryNode, NODE_ID

def demo_s2():
    print("=== DÉMO SPRINT 2 : CHIFFREMENT DE BOUT EN BOUT ===")
    
    # On suppose que node.key et node2.key existent
    # Instance Alice (initiateur)
    alice = DiscoveryNode()
    alice.start_tcp_server() # Alice écoute aussi
    
    print(f"Alice (Node ID: {NODE_ID[:8]}...) est prête.")
    
    # On attend un peu que tout démarre
    time.sleep(2)
    
    print("\n--- TEST : Envoi d'un message chiffré ---")
    print("Alice tente de se connecter à un Node local (simulation)...")
    
    # Note: Dans un vrai test, on lancerait deux processus.
    # Ici on explique comment le faire.
    print("\nVeuillez lancer deux terminaux :")
    print("Terminal 1 : python src/network/discovery.py --port 7777 --key node.key")
    print("Terminal 2 : python src/network/discovery.py --port 7778 --key node2.key")
    print("\nObservez les logs : '[+] Tunnel E2EE établi avec ... (X25519 + AES-GCM)'")

if __name__ == "__main__":
    demo_s2()
