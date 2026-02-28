#!/usr/bin/env python3
import argparse
import os
import sys

# Ajouter le chemin src pour les imports
sys.path.append(os.path.join(os.path.dirname(__file__), "src", "network"))

def main():
    parser = argparse.ArgumentParser(description="ARCHIPEL - Protocole P2P Souverain")
    subparsers = parser.add_subparsers(dest="command", help="Commandes disponibles")

    # Commande 'start'
    start_parser = subparsers.add_parser("start", help="Démarrer un nœud Archipel")
    start_parser.add_argument("--port", type=int, default=7777, help="Port TCP (7777 par défaut)")
    start_parser.add_argument("--key", type=str, default="node.key", help="Fichier de clé privée")

    # Commande 'gen-key' (utilitaire)
    subparsers.add_parser("gen-key", help="Générer une nouvelle identité Ed25519")

    args = parser.parse_args()

    if args.command == "start":
        # Déposer les variables d'environnement pour discovery.py si besoin
        os.environ["TCP_PORT"] = str(args.port)
        
        from discovery import DiscoveryNode, NODE_ID
        
        if NODE_ID == "UNKNOWN_NODE":
            print("\033[91m[!] Erreur : Identité introuvable. Lancez 'python archipel.py gen-key' d'abord.\033[0m")
            return

        node = DiscoveryNode()
        
        # Lancement des services
        import threading
        node.start_beacon()
        node.start_listener()
        node.start_tcp_server()
        
        threading.Thread(target=node.clean_peers, daemon=True).start()
        threading.Thread(target=node.keep_alive_connections, daemon=True).start()
        
        # Interface CLI Premium
        node.start_cli()
        
        import time
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\033[93m[!] Arrêt du nœud Archipel...\033[0m")
            os._exit(0)

    elif args.command == "gen-key":
        print("[*] Génération d'une nouvelle identité...")
        # Simuler ou appeler src/crypto/generate_identity.py
        import subprocess
        subprocess.run([sys.executable, "src/crypto/generate_identity.py"])
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
