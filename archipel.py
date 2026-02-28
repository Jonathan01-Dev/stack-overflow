#!/usr/bin/env python3
import argparse
import os
import sys
import threading
import time

# Ajouter le chemin src pour les imports
sys.path.append(os.path.join(os.path.dirname(__file__), "src", "network"))

def main():
    parser = argparse.ArgumentParser(description="⚓ ARCHIPEL - Protocole P2P Souverain")
    
    # Arguments globaux
    parser.add_argument("--port", type=int, default=7777, help="Port TCP (7777 par défaut)")
    parser.add_argument("--key", type=str, default="node.key", help="Fichier de clé privée")
    parser.add_argument("--web-port", type=int, default=8080, help="Port du Dashboard Web (8080 par défaut)")
    
    # Sous-commandes (optionnelles)
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("start", help="Démarrer le nœud (facultatif)")
    subparsers.add_parser("gen-key", help="Générer une nouvelle identité Ed25519")
    
    args = parser.parse_args()

    # Logique de démarrage (par défaut ou via 'start')
    if args.command is None or args.command == "start":
        os.environ["TCP_PORT"] = str(args.port)
        os.environ["NODE_KEY"] = args.key
        
        # Imports après configuration de l'env
        try:
            from discovery import DiscoveryNode, NODE_ID
        except ImportError as e:
            print(f"\033[91m[!] Erreur d'import : {e}\033[0m")
            return

        if NODE_ID == "UNKNOWN_NODE":
            print("\033[91m[!] Erreur : Identité introuvable. Lancez 'python archipel.py gen-key' d'abord.\033[0m")
            return

        print(f"\033[94m[*] Identité du nœud : {NODE_ID}\033[0m")
        node = DiscoveryNode()
        
        # Lancement des services réseau
        node.start_beacon()
        node.start_listener()
        node.start_tcp_server()
        
        threading.Thread(target=node.clean_peers, daemon=True).start()
        threading.Thread(target=node.keep_alive_connections, daemon=True).start()
        
        # Lancement du Dashboard Web (Sprint 4.1+)
        try:
            from web_server import start_web_server
            threading.Thread(target=start_web_server, args=(node, args.web_port), daemon=True).start()
        except Exception as e:
            print(f"\033[33m[!] Erreur Serveur Web : {e}\033[0m")

        # Interface CLI (Premium)
        node.start_cli()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\033[93m[!] Arrêt du nœud Archipel...\033[0m")
            os._exit(0)

    elif args.command == "gen-key":
        print("[*] Génération d'une nouvelle identité...")
        import subprocess
        key_gen_path = os.path.join("src", "crypto", "generate_identity.py")
        subprocess.run([sys.executable, key_gen_path])
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
