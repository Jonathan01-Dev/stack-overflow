# ⚓ ARCHIPEL - Protocole P2P Souverain

Archipel est un système de communication décentralisé, souverain et chiffré de bout en bout, conçu pour fonctionner sans infrastructure centrale (Ad-hoc, Local Mesh).

## 🚀 Fonctionnalités Clés

- **Messagerie Premium (Sprint 4)** : Nouvelle interface style Messenger/Telegram avec gestion des conversations par ID et historique persistante.
- **Sécurité Militaire** : Chiffrement E2EE utilisant Ed25519 pour l'identité, X25519 pour l'échange de clés et AES-256-GCM pour les données.
- **Découverte Automatique** : Scan réseau via Multicast et UDP Broadcast pour trouver les pairs sans configuration.
- **Web of Trust (WoT)** : Système de certification des pairs pour garantir l'identité des interlocuteurs.
- **Partage de Fichiers** : Catalogue réseau décentralisé avec téléchargement P2P haute performance.
- **Dashboard Web Glassmorphism** : Interface moderne pour piloter votre nœud depuis n'importe quel navigateur.

## 🛠️ Installation & Démarrage

### Prérequis
- Python 3.8+
- Flask & Flask-Cors (`pip install flask flask-cors`)
- PyNaCl (`pip install pynacl`)

### Lancer un nœud
Pour démarrer votre instance avec l'interface Web sur le port 8080 :
```bash
python archipel.py --port 7777 --web-port 8080
```

### Utilisation de l'interface
1. Ouvrez [http://localhost:8080](http://localhost:8080)
2. **Dashboard** : Surveillez l'état de votre nœud et les transferts.
3. **Messenger** : Sélectionnez un pair dans la liste à gauche pour démarrer une conversation chiffrée.
4. **Fichiers** : Parcourez les fichiers partagés sur le réseau et téléchargez-les.
5. **Web of Trust** : Validez l'identité de vos pairs pour renforcer la sécurité.

## 🔒 Sécurité & Souveraineté
Archipel ne dépend d'aucun serveur central. Toutes les clés privées restent localement dans votre dossier `.archipel/`. Les messages et fichiers ne transitent que par des canaux sécurisés et directs entre pairs.

## 📝 Licence
Projet développé dans le cadre du protocole de communication souverain (Sprint 1-4).
