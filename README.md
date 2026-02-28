# ⚓ ARCHIPEL - Protocole de Communication Souverain (Recap Sprints 1-4)

Archipel est un protocole de communication P2P souverain, chiffré et décentralisé, conçu pour fonctionner sans infrastructure centrale (Ad-hoc, Mesh local). Ce document retrace l'évolution du projet à travers les différents sprints.

---

## 📅 Historique des Sprints

### 🔹 Sprint 1 : Architecture & Identité Cryptographique
- **Objectif** : Créer le socle de sécurité et l'identité des nœuds.
- **Réalisations** : 
    - Génération d'identités souveraines basées sur **Ed25519** (clés publiques/privées).
    - Système de fichiers local pour le stockage sécurisé des clés (`node.key`).
    - Structure de données binaire pour les paquets réseau.

### 🔹 Sprint 2 : Network Discovery & Ad-hoc Networking
- **Objectif** : Permettre aux nœuds de se trouver sans serveur.
- **Réalisations** : 
    - Découverte auto-organisée via **Multicast UDP** (239.255.42.99:6000).
    - Mécanisme de fallback sur **Broadcast UDP**.
    - Serveur TCP persistant pour les échanges directs entre pairs.
    - Table des pairs dynamique avec gestion des timeouts.

### 🔹 Sprint 3 : Sécurité Avancée & Web of Trust (WoT)
- **Objectif** : Sécuriser les échanges et créer un réseau de confiance.
- **Réalisations** : 
    - Échange de clés **Diffie-Hellman (X25519)** pour établir des secrets partagés.
    - Chiffrement symétrique **AES-256-GCM** pour chaque message.
    - Implémentation du **Web of Trust** : possibilité de certifier (trust) un pair manuellement pour valider son identité.

### 🔹 Sprint 4 : Messenger Premium & Dashboard Web
- **Objectif** : Offrir une interface utilisateur moderne et une messagerie complète.
- **Réalisations** : 
    - **Dashboard Web (Glassmorphism)** : Interface responsive en HTML/CSS Vanilla avec flous élégants et dégradés.
    - **Messenger Dédié** : Système de chat bi-panneaux style WhatsApp Desktop, entièrement intégré.
    - **Historique Persistant** : Sauvegarde locale des messages reçus et envoyés par pair.
    - **Polling Temps Réel** : Mise à jour automatique des discussions sans rechargement.
    - **Partage de Fichiers** : Indexation et téléchargement décentralisé de fichiers à travers le réseau.

---

## 🛠️ Installation & Démarrage Rapide

### 1. Cloner et Installer les dépendances
```bash
# Modules Python requis
pip install flask flask-cors pynacl
```

### 2. Lancer un nœud Archipel
```bash
# Lance le noeud P2P et l'interface Web sur le port 8080
python archipel.py --port 7777 --web-port 8080
```

### 3. Accéder à l'interface
Ouvrez votre navigateur sur [http://localhost:8080](http://localhost:8080).

---

## 🏗️ Architecture Technique

| Composant | Technologie | Rôle |
|-----------|-------------|------|
| **Core P2P** | Python / Sockets | Gestion RAW des connexions TCP/UDP |
| **Identité** | Ed25519 (NaCl) | Signature et validation de l'origine |
| **Confidentialité** | X25519 + AES-GCM | Chiffrement de bout en bout (E2EE) |
| **API Backend** | Flask | Communication Dashboard <-> Nœud |
| **Frontend** | HTML5 / CSS3 / JS | Interface utilisateur premium |

---

## �️ Principes de Souveraineté
1. **Zéro Serveur** : Pas de cloud, pas de base de données centrale.
2. **Clés Locales** : Vous seul possédez votre clé privée.
3. **Résilience** : Fonctionne même si Internet est coupé, via le réseau local.

---
*Projet conçu pour la liberté de communication et la sécurité des échanges.* ⚓
