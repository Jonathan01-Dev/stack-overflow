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
- **Sprint 4.2 : Intégration Gemini & RAG** : 
    - Liaison avec l'API Gemini Pro pour l'assistance intelligente.
    - Système RAG (Retrieval-Augmented Generation) sur les discussions et les fichiers locaux.
    - Isolation stricte et mode offline via le flag `--no-ai`.

---

## 🛠️ Installation & Démarrage Rapide

### 1. Cloner et Installer les dépendances
```bash
# Modules Python requis
pip install flask flask-cors pynacl
```

### 2. Lancer un nœud Archipel
```bash
# Lance le noeud P2P et l'interface Web sur le port 8080 avec IA activée
# Assurez-vous d'avoir configuré votre clé dans le fichier .env
python archipel.py --port 7777 --web-port 8080

# Pour désactiver l'IA (Mode Offline/Privé)
python archipel.py --no-ai
```

### 3. Intelligence Artificielle (Gemini)
L'intégration Gemini permet d'avoir un assistant intelligent capable de comprendre le contexte de vos conversations et de vos fichiers.

**Configuration :**
- Créez un fichier `.env` avec votre clé : `GEMINI_API_KEY=votre_cle_api`
- Ou passez-la directement via `--ai-key <key>`

**Commandes CLI :**
- `--no-ai` : Désactive complètement toute connexion externe vers Gemini (Souveraineté totale).
- `--ai-key <key>` : Utilise une clé API spécifique pour cette session.

**Usage dans le Messenger :**
- `/ask <question>` : Pose une question à l'IA en utilisant les derniers messages comme contexte.
- `@archipel-ai <question>` : Identique à `/ask`.

**Usage RAG (Files) :**
- Dans l'onglet **Fichiers**, cliquez sur **"Indexer AI"**. Cela extrait le texte du fichier et l'ajoute au "cerveau" de l'IA pour que vous puissiez poser des questions spécifiques sur ce document.

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
