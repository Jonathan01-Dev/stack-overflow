# ARCHIPEL - Protocole P2P Souverain
### Hackathon "The Geek & The Moon" — Lomé Business School (LBS)

## 1. Choix Technologiques (Sprint 0)

### Langage & Écosystème

Nous avons choisi **Python** comme langage principal car la majorité de l’équipe est à l'aise avec, ce qui est essentiel dans un hackathon de 24 heures. Python offre des bibliothèques fiables pour la cryptographie **(PyNaCl, PyCryptodome)** et le réseau **(socket, asyncio)**, tout en permettant un développement rapide et lisible. Ce choix nous permet de nous concentrer sur l’architecture du protocole plutôt que sur la complexité technique.

## 2. Architecture du Système

```
╔══════════════════════════════════════════════════════════════════╗
║                   ARCHIPEL - RÉSEAU P2P                          ║
║             Protocole Chiffré à Zéro-Connexion                   ║
╚══════════════════════════════════════════════════════════════════╝

               ┌─────────────┐         ┌─────────────┐
               │   NŒUD A    │         │   NŒUD B    │
               │             │         │             │
               │─────────────│         │─────────────│
               │ 🔑 Ed25519  │         │ 🔑 Ed25519  │
               │ 📦 Chunks   │         │ 📦 Chunks   │
               └──────┬──────┘         └──────┬──────┘
                      │                       │
                      │    UDP MULTICAST      │
                      │    239.255.42.99:6000 │
                      │◄─────── HELLO ───────►│
                      │◄─── PEER_LIST ───────►│
                      │                       │
                      │      TCP :7777        │
                      │◄════ HANDSHAKE ══════►│
                      │    (X25519+Ed25519)   │
                      │◄════ MSG CHIFFRÉ ════►│
                      │      (AES-256-GCM)    │
                      │◄════ CHUNKS ═════════►│
                      │    (SHA-256 vérifié)  │
                      └───────────┬───────────┘
                                  │
                           ┌──────┴──────┐
                           │   NŒUD C    │
                           │  (Charlie)  │
                           │─────────────│
                           │ 🔑 Ed25519  │
                           │ 📦 Chunks   │
                           └─────────────┘

```

## 3. Spécification du Protocole Binaire v1.0

Chaque paquet transmis respecte une structure binaire stricte pour garantir l'interopérabilité.

### Structure Globale

```
┌─────────────────────────────────────────────────────────┐
│                    ARCHIPEL PACKET v1                   │
├──────────┬──────────┬───────────┬───────────────────────┤
│  MAGIC   │   TYPE   │  NODE_ID  │      PAYLOAD_LEN      │
│  4 bytes │  1 byte  │ 32 bytes  │  4 bytes (uint32_BE)  │
├──────────┴──────────┴───────────┴───────────────────────┤
│           PAYLOAD  (chiffré, longueur variable)         │
├─────────────────────────────────────────────────────────┤
│              HMAC-SHA256 SIGNATURE  (32 bytes)          │
└─────────────────────────────────────────────────────────┘

Types de paquets :
  0x01  HELLO      — annonce de présence sur le réseau
  0x02  PEER_LIST  — réponse avec liste des nœuds connus
  0x03  MSG        — message chiffré
  0x04  CHUNK_REQ  — requête d'un bloc de fichier
  0x05  CHUNK_DATA — transfert d'un bloc de fichier
  0x06  MANIFEST   — métadonnées d'un fichier (hash, nb chunks)
  0x07  ACK        — acquittement
```

### Détail du Header (41 octets) — Encodage Big-Endian

| Champ | Taille | Description |
|-------|--------|-------------|
| `MAGIC` | 4 bytes | Identifiant du protocole : `ARCH` |
| `TYPE` | 1 byte | Type de paquet (0x01 à 0x07) |
| `NODE_ID` | 32 bytes | Clé publique Ed25519 de l'émetteur |
| `PAYLOAD_LEN` | 4 bytes | Taille du payload en bytes |

## 4. Guide d'Utilisation (Sprint 2 & 3)

### Installation & Configuration
1.  **Cloner le projet** et se placer à la racine :
    ```bash
    git clone https://github.com/Jonathan01-Dev/stack-overflow.git
    cd stack-overflow
    ```
2.  **Installer les dépendances** :
    ```bash
    pip install -r requirements.txt
    ```
3.  **Générer votre identité** (obligatoire au premier lancement) :
    ```bash
    python src/crypto/generate_identity.py
    ```

### Lancement des Nœuds
Lancer les terminaux depuis le dossier `src/network` :
```bash
cd src/network

# Nœud Alice (Port par défaut 7777)
python discovery.py --port 7777 --key node.key

# Nœud Bob (Port 7778, Clé différente)
python discovery.py --port 7778 --key node2.key
```

---

## 5. Répertoire des Commandes CLI
Une fois le nœud lancé, tapez ces commandes dans l'invite `Archipel>` :

### 💬 Messagerie Sécurisée (E2EE)
- `/msg <texte>` : Envoie un message chiffré à tous les pairs connectés.
- `/list` : Affiche les identités (`node_id`) des pairs connectés dans le tunnel.

### 📦 Partage de Fichiers (P2P Transfer)
- `/ls` : Liste les fichiers locaux (actuel + racine du projet).
- `/share <nom_fichier>` : Découpe et met en partage un fichier.
  - *Exemple (Linux)* : `/share /home/koffi/Documents/rapport.pdf`
  - *Exemple (Windows)* : `/share C:\Users\Perso\Desktop\photo.jpg`
- `/files` : Affiche les fichiers disponibles sur le réseau.
- `/download <id_prefix>` : Démarre le téléchargement parallèle (multi-source).
- `/status` : Affiche l'avancement (%) des téléchargements.

### 🛠️ Utilitaires
- `/debug` : État technique des sessions et connexions.
- `/quit` : Arrête le nœud.

/share C:\Users\HP ELITEBOOK\Downloads\Wireshark-4.6.4-x64.exe
         
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
