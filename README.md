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


