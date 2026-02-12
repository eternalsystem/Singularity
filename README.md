# Singularity

Singularity est un outil d'analyse de logiciels malveillants et de rétro‑ingénierie écrit en Rust. Il fournit une interface GUI rapide et une CLI pour analyser des fichiers binaires, des paquets JavaScript/Node.js et des charges Python obfusquées, avec extraction de contenus, désassemblage et détection de secrets.

## Vue d’ensemble
- **Double mode GUI/CLI** : interface graphique eframe/egui et analyse en ligne de commande.
- **Analyse multi‑formats** : PE/ELF, scripts, archives et conteneurs.
- **Extraction et déobfuscation** : PyInstaller, PyArmor, JS obfusqué, fichiers embarqués.
- **Détection avancée** : YARA (Boreal), secrets, URLs, heuristiques et couche par couche.
- **Outils intégrés** : décodeurs, stéganographie, scanner en ligne, rapport webhook.

## Architecture (haute‑niveau)
- **Point d’entrée** : `src/main.rs` choisit le mode CLI si un chemin est fourni, sinon démarre la GUI.
- **Interface** : `src/app.rs` gère l’état, les onglets, le viewer de code, l’envoi de rapport et le consentement YARA.
- **Moteur d’analyse** : `src/analysis.rs` orchestre la détection de type, la sélection d’analyseur et l’agrégation des résultats.
- **Analyse en couches** : `src/layered_analysis.rs` construit un rapport par couches avec guide d’investigation.
- **YARA** : `src/signature_engine.rs` + `src/update_rules.rs` chargent et mettent à jour les règles (yara‑forge).
- **Outils externes** : `src/tools_manager.rs` installe Node.js, Synchrony/deobfuscator et asar via npm, et PyArmor OneShot.
- **Services** : `src/online_scanner.rs` intègre OPSWAT MetaDefender Cloud.
- **Modules malware** : `src/malware/*` et `src/heuristic_decryptor.rs` gèrent la déobfuscation et l’extraction de configs.

## Flux d’analyse (résumé)
1. **Détection du type** (format, langage, heuristiques de conteneur).
2. **Sélection d’un analyseur** (PyArmor, PyInstaller, PYC, binaire, texte, Lua, inconnu).
3. **Extraction des contenus** (archives internes, snapshots, sections, strings).
4. **Déobfuscation** (Synchrony pour JS, PyArmor OneShot, routines spécifiques malware).
5. **Désassemblage** et **collecte des imports/sections**.
6. **Détection YARA** si les règles sont installées.
7. **Scan de secrets/URLs** sur les sorties.
8. **Rapport en couches** avec instructions de suivi.

## Fonctionnalités détaillées

### 🔍 Analyse statique avancée
- **Binaire** : parsing via Goblin, sections, imports, strings.
- **Désassemblage** : Capstone avec listing lisible.
- **Secrets & URLs** : regex + heuristiques (Base64, tokens inversés).
- **YARA** : scan des octets et chargement automatique de règles.

### 📦 JavaScript / Node.js
- **ASAR** : extraction des archives Electron.
- **PKG snapshot** : reconstruction et listing des fichiers JS.
- **Déobfuscation** : Synchrony/deobfuscator via npm.
- **Sandbox** : exécution isolée via Boa.
- **Viewer** : affichage du code original/déobfusqué avec recherche.

### 🧪 Python & stealer
- **PyInstaller** : extraction du TOC, reconstruction de PYC et désassemblage.
- **PyArmor OneShot** : support d’extraction automatisée.
- **Déchiffrement heuristique** : clés/IV détectées dans le code/disassembly.
- **Modules stealer** : déobfuscation et extraction de configuration.

### 🧰 Outils complémentaires
- **Décodeur de chaînes** : Base64, Hex, Rot13, Reverse, URL, Binaire.
- **Stéganographie** : LSB, métadonnées et intégration Aperi'Solve.
- **Décrypteur de liens** : mode manuel dans le viewer.
- **Rapport** : envoi par webhook avec embeds et suppression possible.

### ☁️ Scanner en ligne
- **MetaDefender Cloud (OPSWAT)** : 30+ moteurs AV via API.
- **Optimisation** : tentative de résolution par hash avant upload.

## Interface GUI (onglets)
- **Info** : format, langage, score et méta.
- **URLs** : extraction centralisée.
- **Imports / Sections** : vue binaire.
- **Strings / Disassembly** : recherche texte intégrée.
- **Secrets** : tokens et clés détectés.
- **Extracted** : fichiers, code original/déobfusqué, sandbox JS.
- **Layered Analysis** : rapport multi‑couches et guide.
- **Send Report** : webhook + embeds + image.
- **Online Scan** : MetaDefender Cloud.

## Stockage local
- **Outils** : `%APPDATA%\Singularity\tools` (Windows).
- **Extraits** : `%APPDATA%\Singularity\extracted`.
- **Règles YARA** : `%APPDATA%\Singularity\signatures`.
- **Config** : `%APPDATA%\Singularity\config.json`.
- **Fallback** : si APPDATA/LOCALAPPDATA indisponible, le dossier temporaire est utilisé.

## Installation

### Prérequis
- Rust (dernière version stable)
- Dépendances système pour `eframe`/`wgpu` (généralement installées par défaut sur Windows/macOS, paquets `libgtk-3-dev` etc. sur Linux).

### Compilation
```bash
git clone https://github.com/votre-username/singularity.git
cd singularity
cargo run --release
```

### Installation d’outils externes
Lors du premier lancement, Singularity peut installer automatiquement :
- Node.js (portable) pour Synchrony/deobfuscator et asar.
- PyArmor OneShot et ses dépendances.
- Règles YARA via yara‑forge (sur consentement explicite).

## Utilisation

### Mode GUI
```bash
cargo run --release
```
Glissez‑déposez un fichier dans la fenêtre ou utilisez le menu pour ouvrir un fichier à analyser.

### Mode CLI
```bash
cargo run --release -- <chemin_du_fichier>
```
La CLI affiche un suivi de progression, les résultats de base et le rapport en couches.

## Technologies
- **Langage** : Rust 🦀
- **GUI** : eframe / egui
- **Parsing binaire** : Goblin
- **Désassemblage** : Capstone
- **Moteur JS** : Boa
- **Matching de signatures** : Boreal (YARA)
- **HTTP** : reqwest

## Avertissement
Cet outil est destiné à des fins éducatives et de recherche en sécurité. L’analyse de logiciels malveillants doit être effectuée dans un environnement isolé et sécurisé (machine virtuelle, sandbox). L’auteur n’est pas responsable de l’utilisation abusive de cet outil.
