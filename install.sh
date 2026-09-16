#!/usr/bin/env bash
# ============================================
# JATHNIEL-WEB-CRAWLER-PRO v5.0
# Script d'installation automatique
# Ubuntu / Debian / Kali / WSL
# ============================================

set -e

# --- Couleurs ---
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
BOLD='\033[1m'
NC='\033[0m'

log()   { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[✗]${NC} $1"; }

# --- Bannière ---
cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██╗ █████╗ ████████╗██╗  ██╗███╗   ██╗██╗███████╗██╗     ██╗   ██╗         ║
║   ██║██╔══██╗╚══██╔══╝██║  ██║████╗  ██║██║██╔════╝██║     ██║   ██║         ║
║   ██║███████║   ██║   ███████║██╔██╗ ██║██║█████╗  ██║     ██║   ██║         ║
║   ██║██╔══██║   ██║   ██╔══██║██║╚██╗██║██║██╔══╝  ██║     ██║   ██║         ║
║   ██║██║  ██║   ██║   ██║  ██║██║ ╚████║██║███████╗███████╗╚██████╔╝         ║
║   ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚══════╝╚══════╝ ╚═════╝          ║
║                                                                              ║
║        WEB CRAWLER + DB EXTRACTOR v5.0 — Installation                        ║
║        🛡️  Usage éducatif / CTF / pentest autorisé uniquement                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF

echo ""

# --- 1. Vérifier Python ---
log "Vérification de Python..."
if ! command -v python3 &> /dev/null; then
    err "Python3 n'est pas installé."
    log "Installation de Python3..."
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv
else
    PY_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    ok "Python3 détecté : $PY_VERSION"
fi

# --- 2. Vérifier pip ---
log "Vérification de pip..."
if ! python3 -m pip --version &> /dev/null; then
    warn "pip manquant, installation..."
    sudo apt update
    sudo apt install -y python3-pip
else
    ok "pip disponible"
fi

# --- 3. Vérifier venv ---
log "Vérification de venv..."
if ! python3 -c "import venv" &> /dev/null; then
    warn "venv manquant, installation..."
    sudo apt install -y python3-venv
else
    ok "venv disponible"
fi

# --- 4. Détecter ou créer le venv ---
if [ -d ".venv" ]; then
    VENV_DIR=".venv"
    warn "Dossier '.venv' détecté, réutilisation..."
elif [ -d "venv" ]; then
    VENV_DIR="venv"
    warn "Dossier 'venv' détecté, réutilisation..."
else
    VENV_DIR=".venv"
    log "Création du venv dans '$VENV_DIR'..."
    python3 -m venv "$VENV_DIR"
    ok "Venv créé dans ./$VENV_DIR"
fi

# --- 5. Activer le venv ---
log "Activation de ./$VENV_DIR ..."
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
ok "Python actif : $(which python3)"

# --- 6. Mettre à jour pip dans le venv ---
log "Mise à jour de pip..."
python3 -m pip install --upgrade pip setuptools wheel 2>&1 | tail -1
ok "pip à jour"

# --- 7. Installer les dépendances ---
log "Installation des dépendances (requirements.txt)..."
if [ -f "requirements.txt" ]; then
    python3 -m pip install -r requirements.txt
    ok "Dépendances installées via requirements.txt"
else
    warn "requirements.txt introuvable, installation manuelle..."
    python3 -m pip install requests beautifulsoup4 lxml urllib3 certifi pymongo dnspython
    ok "Dépendances installées manuellement"
fi

# --- 8. Vérification des imports ---
log "Vérification des imports..."
python3 -c "
import requests
import bs4
import sqlite3
import socket
import gzip, bz2, lzma
import zipfile, tarfile
import ssl
import subprocess
print('  requests:', requests.__version__)
print('  bs4:', bs4.__version__)
print('  sqlite3: OK')
print('  socket: OK')
print('  compression: OK')
print('  ssl: OK')
print('  subprocess: OK')
try:
    import pymongo
    print('  pymongo:', pymongo.__version__)
except ImportError:
    print('  pymongo: MANQUANT (requis pour MongoDB)')
try:
    import dns.resolver
    print('  dnspython: OK')
except ImportError:
    print('  dnspython: MANQUANT (requis pour subdomain enum)')
" && ok "Tous les imports critiques fonctionnent"

# --- 9. Créer les dossiers de sortie ---
log "Création des dossiers de sortie..."
mkdir -p crawled_sites
ok "Dossier 'crawled_sites/' créé"

# --- 10. Outils système optionnels ---
log "Vérification des outils système optionnels..."

# git-dumper (pour dump .git/ exposé)
if ! command -v git-dumper &> /dev/null; then
    warn "git-dumper non installé (optionnel pour .git/ dump)"
    read -p "  Installer git-dumper ? (o/n) : " install_gd
    if [[ "$install_gd" =~ ^[oOyY] ]]; then
        python3 -m pip install git-dumper 2>&1 | tail -1 && ok "git-dumper installé"
    fi
else
    ok "git-dumper déjà installé"
fi

# mongosh (fallback MongoDB)
if ! command -v mongosh &> /dev/null && ! command -v mongo &> /dev/null; then
    warn "mongosh/mongo non installé (optionnel, fallback pour MongoDB)"
else
    ok "mongosh/mongo déjà installé"
fi

# --- 11. Détecter le fichier crawler ---
CRAWLER_FILE=""
for f in crawler.py jathniel_crawler.py jathniel_crawler_v5.py \
         JATHNIEL-WEB-CRAWLER-PRO.py; do
    if [ -f "$f" ]; then
        CRAWLER_FILE="$f"
        break
    fi
done

if [ -n "$CRAWLER_FILE" ]; then
    ok "Fichier crawler détecté : $CRAWLER_FILE"
else
    warn "Aucun fichier crawler détecté"
    warn "→ Place ton fichier .py dans ce dossier"
fi

# --- 12. Résumé ---
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✓ INSTALLATION TERMINÉE${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Prochaines étapes :${NC}"
echo ""
echo -e "  1. Activer le venv :"
echo -e "     ${CYAN}source $VENV_DIR/bin/activate${NC}"
echo ""
echo -e "  2. Lancer le crawler :"
if [ -n "$CRAWLER_FILE" ]; then
    echo -e "     ${CYAN}python3 $CRAWLER_FILE${NC}"
else
    echo -e "     ${CYAN}python3 <ton_fichier>.py${NC}"
fi
echo ""
echo -e "  3. Menu recommandé :"
echo -e "     ${CYAN}→ Option 3 : RECON COMPLET (tous les modules)${NC}"
echo ""
echo -e "  ${YELLOW}⚠️  Rappel légal :${NC}"
echo -e "     Usage éducatif / CTF / pentest AUTORISÉ uniquement."
echo -e "     Ne JAMAIS scanner un site sans autorisation écrite."
echo ""
echo -e "${G lREEN}════════════════════════════════════════════════════════════${NC}"
echo ""