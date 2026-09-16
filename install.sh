#!/usr/bin/env bash
# ============================================
# JATHNIEL-WEB-CRAWLER-PRO v5.1
# Script d'installation automatique
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
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[X]${NC} $1"; }

# --- Banniere (ASCII pur, compatible partout) ---
echo ""
cat << "EOF"

     _   _   _  _____ _   _ _   _ ___ _____ _
    | | | | | ||_   _| | | | \ | |_ _| ____| |
 _  | | | | | |  | | | |_| |  \| || ||  _| | |
| |_| | |_| |   | | |  _  | |\  || || |___| |___
 \___/ \___/    |_| |_| |_|_| \_|___|_____|_____|

    WEB CRAWLER + DB EXTRACTOR v5.1
    Usage educatif / CTF / pentest autorise uniquement

EOF
echo ""

# --- 1. Verifier Python ---
log "Verification de Python..."
if ! command -v python3 &> /dev/null; then
    err "Python3 n'est pas installe."
    log "Installation de Python3..."
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv
else
    PY_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    ok "Python3 detecte : $PY_VERSION"
fi

# --- 2. Verifier pip ---
log "Verification de pip..."
if ! python3 -m pip --version &> /dev/null; then
    warn "pip manquant, installation..."
    sudo apt update
    sudo apt install -y python3-pip
else
    ok "pip disponible"
fi

# --- 3. Verifier venv ---
log "Verification de venv..."
if ! python3 -c "import venv" &> /dev/null; then
    warn "venv manquant, installation..."
    sudo apt install -y python3-venv
else
    ok "venv disponible"
fi

# --- 4. Detecter ou creer le venv ---
if [ -d ".venv" ]; then
    VENV_DIR=".venv"
    warn "Dossier '.venv' detecte, reutilisation..."
elif [ -d "venv" ]; then
    VENV_DIR="venv"
    warn "Dossier 'venv' detecte, reutilisation..."
else
    VENV_DIR=".venv"
    log "Creation du venv dans '$VENV_DIR'..."
    python3 -m venv "$VENV_DIR"
    ok "Venv cree dans ./$VENV_DIR"
fi

# --- 5. Activer le venv ---
log "Activation de ./$VENV_DIR ..."
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
ok "Python actif : $(which python3)"

# --- 6. Mettre a jour pip ---
log "Mise a jour de pip..."
python3 -m pip install --upgrade pip setuptools wheel 2>&1 | tail -1
ok "pip a jour"

# --- 7. Installer les dependances ---
log "Installation des dependances..."
if [ -f "requirements.txt" ]; then
    python3 -m pip install -r requirements.txt
    ok "Dependances installees via requirements.txt"
else
    warn "requirements.txt introuvable, installation manuelle..."
    python3 -m pip install requests beautifulsoup4 lxml urllib3 certifi pymongo dnspython
    ok "Dependances installees manuellement"
fi

# --- 8. Verification des imports ---
log "Verification des imports..."
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
try:
    import pymongo
    print('  pymongo:', pymongo.__version__)
except ImportError:
    print('  pymongo: MANQUANT')
try:
    import dns.resolver
    print('  dnspython: OK')
except ImportError:
    print('  dnspython: MANQUANT')
" && ok "Imports critiques OK"

# --- 9. Creer les dossiers de sortie ---
log "Creation des dossiers de sortie..."
mkdir -p crawled_sites
ok "Dossier 'crawled_sites/' cree"

# --- 10. Detection du fichier crawler ---
CRAWLER_FILE=""
for f in crawler.py jathniel_crawler.py jathniel_crawler_v5.py \
         JATHNIEL-WEB-CRAWLER-PRO.py; do
    if [ -f "$f" ]; then
        CRAWLER_FILE="$f"
        break
    fi
done

if [ -n "$CRAWLER_FILE" ]; then
    ok "Fichier crawler detecte : $CRAWLER_FILE"
else
    warn "Aucun fichier crawler detecte"
fi

# --- 11. Resume ---
echo ""
echo -e "${GREEN}========================================================${NC}"
echo -e "${GREEN}  INSTALLATION TERMINEE${NC}"
echo -e "${GREEN}========================================================${NC}"
echo ""
echo -e "  ${BOLD}Prochaines etapes :${NC}"
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
echo -e "  3. Menu recommande :"
echo -e "     ${CYAN}Option 3 : RECON COMPLET${NC}"
echo ""
echo -e "  ${YELLOW}Rappel legal :${NC}"
echo -e "     Usage educatif / CTF / pentest AUTORISE uniquement."
echo -e "     Ne JAMAIS scanner un site sans autorisation ecrite."
echo ""
echo -e "${GREEN}========================================================${NC}"
echo ""