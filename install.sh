#!/usr/bin/env bash
# ============================================
# JATHNIEL-WEB-CRAWLER-PRO v4.2
# Script d'installation automatique
# Ubuntu / Debian / Kali / WSL
# ============================================

set -e  # Arrêt en cas d'erreur

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
║              WEB CRAWLER PRO v4.2 — Installation                             ║
║         🛡️  CTF / Labo - Usage autorisé uniquement                           ║
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

# --- 4. Créer le venv ---
log "Création de l'environnement virtuel..."
if [ -d "venv" ]; then
    warn "Le dossier 'venv' existe déjà, réutilisation..."
else
    python3 -m venv venv
    ok "Environnement virtuel créé dans ./venv"
fi

# --- 5. Activer le venv ---
log "Activation du venv..."
# shellcheck disable=SC1091
source venv/bin/activate
ok "venv activé ($(which python3))"

# --- 6. Mettre à jour pip dans le venv ---
log "Mise à jour de pip..."
pip install --upgrade pip setuptools wheel 2>&1 | tail -1
ok "pip à jour"

# --- 7. Installer les dépendances ---
log "Installation des dépendances (requirements.txt)..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    ok "Dépendances installées"
else
    warn "requirements.txt introuvable, installation manuelle..."
    pip install requests beautifulsoup4 lxml urllib3 certifi
    ok "Dépendances installées (manuelles)"
fi

# --- 8. Vérifier l'import ---
log "Vérification des imports..."
python3 -c "
import requests
import bs4
import sqlite3
import gzip, bz2, lzma
import zipfile, tarfile
print('  requests:', requests.__version__)
print('  bs4:', bs4.__version__)
print('  sqlite3: OK')
print('  compression: OK')
" && ok "Tous les imports fonctionnent"

# --- 9. Vérifier que le crawler est présent ---
log "Vérification du crawler..."
if [ -f "crawler.py" ]; then
    ok "crawler.py trouvé"
elif [ -f "JATHNIEL-WEB-CRAWLER-PRO.py" ]; then
    ok "JATHNIEL-WEB-CRAWLER-PRO.py trouvé"
else
    warn "Aucun fichier crawler détecté dans le dossier courant"
    warn "Assure-toi d'avoir placé crawler.py ici"
fi

# --- 10. Créer le dossier de sortie ---
log "Création des dossiers de sortie..."
mkdir -p crawled_sites
ok "Dossier 'crawled_sites/' créé"

# --- 11. Résumé ---
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✓ INSTALLATION TERMINÉE${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Prochaines étapes :${NC}"
echo ""
echo -e "  1. Activer le venv :"
echo -e "     ${CYAN}source venv/bin/activate${NC}"
echo ""
echo -e "  2. Lancer le crawler :"
echo -e "     ${CYAN}python3 crawler.py${NC}"
echo ""
echo -e "  3. Pour quitter le venv :"
echo -e "     ${CYAN}deactivate${NC}"
echo ""
echo -e "  ${YELLOW}⚠️  Rappel légal :${NC}"
echo -e "     Usage éducatif / CTF / pentest AUTORISÉ uniquement."
echo -e "     Ne jamais cibler un site sans autorisation écrite."
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""