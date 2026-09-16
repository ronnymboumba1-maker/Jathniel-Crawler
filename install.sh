#!/usr/bin/env bash
# install.sh - Installation de JATHNIEL-WEB-CRAWLER-PRO pour WSL/Ubuntu
set -e

echo "🔧 Installation de JATHNIEL-WEB-CRAWLER-PRO v4.1"
echo "================================================"

# Dépendances système
echo "📦 Installation des paquets système..."
sudo apt update
sudo apt install -y python3 python3-pip python3-venv

# Environnement virtuel
if [ ! -d ".venv" ]; then
    echo "🐍 Creation de l'environnement virtuel..."
    python3 -m venv .venv
fi

# Activation + pip
echo "📥 Installation des dependances Python..."
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Rendre le script exécutable
chmod +x jathniel_crawler.py

echo ""
echo "✅ Installation terminee!"
echo ""
echo "Pour lancer le crawler:"
echo "  source .venv/bin/activate"
echo "  python jathniel_crawler.py"
echo ""
