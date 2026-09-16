#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
JATHNIEL-WEB-CRAWLER-PRO v4.3
Crawler web professionnel avec détection et extraction de bases de données exposées

Pour Ubuntu/WSL - Usage éducatif et tests de sécurité autorisés uniquement
(cadre CTF, labo personnel, DVWA, WebGoat, etc.)

CHANGELOG v4.3 (FIX MAJEUR téléchargements):
[FIX] visited_assets vs visited_sensitive : plus de conflit entre assets et sensibles
[FIX] Compteur active_downloads : le crawl attend la fin des DL avant de terminer
[FIX] extract_assets epure : ne telecharge plus les .json/.xml/.txt (evite le blocage)
[FIX] search_sensitive_in_page : logs detailles pour chaque candidat
[FIX] download_sensitive_file : logs etapes + skip des pages HTML 404 custom
[ADD] Progress des telechargements en cours
[ADD] Detection automatique des faux positifs HTML (404 custom)
"""

import os
import sys
import time
import json
import re
import random
import hashlib
import threading
import queue
import socket
import urllib3
import shutil
import sqlite3
import gzip
import bz2
import lzma
import zipfile
import tarfile
import csv
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from typing import Dict, List, Tuple, Optional, Any
from collections import deque, defaultdict
from io import BytesIO

import requests
from bs4 import BeautifulSoup
import mimetypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class JATHNIELCrawlerPro:
    """Crawler web professionnel avec extraction de bases de donnees exposees."""

    def __init__(self):
        # Configuration
        self.config = {
            'max_depth': 3,
            'max_pages': 500,
            'max_files': 100,
            'threads': 10,
            'timeout': 30,
            'delay': 0.5,
            'user_agent': 'JATHNIEL-Crawler-Pro/4.3 (Educational; CTF/Lab)',
            'output_dir': './crawled_sites',
            'download_sensitive': True,
            'download_assets': True,
            'respect_robots': True,
            'javascript': False,
            'follow_redirects': True,
            'verify_ssl': False,
            'analyze_db': True,
            'auto_extract_zip': True,
        }

        # Etat
        self.target_url = ""
        self.target_domain = ""
        self.visited_urls = set()
        self.visited_assets = set()           # NOUVEAU : assets
        self.visited_sensitive = set()        # NOUVEAU : fichiers sensibles
        self._crawled_urls = set()
        self._seed_urls = []
        self.queue = deque()
        self.results = self._empty_results()

        # Compteur de telechargements actifs
        self.active_downloads = [0]           # NOUVEAU
        self.download_lock = threading.Lock() # NOUVEAU

        self.lock = threading.Lock()
        self.scanning = False
        self.pause = False

        # Log d'erreurs
        os.makedirs(self.config['output_dir'], exist_ok=True)
        self.error_log_path = os.path.join(self.config['output_dir'], 'errors.log')

        # ==================== LISTES SENSIBLES ====================

        self.sensitive_extensions = [
            '.env', '.env.local', '.env.prod', '.env.backup',
            '.ini', '.conf', '.config', '.cfg',
            '.yml', '.yaml', '.toml',
            '.sql', '.db', '.sqlite', '.sqlite3', '.db3', '.s3db',
            '.dump', '.bson', '.rdb', '.pgdump', '.archive',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.xz',
            '.pem', '.crt', '.cer', '.key', '.p12', '.pfx', '.ppk',
            '.log',
            '.bin', '.dat', '.raw', '.img', '.iso',
        ]

        self.sensitive_filenames = [
            'wp-config.php', 'config.php', 'configuration.php',
            'settings.py', 'settings.json', 'appsettings.json',
            'web.config', 'app.config', 'database.yml', 'db.php',
            'config.inc.php', 'php.ini', 'nginx.conf', 'httpd.conf',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'humans.txt', 'security.txt', 'clientaccesspolicy.xml',
            'passwd', 'shadow', 'sudoers',
            'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
            'authorized_keys', 'known_hosts',
            '.bash_history', '.bashrc', '.profile', '.gitconfig',
            '.gitignore', '.DS_Store', 'Thumbs.db', '.htaccess', '.htpasswd',
            'composer.json', 'composer.lock', 'package.json',
            'package-lock.json', 'yarn.lock', 'requirements.txt',
            'Gemfile', 'Gemfile.lock', 'pom.xml', 'build.gradle',
            'Dockerfile', 'docker-compose.yml', 'Makefile', 'Vagrantfile',
            '.travis.yml', '.gitlab-ci.yml', 'Jenkinsfile',
            'README.md', 'README.txt', 'INSTALL', 'CHANGELOG.md',
            'LICENSE', 'COPYING',
        ]

        self.database_filenames = [
            'database.db', 'data.db', 'app.db', 'main.db', 'site.db',
            'users.db', 'test.db', 'prod.db', 'dev.db',
            'database.sqlite', 'data.sqlite', 'app.sqlite',
            'database.sqlite3', 'data.sqlite3', 'app.sqlite3',
            'dump.sql', 'database.sql', 'backup.sql', 'db.sql',
            'mysql.sql', 'data.sql', 'dump.sqlite',
            'pg_dump.sql', 'postgres.sql', 'database.pgdump',
            'dump.rdb', 'redis.rdb', 'mongodb.archive',
        ]

        self.sensitive_directories = [
            '/admin/', '/administrator/', '/backup/', '/backups/',
            '/private/', '/secret/', '/config/', '/configs/',
            '/db/', '/database/', '/sql/', '/dumps/', '/dump/',
            '/.git/', '/.svn/', '/.hg/', '/.env/',
            '/logs/', '/log/', '/tmp/', '/temp/',
            '/api/', '/v1/', '/v2/', '/graphql',
            '/swagger/', '/api-docs/', '/phpmyadmin/',
            '/adminer/', '/shell/', '/test/', '/data/',
            '/export/', '/mysql/', '/sqlite/',
        ]

        self.asset_extensions = [
            '.css', '.js',
            '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wav',
            '.woff', '.woff2', '.ttf', '.eot', '.otf'
        ]

        self.admin_patterns = [
            'admin', 'administrator', 'login', 'signin', 'panel', 'dashboard',
            'backoffice', 'backend', 'cpanel', 'webmail', 'manager',
            'moderator', 'staff', 'sysadmin', 'root', 'control'
        ]

        self.tech_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-json', 'wp-admin'],
            'Drupal': ['drupal', 'sites/all', 'drupal.js'],
            'Joomla': ['joomla', 'com_content', 'modules/mod_'],
            'Laravel': ['laravel', 'csrf-token', '_token'],
            'Django': ['django', 'csrfmiddlewaretoken', 'admin/'],
            'Rails': ['rails', 'authenticity_token', 'application.js'],
            'Express': ['express', 'x-powered-by: express'],
            'Flask': ['flask', 'x-powered-by: flask'],
            'React': ['react', 'react-dom', 'react.min.js'],
            'Vue': ['vue.js', 'vue.min.js', 'v-bind'],
            'Angular': ['angular', 'ng-app', 'ng-controller'],
            'jQuery': ['jquery', 'jquery.min.js', 'jquery-'],
            'Bootstrap': ['bootstrap', 'navbar', 'bootstrap.min.css'],
            'FontAwesome': ['font-awesome', 'fa-', 'fa-solid'],
            'GoogleAnalytics': ['ga.js', 'gtag.js', 'analytics.js'],
            'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
            'AmazonAWS': ['aws.amazon', 'x-amz', 'amazonaws']
        }

        self.magic_signatures = {
            b'SQLite format 3\x00': 'sqlite',
            b'PK\x03\x04': 'zip',
            b'PK\x05\x06': 'zip_empty',
            b'\x1f\x8b': 'gzip',
            b'BZh': 'bzip2',
            b'\xfd7zXZ\x00': 'xz',
            b'\x89PNG\r\n\x1a\n': 'png',
            b'\xff\xd8\xff': 'jpeg',
            b'GIF87a': 'gif',
            b'GIF89a': 'gif',
            b'%PDF-': 'pdf',
            b'\x7fELF': 'elf',
            b'MZ': 'exe',
            b'Rar!\x1a\x07': 'rar',
            b'7z\xbc\xaf\x27\x1c': '7z',
            b'REDIS': 'redis_dump',
            b'BSON': 'bson',
            b'-- MySQL dump': 'mysql_dump',
            b'-- PostgreSQL database dump': 'postgres_dump',
            b'-- SQLite': 'sqlite_dump',
        }

        self.clear_screen()
        self.show_banner()

    # ==================== UTILITAIRES ====================

    def _empty_results(self):
        return {
            'pages': [],
            'assets': [],
            'sensitive_files': [],
            'databases': [],
            'db_contents': {},
            'forms': [],
            'links': [],
            'emails': [],
            'technologies': [],
            'admin_pages': [],
            'comments': [],
            'vulnerabilities': [],
            'statistics': {
                'total_pages': 0,
                'total_assets': 0,
                'total_sensitive': 0,
                'total_databases': 0,
                'total_size': 0,
                'start_time': None,
                'end_time': None,
                'duration': 0
            }
        }

    def reset_state(self):
        self.target_url = ""
        self.target_domain = ""
        self.visited_urls = set()
        self.visited_assets = set()
        self.visited_sensitive = set()
        self._crawled_urls = set()
        self._seed_urls = []
        self.queue = deque()
        self.results = self._empty_results()
        self.active_downloads = [0]

    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def colorize(self, text, color='white', bold=False):
        colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'magenta': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'bold': '\033[1m',
            'end': '\033[0m'
        }
        bold_text = colors['bold'] if bold else ''
        return f"{colors.get(color, '')}{bold_text}{text}{colors['end']}"

    def log_error(self, message):
        try:
            with self.lock:
                with open(self.error_log_path, 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now().isoformat()}] {message}\n")
        except Exception:
            pass

    def format_size(self, bytes):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} TB"

    def show_banner(self):
        banner = f"""
{self.colorize('╔══════════════════════════════════════════════════════════════════════════════╗', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('██╗ █████╗ ████████╗██╗  ██╗███╗   ██╗██╗███████╗██╗     ██╗   ██╗', 'red')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('██║██╔══██╗╚══██╔══╝██║  ██║████╗  ██║██║██╔════╝██║     ██║   ██║', 'red')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('██║███████║   ██║   ███████║██╔██╗ ██║██║█████╗  ██║     ██║   ██║', 'red')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('██║██╔══██║   ██║   ██╔══██║██║╚██╗██║██║██╔══╝  ██║     ██║   ██║', 'red')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('██║██║  ██║   ██║   ██║  ██║██║ ╚████║██║███████╗███████╗╚██████╔╝', 'red')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚══════╝╚══════╝ ╚═════╝ ', 'red')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('              WEB CRAWLER PRO v4.3 - JATHNIEL EDITION', 'yellow')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('     🕷️  Crawler + Extraction de bases de donnees exposees  🕷️', 'green')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('           🛡️  CTF / Labo - Usage autorise uniquement  🛡️', 'magenta')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('                              ★  JATHNIEL  ★                                  ', 'yellow')}  {self.colorize('║', 'cyan')}
{self.colorize('╚══════════════════════════════════════════════════════════════════════════════╝', 'cyan')}
        """
        print(banner)

    def show_menu(self):
        status = self.colorize('● EN COURS', 'green') if self.scanning else self.colorize('○ ARRETE', 'red')
        target_display = self.target_url if self.target_url else self.colorize('Aucune', 'red')

        menu = f"""
{self.colorize('┌────────────────────────────────────────────────────────────────────────────────────┐', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('MENU PRINCIPAL - WEB CRAWLER PRO v4.3', 'bold')}                                          {self.colorize('│', 'cyan')}
{self.colorize('├────────────────────────────────────────────────────────────────────────────────────┤', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('1.', 'yellow')}  {self.colorize('Lancer un crawl complet', 'white')}                                                 {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('2.', 'yellow')}  {self.colorize('Crawl + extraction de bases de donnees', 'white')}                              {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('3.', 'yellow')}  {self.colorize('Changer la cible actuelle', 'white')}                                              {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('4.', 'yellow')}  {self.colorize('Telecharger un fichier specifique', 'white')}                                       {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('5.', 'yellow')}  {self.colorize('Voir les resultats du crawl', 'white')}                                             {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('6.', 'yellow')}  {self.colorize('Voir les fichiers sensibles trouves', 'white')}                                     {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('7.', 'yellow')}  {self.colorize('Voir les bases de donnees extraites', 'white')}                                   {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('8.', 'yellow')}  {self.colorize('Exporter les resultats (JSON/HTML/CSV)', 'white')}                                  {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('9.', 'yellow')}  {self.colorize('Configuration', 'white')}                                                          {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('10.', 'yellow')} {self.colorize('Statistiques du crawl', 'white')}                                                   {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('11.', 'yellow')} {self.colorize('Aide / Documentation', 'white')}                                                    {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('0.', 'yellow')}  {self.colorize('Quitter', 'white')}                                                               {self.colorize('│', 'cyan')}
{self.colorize('├────────────────────────────────────────────────────────────────────────────────────┤', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('📌 Cible:', 'bold')} {target_display[:70]:<70} {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('📄 Pages:', 'bold')} {self.results['statistics']['total_pages']}  {self.colorize('📁 Sensibles:', 'bold')} {self.results['statistics']['total_sensitive']}  {self.colorize('🗄️  DB:', 'bold')} {self.results['statistics']['total_databases']}  {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('📊 Statut:', 'bold')} {status}  {self.colorize('│', 'cyan')}
{self.colorize('└────────────────────────────────────────────────────────────────────────────────────┘', 'cyan')}
        """
        print(menu)

    def get_user_input(self, prompt, default=""):
        if default:
            prompt = f"{prompt} [{default}]: "
        else:
            prompt = f"{prompt}: "
        return input(self.colorize(prompt, 'yellow')).strip() or default

    def get_yes_no(self, prompt):
        while True:
            response = input(self.colorize(f"{prompt} (o/n): ", 'yellow')).lower()
            if response in ['o', 'oui', 'y', 'yes']:
                return True
            elif response in ['n', 'non', 'no']:
                return False
            else:
                print(self.colorize("❌ Repondez par 'o' ou 'n'", 'red'))

    # ==================== AMORCAGE ====================

    def seed_from_robots_and_sitemap(self, base_url):
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        seeds = []

        if self.config['respect_robots']:
            try:
                r = requests.get(f"{base}/robots.txt",
                                 headers={'User-Agent': self.config['user_agent']},
                                 timeout=10, verify=self.config['verify_ssl'])
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        if line.lower().startswith('sitemap:'):
                            sitemap_url = line.split(':', 1)[1].strip()
                            seeds.append(sitemap_url)
            except Exception as e:
                self.log_error(f"robots.txt: {e}")

        seeds.append(f"{base}/sitemap.xml")

        self._seed_urls = []
        seen = set()
        for seed in seeds:
            if seed in seen:
                continue
            seen.add(seed)
            try:
                r = requests.get(seed,
                                 headers={'User-Agent': self.config['user_agent']},
                                 timeout=10, verify=self.config['verify_ssl'])
                if r.status_code != 200:
                    continue
                urls = re.findall(r'<loc>\s*([^<\s]+)\s*</loc>', r.text, re.IGNORECASE)
                for u in urls[:200]:
                    if self.target_domain in urlparse(u).netloc:
                        self._seed_urls.append(u)
                if urls:
                    print(f"  🌱 {len(urls)} URLs amorcees depuis {seed}")
            except Exception as e:
                self.log_error(f"seed {seed}: {e}")

    # ==================== MOTEUR DE CRAWL ====================

    def crawl_complete(self, url):
        """Crawl complet avec threading propre."""
        self.target_url = url
        self.target_domain = urlparse(url).netloc
        self.scanning = True

        # Reset d'etat
        self.visited_urls = set()
        self.visited_assets = set()
        self.visited_sensitive = set()
        self._crawled_urls = set()
        self._seed_urls = []
        self.queue = deque()
        self.results = self._empty_results()
        self.active_downloads = [0]

        # Dossiers de sortie
        site_dir = f"{self.config['output_dir']}/{self.target_domain}"
        for sub in ['pages', 'assets', 'sensitive', 'databases', 'reports']:
            os.makedirs(f"{site_dir}/{sub}", exist_ok=True)

        print(f"\n{self.colorize('🕷️ Debut du crawl de:', 'cyan')} {url}")
        print(self.colorize("=" * 80, 'blue'))
        print(f"📁 Dossier de sortie: {site_dir}")
        print(f"📊 Max pages: {self.config['max_pages']}  |  Max depth: {self.config['max_depth']}")
        print(f"🧵 Threads: {self.config['threads']}  |  Delay: {self.config['delay']}s")
        print(f"🔍 Fichiers sensibles: {self.colorize('OUI', 'green') if self.config['download_sensitive'] else self.colorize('NON', 'red')}")
        print(f"🗄️  Analyse DB: {self.colorize('OUI', 'green') if self.config['analyze_db'] else self.colorize('NON', 'red')}")
        print(self.colorize("=" * 80, 'blue'))

        self.results['statistics']['start_time'] = datetime.now()

        # Amorcage
        print(self.colorize("\n🌱 Amorcage via robots.txt / sitemap.xml...", 'yellow'))
        try:
            self.seed_from_robots_and_sitemap(url)
        except Exception as e:
            self.log_error(f"seed_from_robots: {e}")

        # Queue thread-safe
        page_queue = queue.Queue()
        page_queue.put((url, 0))
        for seed_url in self._seed_urls:
            page_queue.put((seed_url, 1))

        # Semaphore + flag
        active_workers = [0]
        active_lock = threading.Lock()
        stop_flag = threading.Event()

        def worker():
            while not stop_flag.is_set():
                try:
                    current_url, depth = page_queue.get(timeout=5)
                except queue.Empty:
                    with active_lock:
                        if active_workers[0] > 0 or not page_queue.empty():
                            continue
                    return
                try:
                    with active_lock:
                        active_workers[0] += 1
                    try:
                        if current_url in self._crawled_urls:
                            continue
                        with self.lock:
                            if len(self._crawled_urls) >= self.config['max_pages']:
                                stop_flag.set()
                                return
                            self._crawled_urls.add(current_url)
                            self.visited_urls.add(current_url)
                        self.crawl_page(current_url, depth, site_dir, page_queue)
                    finally:
                        with active_lock:
                            active_workers[0] -= 1
                finally:
                    page_queue.task_done()

        threads = []
        for _ in range(self.config['threads']):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        # Attente : 3 confirmations successives d'inactivite
        # MAIS on attend aussi que tous les telechargements soient termines
        idle_count = 0
        while idle_count < 3:
            time.sleep(1.0)
            with active_lock:
                idle_crawl = (page_queue.empty() and active_workers[0] == 0)
            with self.download_lock:
                idle_dl = (self.active_downloads[0] == 0)

            idle = idle_crawl and idle_dl
            if idle:
                idle_count += 1
            else:
                idle_count = 0

            # Log de progression si des DL sont en cours
            if not idle:
                with self.download_lock:
                    dl_count = self.active_downloads[0]
                if dl_count > 0:
                    print(f"  ⏳ {dl_count} téléchargement(s) en cours...")

        stop_flag.set()
        for t in threads:
            t.join(timeout=10)

        # Analyses complementaires
        print(self.colorize("\n🔍 Analyse complementaire...", 'yellow'))
        try:
            self.detect_technologies()
        except Exception as e:
            self.log_error(f"detect_technologies: {e}")
        try:
            self.find_admin_pages()
        except Exception as e:
            self.log_error(f"find_admin_pages: {e}")
        try:
            self.extract_emails()
        except Exception as e:
            self.log_error(f"extract_emails: {e}")

        self.results['statistics']['end_time'] = datetime.now()
        self.results['statistics']['duration'] = (
            self.results['statistics']['end_time'] -
            self.results['statistics']['start_time']
        ).total_seconds()

        self.scanning = False

        print(self.colorize("\n✅ Crawl termine!", 'green'))
        print(f"📄 Pages: {self.results['statistics']['total_pages']}")
        print(f"📁 Fichiers sensibles: {self.results['statistics']['total_sensitive']}")
        print(f"🗄️  Bases de donnees: {self.results['statistics']['total_databases']}")
        print(f"📦 Assets: {self.results['statistics']['total_assets']}")
        print(f"📊 Duree: {self.results['statistics']['duration']:.2f} secondes")
        if os.path.exists(self.error_log_path):
            try:
                with open(self.error_log_path, 'r') as f:
                    n_errors = len(f.readlines())
                if n_errors > 0:
                    print(f"📝 Log d'erreurs: {self.error_log_path} ({n_errors} entrees)")
            except Exception:
                pass

    def crawl_page(self, url, depth, site_dir, page_queue):
        """Crawl une page individuelle."""
        try:
            response = requests.get(
                url,
                headers={'User-Agent': self.config['user_agent']},
                timeout=self.config['timeout'],
                verify=self.config['verify_ssl'],
                allow_redirects=self.config['follow_redirects']
            )

            if response.status_code != 200:
                return

            html = response.text
            page_filename = self.save_page(url, html, site_dir)

            page_data = {
                'url': url,
                'depth': depth,
                'status': response.status_code,
                'size': len(response.content),
                'filename': page_filename,
                'html': html,
                'headers': dict(response.headers),
            }

            with self.lock:
                self.results['pages'].append(page_data)
                self.results['statistics']['total_pages'] += 1
                self.results['statistics']['total_size'] += len(response.content)

            print(f"  📄 [{depth}] {url} ({len(response.content)} o)")

            # Liens
            if depth < self.config['max_depth']:
                links = self.extract_links(html, url)
                for link in links:
                    with self.lock:
                        if link not in self._crawled_urls:
                            page_queue.put((link, depth + 1))

            # Fichiers sensibles EN PREMIER (avant les assets)
            if self.config['download_sensitive']:
                self.search_sensitive_in_page(html, url, site_dir)

            # Assets APRES (pour eviter les conflits)
            if self.config['download_assets']:
                self.extract_assets(html, url, site_dir)

            # Formulaires
            forms = self.extract_forms(html, url)
            with self.lock:
                self.results['forms'].extend(forms)

            # Commentaires
            comments = self.extract_comments(html, url)
            with self.lock:
                self.results['comments'].extend(comments)

            # Delai aleatoire
            time.sleep(random.uniform(self.config['delay'], self.config['delay'] * 2))

        except Exception as e:
            self.log_error(f"crawl_page({url}): {e}")
            print(f"  {self.colorize('⚠️', 'yellow')} Erreur sur {url}: {str(e)[:60]}")

    def extract_links(self, html, base_url):
        links = set()
        try:
            soup = BeautifulSoup(html, 'html.parser')
        except Exception:
            return links

        for a in soup.find_all('a', href=True):
            href = a['href']
            if href and not href.startswith('#') and not href.startswith('javascript:'):
                absolute_url = urljoin(base_url, href)
                if self.target_domain in urlparse(absolute_url).netloc:
                    links.add(absolute_url)

        for link in soup.find_all('link', href=True):
            href = link['href']
            if href:
                absolute_url = urljoin(base_url, href)
                if self.target_domain in urlparse(absolute_url).netloc:
                    links.add(absolute_url)

        return links

    def extract_assets(self, html, base_url, site_dir):
        """Extrait UNIQUEMENT les vrais assets (css, js, images, fonts, media)."""
        try:
            soup = BeautifulSoup(html, 'html.parser')
        except Exception:
            return

        assets_found = []

        # CSS uniquement
        for link in soup.find_all('link', rel='stylesheet', href=True):
            href = link['href']
            if href and href.endswith('.css'):
                assets_found.append(urljoin(base_url, href))

        # JS uniquement
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src and src.endswith('.js'):
                assets_found.append(urljoin(base_url, src))

        # Images
        for img in soup.find_all('img', src=True):
            src = img['src']
            if src and any(src.lower().endswith(ext) for ext in
                           ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.ico']):
                assets_found.append(urljoin(base_url, src))

        for asset_url in assets_found:
            self.download_asset(asset_url, site_dir)

    def download_asset(self, url, site_dir):
        """Telecharge un asset en streaming (robuste)."""
        with self.lock:
            if url in self.visited_assets:
                return
            self.visited_assets.add(url)

        tmp_path = None
        try:
            response = requests.get(
                url,
                headers={'User-Agent': self.config['user_agent']},
                timeout=self.config['timeout'],
                verify=self.config['verify_ssl'],
                stream=True,
                allow_redirects=True,
            )

            if response.status_code != 200:
                response.close()
                return

            filename = urlparse(url).path.split('/')[-1] or hashlib.md5(url.encode()).hexdigest()
            ext = os.path.splitext(filename)[1]
            if not ext:
                content_type = response.headers.get('content-type', '')
                ext = mimetypes.guess_extension(content_type.split(';')[0].strip()) or '.bin'
                filename += ext

            filename = re.sub(r'[<>:"/\\|?*]', '_', filename)[:100]
            filepath = f"{site_dir}/assets/{filename}"

            max_size = 20 * 1024 * 1024
            size = 0
            tmp_path = filepath + '.tmp'

            with open(tmp_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > max_size:
                        f.close()
                        response.close()
                        try:
                            os.remove(tmp_path)
                        except Exception:
                            pass
                        self.log_error(f"asset trop gros: {url}")
                        return
                    f.write(chunk)

            response.close()

            if os.path.exists(filepath):
                base, ext = os.path.splitext(filename)
                filename = f"{base}_{hashlib.md5(url.encode()).hexdigest()[:6]}{ext}"
                filepath = f"{site_dir}/assets/{filename}"

            shutil.move(tmp_path, filepath)
            tmp_path = None

            with self.lock:
                self.results['assets'].append({
                    'url': url, 'filename': filename, 'size': size
                })
                self.results['statistics']['total_assets'] += 1

            print(f"    📦 Asset: {filename} ({size} o)")

        except Exception as e:
            self.log_error(f"download_asset({url}): {e}")
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    def save_page(self, url, html, site_dir):
        filename = urlparse(url).path.replace('/', '_') or 'index'
        if not filename.endswith('.html'):
            filename += '.html'
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)[:120]

        filepath = f"{site_dir}/pages/{filename}"
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html)
        except Exception as e:
            self.log_error(f"save_page({url}): {e}")
            return 'error.html'

        return filename

    # ==================== DETECTION FICHIERS SENSIBLES ====================

    def search_sensitive_in_page(self, html, url, site_dir):
        """Detecte et telecharge les fichiers sensibles (avec logs detailles)."""
        found_urls = set()
        candidates = []

        # 1. URLs dans les attributs HTML
        urls_in_page = re.findall(
            r'(?:href|src|action|data-url|data-src|data-href)=["\']([^"\']+)["\']',
            html, re.IGNORECASE
        )

        for file_url in urls_in_page:
            file_url_lower = file_url.lower()
            matched_reason = None

            # Extensions sensibles
            for ext in self.sensitive_extensions:
                if (file_url_lower.endswith(ext) or
                    ext + '?' in file_url_lower or
                    ext + '#' in file_url_lower):
                    matched_reason = f"ext {ext}"
                    break

            # Noms sensibles
            if not matched_reason:
                for fname in self.sensitive_filenames:
                    if fname.lower() in file_url_lower:
                        matched_reason = f"file {fname}"
                        break

            # Dossiers sensibles
            if not matched_reason:
                for directory in self.sensitive_directories:
                    if directory.lower() in file_url_lower:
                        matched_reason = f"dir {directory}"
                        break

            if matched_reason:
                absolute_url = urljoin(url, file_url)
                if absolute_url not in found_urls:
                    found_urls.add(absolute_url)
                    candidates.append((absolute_url, matched_reason))

        # 2. Chemins absolus dans le texte brut
        ext_pattern = '|'.join([re.escape(e.lstrip('.')) for e in self.sensitive_extensions])
        paths_ext = re.findall(
            r'(/[a-zA-Z0-9_\-./]+\.(?:' + ext_pattern + r'))',
            html, re.IGNORECASE
        )
        for path in paths_ext:
            absolute_url = urljoin(url, path)
            if absolute_url not in found_urls:
                found_urls.add(absolute_url)
                candidates.append((absolute_url, f"path {path}"))

        # 3. Liens directs DB
        db_link_patterns = [
            r'href=["\']([^"\']*\.(?:sqlite|sqlite3|db|sql|dump|bson|rdb))["\']',
            r'src=["\']([^"\']*\.(?:sqlite|sqlite3|db|sql))["\']',
            r'["\']([^"\']*/(?:db|database|backup|dump|sql)/[^"\']*)["\']',
        ]
        for pattern in db_link_patterns:
            for match in re.findall(pattern, html, re.IGNORECASE):
                absolute_url = urljoin(url, match)
                if absolute_url not in found_urls:
                    found_urls.add(absolute_url)
                    candidates.append((absolute_url, "db link"))

        # 4. Telecharger tous les candidats
        for absolute_url, reason in candidates:
            if urlparse(absolute_url).netloc == self.target_domain:
                self.download_sensitive_file(absolute_url, site_dir, reason=reason)

    def download_sensitive_file(self, url, site_dir, reason=""):
        """Telecharge un fichier sensible (logs detailles)."""
        with self.lock:
            if url in self.visited_sensitive:
                return False
            self.visited_sensitive.add(url)

        # Incrementer le compteur de DL actifs
        with self.download_lock:
            self.active_downloads[0] += 1

        tmp_path = None
        try:
            response = requests.get(
                url,
                headers={'User-Agent': self.config['user_agent']},
                timeout=self.config['timeout'],
                verify=self.config['verify_ssl'],
                stream=True,
                allow_redirects=True,
            )

            if response.status_code != 200:
                response.close()
                return False

            content_type = response.headers.get('content-type', '').lower()
            content_length = int(response.headers.get('content-length', 0) or 0)

            is_db_url = any(url.lower().split('?')[0].endswith(ext) for ext in
                            ['.sql', '.db', '.sqlite', '.sqlite3', '.dump', '.bson', '.rdb'])
            max_size = 50 * 1024 * 1024 if is_db_url else 10 * 1024 * 1024

            if content_length > 0 and content_length > max_size:
                response.close()
                self.log_error(f"trop gros ({content_length}): {url}")
                return False

            filename = urlparse(url).path.split('/')[-1]
            if not filename or filename.endswith('/'):
                filename = 'index_' + hashlib.md5(url.encode()).hexdigest()[:8]
            if '.' not in filename:
                ext = mimetypes.guess_extension(content_type.split(';')[0].strip()) or '.bin'
                filename += ext
            filename = re.sub(r'[<>:"/\\|?*]', '_', filename)[:100]

            tmp_path = os.path.join(site_dir, f".tmp_{hashlib.md5(url.encode()).hexdigest()[:8]}")
            size = 0
            with open(tmp_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > max_size:
                        f.close()
                        response.close()
                        try:
                            os.remove(tmp_path)
                        except Exception:
                            pass
                        self.log_error(f"depasse limite ({size}): {url}")
                        return False
                    f.write(chunk)

            response.close()

            # Identifier par magic bytes
            with open(tmp_path, 'rb') as f:
                head = f.read(8192)

            real_type = self.identify_file_type(head)

            # Detecter les faux positifs : HTML 404 custom
            is_html = b'<html' in head.lower() or b'<!doctype' in head.lower()
            is_404_page = False
            if is_html and size < 10000:
                head_str = head[:3000].decode('utf-8', errors='ignore').lower()
                if any(marker in head_str for marker in
                       ['not found', '404', 'page introuvable', 'does not exist']):
                    is_404_page = True

            if is_404_page:
                self.log_error(f"404 custom ignore: {url}")
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
                tmp_path = None
                return False

            is_db = (real_type in ['sqlite', 'mysql_dump', 'postgres_dump',
                                   'redis_dump', 'bson', 'sqlite_dump', 'sql_dump']) or \
                    any(filename.lower().endswith(ext) for ext in
                        ['.sql', '.db', '.sqlite', '.sqlite3', '.dump', '.bson', '.rdb'])

            dest_dir = f"{site_dir}/databases" if is_db else f"{site_dir}/sensitive"
            os.makedirs(dest_dir, exist_ok=True)
            filepath = os.path.join(dest_dir, filename)

            if os.path.exists(filepath):
                base, ext = os.path.splitext(filename)
                filename = f"{base}_{hashlib.md5(url.encode()).hexdigest()[:6]}{ext}"
                filepath = os.path.join(dest_dir, filename)

            shutil.move(tmp_path, filepath)
            tmp_path = None

            file_info = {
                'url': url,
                'filename': filename,
                'size': size,
                'path': filepath,
                'type': self.classify_sensitive_file(filename),
                'real_type': real_type,
                'content_preview': head[:200].decode('utf-8', errors='ignore')
            }

            with self.lock:
                if is_db:
                    self.results['databases'].append(file_info)
                    self.results['statistics']['total_databases'] += 1
                else:
                    self.results['sensitive_files'].append(file_info)
                    self.results['statistics']['total_sensitive'] += 1

            reason_str = f" ({reason})" if reason else ""
            if is_db:
                print(f"    {self.colorize('🗄️  BASE:', 'magenta')} {filename} ({size} o) [{real_type}]{reason_str}")
            else:
                print(f"    {self.colorize('🔴 SENSIBLE:', 'red')} {filename} ({size} o) [{real_type}]{reason_str}")
            print(f"        📍 {url}")

            if is_db and self.config['analyze_db']:
                try:
                    self.analyze_database(filepath, real_type, filename)
                except Exception as e:
                    self.log_error(f"analyze_database({filename}): {e}")

            return True

        except Exception as e:
            self.log_error(f"download_sensitive_file({url}): {e}")
            print(f"    {self.colorize('⚠️', 'yellow')} Erreur DL {url}: {str(e)[:80]}")
            return False
        finally:
            # Decrementer le compteur TOUJOURS
            with self.download_lock:
                self.active_downloads[0] -= 1
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    def identify_file_type(self, content: bytes) -> str:
        for magic, name in self.magic_signatures.items():
            if content.startswith(magic):
                return name

        preview = content[:5000]
        if b'CREATE TABLE' in preview or b'INSERT INTO' in preview:
            if b'`' in preview or b'ENGINE=' in preview:
                return 'mysql_dump'
            return 'sql_dump'

        return 'unknown'

    def classify_sensitive_file(self, filename):
        fl = filename.lower()
        if any(x in fl for x in ['.sqlite', '.sqlite3', '.db3', '.s3db']):
            return 'SQLite Database'
        elif '.sql' in fl or 'dump' in fl:
            return 'SQL Dump'
        elif '.rdb' in fl:
            return 'Redis Dump'
        elif '.bson' in fl or 'mongo' in fl:
            return 'MongoDB Export'
        elif '.pgdump' in fl:
            return 'PostgreSQL Dump'
        elif 'config' in fl or '.env' in fl or '.ini' in fl:
            return 'Configuration'
        elif 'backup' in fl or '.bak' in fl:
            return 'Backup'
        elif '.log' in fl:
            return 'Log'
        elif '.key' in fl or '.pem' in fl or 'id_rsa' in fl or '.crt' in fl:
            return 'Certificate/Key'
        elif '.git' in fl or '.svn' in fl:
            return 'Version Control'
        elif 'wp-config' in fl:
            return 'WordPress Config'
        elif 'robots.txt' in fl or 'sitemap' in fl:
            return 'SEO/Discovery'
        elif any(x in fl for x in ['.zip', '.rar', '.7z', '.tar', '.gz']):
            return 'Archive'
        elif 'package.json' in fl or 'composer.json' in fl or 'requirements.txt' in fl:
            return 'Dependencies'
        elif '.bin' in fl or '.dat' in fl:
            return 'Binary'
        return 'Other'

    # ==================== ANALYSE BASES DE DONNEES ====================

    def analyze_database(self, filepath: str, real_type: str, filename: str):
        print(f"    {self.colorize('🔬 Analyse de la base...', 'cyan')}")

        analysis = {
            'file': filename,
            'type': real_type,
            'tables': {},
            'error': None
        }

        try:
            if real_type == 'sqlite':
                analysis = self.analyze_sqlite(filepath, filename)
            elif real_type in ['mysql_dump', 'postgres_dump', 'sql_dump']:
                analysis = self.analyze_sql_dump(filepath, filename)
            elif real_type == 'gzip':
                analysis = self.analyze_compressed_db(filepath, filename)
            elif real_type == 'zip':
                analysis = self.analyze_zip_archive(filepath, filename)
            elif real_type == 'redis_dump':
                analysis = self.analyze_redis_dump(filepath, filename)
            elif real_type == 'bson':
                analysis = self.analyze_bson(filepath, filename)
            else:
                analysis = self.analyze_generic_db(filepath, filename)
        except Exception as e:
            analysis['error'] = str(e)
            self.log_error(f"analyze_database({filename}): {e}")

        with self.lock:
            self.results['db_contents'][filename] = analysis

        self.display_db_summary(analysis)

    def analyze_sqlite(self, filepath: str, filename: str) -> dict:
        result = {'file': filename, 'type': 'SQLite', 'tables': {}, 'error': None}
        tmp_path = None
        try:
            tmp_path = f"/tmp/{hashlib.md5(filename.encode()).hexdigest()}_analyze"
            shutil.copy2(filepath, tmp_path)

            conn = sqlite3.connect(tmp_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM `{table}`")
                    count = cursor.fetchone()[0]
                    cursor.execute(f"SELECT * FROM `{table}` LIMIT 10")
                    rows = cursor.fetchall()
                    cols = [desc[0] for desc in cursor.description] if cursor.description else []
                    result['tables'][table] = {
                        'columns': cols, 'row_count': count,
                        'sample': [list(row) for row in rows]
                    }
                except Exception as e:
                    result['tables'][table] = {'error': str(e)}
            conn.close()
        except Exception as e:
            result['error'] = str(e)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
        return result

    def analyze_sql_dump(self, filepath: str, filename: str) -> dict:
        result = {'file': filename, 'type': 'SQL Dump', 'tables': {}, 'error': None}
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            if '-- MySQL dump' in content[:200]:
                result['type'] = 'MySQL Dump'
            elif '-- PostgreSQL database dump' in content[:200]:
                result['type'] = 'PostgreSQL Dump'

            create_re = re.compile(r'CREATE TABLE\s+(?:IF NOT EXISTS\s+)?[`"\[]?(\w+)[`"\]]?', re.IGNORECASE)
            tables = create_re.findall(content)

            for table in tables:
                insert_re = re.compile(
                    rf'INSERT INTO\s+[`"\[]?{re.escape(table)}[`"\]]?\s+.*?;',
                    re.IGNORECASE | re.DOTALL
                )
                inserts = insert_re.findall(content)
                create_table_re = re.compile(
                    rf'CREATE TABLE\s+[`"\[]?{re.escape(table)}[`"\]]?\s*\((.*?)\)',
                    re.IGNORECASE | re.DOTALL
                )
                create_match = create_table_re.search(content)
                columns = []
                if create_match:
                    for line in create_match.group(1).split(','):
                        col_match = re.match(r'\s*[`"\[]?(\w+)[`"\]]?', line)
                        if col_match:
                            col_name = col_match.group(1)
                            if col_name.upper() not in ['PRIMARY', 'KEY', 'UNIQUE', 'INDEX',
                                                        'CONSTRAINT', 'FOREIGN']:
                                columns.append(col_name)
                result['tables'][table] = {
                    'columns': columns, 'insert_count': len(inserts),
                    'sample': [ins[:300] for ins in inserts[:3]]
                }
        except Exception as e:
            result['error'] = str(e)
        return result

    def analyze_compressed_db(self, filepath: str, filename: str) -> dict:
        result = {'file': filename, 'type': 'Compressed DB', 'tables': {}, 'error': None}
        tmp_path = None
        try:
            with open(filepath, 'rb') as f:
                magic = f.read(6)
            tmp_path = filepath + '.decompressed'

            if magic.startswith(b'\x1f\x8b'):
                with gzip.open(filepath, 'rb') as fi, open(tmp_path, 'wb') as fo:
                    shutil.copyfileobj(fi, fo)
            elif magic.startswith(b'BZh'):
                with bz2.open(filepath, 'rb') as fi, open(tmp_path, 'wb') as fo:
                    shutil.copyfileobj(fi, fo)
            elif magic.startswith(b'\xfd7zXZ'):
                with lzma.open(filepath, 'rb') as fi, open(tmp_path, 'wb') as fo:
                    shutil.copyfileobj(fi, fo)
            else:
                result['error'] = 'compression non reconnue'
                return result

            with open(tmp_path, 'rb') as f:
                head = f.read(100)
            real_type = self.identify_file_type(head)
            result['decompressed_type'] = real_type

            if real_type == 'sqlite':
                sub = self.analyze_sqlite(tmp_path, filename + '.decompressed')
                result['tables'] = sub.get('tables', {})
            elif 'dump' in real_type:
                sub = self.analyze_sql_dump(tmp_path, filename + '.decompressed')
                result['tables'] = sub.get('tables', {})
            else:
                with open(tmp_path, 'rb') as f:
                    result['preview'] = f.read(500).decode('utf-8', errors='ignore')
        except Exception as e:
            result['error'] = str(e)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
        return result

    def analyze_zip_archive(self, filepath: str, filename: str) -> dict:
        result = {'file': filename, 'type': 'ZIP Archive', 'contents': [],
                  'db_found': [], 'tables': {}, 'error': None}
        try:
            with zipfile.ZipFile(filepath, 'r') as z:
                for name in z.namelist():
                    result['contents'].append(name)
                    if any(name.lower().endswith(ext) for ext in
                           ['.sql', '.db', '.sqlite', '.sqlite3', '.dump', '.bson']):
                        extract_dir = f"{os.path.dirname(filepath)}/extracted_{hashlib.md5(filename.encode()).hexdigest()[:6]}"
                        os.makedirs(extract_dir, exist_ok=True)
                        z.extract(name, extract_dir)
                        extracted_path = os.path.join(extract_dir, name)

                        with open(extracted_path, 'rb') as f:
                            real_type = self.identify_file_type(f.read(100))

                        db_entry = {'name': name, 'extracted_path': extracted_path,
                                    'type': real_type, 'tables': {}}
                        if real_type == 'sqlite':
                            sub = self.analyze_sqlite(extracted_path, name)
                            db_entry['tables'] = sub.get('tables', {})
                        elif 'dump' in real_type:
                            sub = self.analyze_sql_dump(extracted_path, name)
                            db_entry['tables'] = sub.get('tables', {})
                        result['db_found'].append(db_entry)
                        result['tables'][name] = db_entry['tables']
        except Exception as e:
            result['error'] = str(e)
        return result

    def analyze_redis_dump(self, filepath: str, filename: str) -> dict:
        result = {'file': filename, 'type': 'Redis RDB', 'keys': [], 'error': None}
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            raw = re.findall(rb'[\x20-\x7e]{4,100}', content)
            candidates = set()
            for s in raw:
                try:
                    decoded = s.decode('ascii', errors='ignore')
                except Exception:
                    continue
                if any(c in decoded for c in ('\\x', '\x00')):
                    continue
                if decoded.startswith('REDIS'):
                    continue
                if len(set(decoded)) < 3:
                    continue
                candidates.add(decoded)
            result['keys'] = sorted(candidates)[:100]
        except Exception as e:
            result['error'] = str(e)
        return result

    def analyze_bson(self, filepath: str, filename: str) -> dict:
        result = {'file': filename, 'type': 'MongoDB BSON', 'preview': '', 'error': None}
        try:
            with open(filepath, 'rb') as f:
                content = f.read(10000)
            result['preview'] = content[:500].decode('utf-8', errors='ignore')
            strings_found = re.findall(rb'[a-zA-Z0-9_]{3,50}', content)
            unique = list(set([s.decode('utf-8', errors='ignore') for s in strings_found]))
            result['fields'] = unique[:50]
        except Exception as e:
            result['error'] = str(e)
        return result

    def analyze_generic_db(self, filepath: str, filename: str) -> dict:
        result = {'file': filename, 'type': 'Unknown (tentative generique)',
                  'tables': {}, 'error': None}
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            text = content.decode('utf-8', errors='ignore')
            create_re = re.compile(r'CREATE TABLE\s+(?:IF NOT EXISTS\s+)?[`"\[]?(\w+)[`"\]]?', re.IGNORECASE)
            tables = create_re.findall(text)
            for table in tables:
                insert_re = re.compile(
                    rf'INSERT INTO\s+[`"\[]?{re.escape(table)}[`"\]]?\s+.*?;',
                    re.IGNORECASE | re.DOTALL
                )
                inserts = insert_re.findall(text)
                result['tables'][table] = {
                    'insert_count': len(inserts),
                    'sample': [ins[:200] for ins in inserts[:2]]
                }
        except Exception as e:
            result['error'] = str(e)
        return result

    def display_db_summary(self, analysis: dict):
        print(f"    {self.colorize('┌─ Resume de la base', 'cyan')}")
        print(f"    {self.colorize('│', 'cyan')} Fichier: {analysis.get('file', 'N/A')}")
        print(f"    {self.colorize('│', 'cyan')} Type: {analysis.get('type', 'N/A')}")

        tables = analysis.get('tables', {})
        if tables:
            print(f"    {self.colorize('│', 'cyan')} Tables: {len(tables)}")
            for table_name, table_data in list(tables.items())[:10]:
                if 'error' in table_data:
                    print(f"    {self.colorize('│', 'cyan')}   - {table_name}: [ERREUR]")
                else:
                    cols = table_data.get('columns', [])
                    count = table_data.get('row_count', 0) or table_data.get('insert_count', 0)
                    print(f"    {self.colorize('│', 'cyan')}   - {table_name}: {count} lignes, {len(cols)} colonnes")

        if analysis.get('keys'):
            print(f"    {self.colorize('│', 'cyan')} Cles Redis: {len(analysis['keys'])}")
        if analysis.get('error'):
            print(f"    {self.colorize('│', 'yellow')} Erreur: {analysis['error'][:80]}")
        print(f"    {self.colorize('└─', 'cyan')}")

    # ==================== ANALYSE AVANCEE ====================

    def detect_technologies(self):
        techs_found = set()
        for page in self.results['pages']:
            text = page.get('html', '')
            headers = page.get('headers', {})
            for tech, patterns in self.tech_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in text.lower():
                        techs_found.add(tech)
                    if pattern.lower() in str(headers).lower():
                        techs_found.add(tech)
            server = headers.get('Server', '')
            if 'nginx' in server.lower():
                techs_found.add('Nginx')
            elif 'apache' in server.lower():
                techs_found.add('Apache')
            elif 'cloudflare' in server.lower():
                techs_found.add('Cloudflare')
        self.results['technologies'] = sorted(techs_found)
        if techs_found:
            print(f"    ⚙️  {len(techs_found)} technologies detectees")

    def find_admin_pages(self):
        base_url = self.target_url.rstrip('/')
        admin_urls = []
        uas = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.0',
        ]
        for pattern in self.admin_patterns:
            for ext in ['', '.php', '.html', '.asp', '.aspx']:
                url = f"{base_url}/{pattern}{ext}"
                try:
                    response = requests.get(
                        url, headers={'User-Agent': random.choice(uas)},
                        timeout=5, verify=self.config['verify_ssl']
                    )
                    if response.status_code == 200 and len(response.content) > 100:
                        admin_urls.append(url)
                        print(f"    🔐 Page admin: {url}")
                except Exception as e:
                    self.log_error(f"find_admin({url}): {e}")
                finally:
                    time.sleep(random.uniform(0.3, 1.2))
        self.results['admin_pages'] = admin_urls

    def extract_emails(self):
        emails = set()
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        for page in self.results['pages']:
            found = email_pattern.findall(page.get('html', ''))
            emails.update(found)
        self.results['emails'] = sorted(emails)
        if emails:
            print(f"\n    📧 Emails: {len(emails)}")

    def extract_forms(self, html, base_url):
        forms = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
        except Exception:
            return forms
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            absolute_action = urljoin(base_url, action)
            fields = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                fields.append({
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'required': input_tag.has_attr('required')
                })
            has_csrf = any('csrf' in str(field).lower() or 'token' in str(field).lower()
                           for field in fields)
            forms.append({
                'url': base_url, 'action': absolute_action, 'method': method,
                'fields': fields, 'has_csrf': has_csrf
            })
        return forms

    def extract_comments(self, html, url):
        comments = []
        comment_pattern = re.compile(r'<!--(.*?)-->', re.DOTALL)
        for comment in comment_pattern.findall(html):
            comment = comment.strip()
            if len(comment) > 10 and '<!--' not in comment:
                comments.append({'page': url, 'comment': comment[:200]})
        return comments

    # ==================== CHANGER DE CIBLE ====================

    def change_target(self):
        print(self.colorize("\n🎯 CHANGER DE CIBLE", 'bold'))
        print(self.colorize("=" * 60, 'cyan'))
        print(f"Cible actuelle: {self.target_url or '(aucune)'}")

        new_url = self.get_user_input("\nNouvelle URL cible (vide pour annuler)", "")
        if not new_url:
            print(self.colorize("\n⚠️ Changement annule", 'yellow'))
            input(self.colorize("Appuyez sur Entree...", 'blue'))
            return

        if not new_url.startswith(('http://', 'https://')):
            new_url = 'https://' + new_url

        try:
            parsed = urlparse(new_url)
            if not parsed.netloc:
                raise ValueError("URL invalide")
        except Exception:
            print(self.colorize(f"\n❌ URL invalide: {new_url}", 'red'))
            input(self.colorize("Appuyez sur Entree...", 'blue'))
            return

        if self.target_url and self.get_yes_no("\n🗑️  Effacer les resultats precedents ?"):
            self.reset_state()
            print(self.colorize("  ✓ Resultats effaces", 'green'))
        else:
            self.reset_state()
            print(self.colorize("  ✓ Etat reinitialise (nouveau crawl prealable)", 'green'))

        self.target_url = new_url
        self.target_domain = parsed.netloc

        print(self.colorize(f"\n✅ Nouvelle cible: {self.target_url}", 'green'))
        print(f"   Domaine: {self.target_domain}")
        print(f"   Dossier: {self.config['output_dir']}/{self.target_domain}")

        input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))

    # ==================== AFFICHAGE ET EXPORT ====================

    def download_specific_file(self):
        print(self.colorize("\n📥 TELECHARGER UN FICHIER SPECIFIQUE", 'bold'))
        print(self.colorize("=" * 60, 'cyan'))
        url = self.get_user_input("URL du fichier", "")
        if not url:
            return
        if not self.target_domain:
            self.target_domain = urlparse(url).netloc
        site_dir = f"{self.config['output_dir']}/{self.target_domain}"
        for sub in ['sensitive', 'databases']:
            os.makedirs(f"{site_dir}/{sub}", exist_ok=True)
        print(f"\n🔍 Tentative de telechargement: {url}")
        success = self.download_sensitive_file(url, site_dir, reason="manuel")
        if success:
            print(self.colorize("\n✅ Fichier telecharge avec succes!", 'green'))
        else:
            print(self.colorize("\n❌ Echec du telechargement", 'red'))
        input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))

    def show_sensitive_files(self):
        if not self.results['sensitive_files']:
            print(self.colorize("\n❌ Aucun fichier sensible trouve", 'yellow'))
            return
        print(self.colorize("\n🔴 FICHIERS SENSIBLES TROUVES", 'bold'))
        print(self.colorize("=" * 60, 'cyan'))
        by_type = defaultdict(list)
        for file in self.results['sensitive_files']:
            by_type[file['type']].append(file)
        for ftype, files in by_type.items():
            print(f"\n{self.colorize(f'📁 {ftype} ({len(files)})', 'yellow', bold=True)}")
            for file in files:
                print(f"  • {self.colorize(file['filename'], 'red')} ({file['size']} o) [{file.get('real_type', 'unknown')}]")
                print(f"    📍 {file['url']}")

    def show_databases(self):
        if not self.results['databases']:
            print(self.colorize("\n❌ Aucune base de donnees trouvee", 'yellow'))
            return
        print(self.colorize("\n🗄️  BASES DE DONNEES TROUVEES", 'bold'))
        print(self.colorize("=" * 60, 'cyan'))
        for i, db in enumerate(self.results['databases'], 1):
            print(f"\n{i}. {self.colorize(db['filename'], 'magenta')} ({db['size']} o)")
            print(f"   📍 {db['url']}")
            print(f"   📂 {db['path']}")
            print(f"   🔎 Type reel: {db.get('real_type', 'unknown')}")
            analysis = self.results['db_contents'].get(db['filename'], {})
            tables = analysis.get('tables', {})
            if tables:
                print(f"   📊 {len(tables)} table(s):")
                for table_name, table_data in tables.items():
                    if 'error' in table_data:
                        print(f"      - {table_name}: [ERREUR]")
                    else:
                        cols = table_data.get('columns', [])
                        count = table_data.get('row_count', 0) or table_data.get('insert_count', 0)
                        print(f"      - {table_name}: {count} lignes")
                        if cols:
                            print(f"        Colonnes: {', '.join(cols[:10])}")
                        sample = table_data.get('sample', [])
                        if sample:
                            print(f"        Echantillon:")
                            for row in sample[:3]:
                                if isinstance(row, list):
                                    print(f"          {' | '.join(str(c)[:30] for c in row)}")
                                else:
                                    print(f"          {str(row)[:100]}")
            if analysis.get('keys'):
                print(f"   🔑 {len(analysis['keys'])} cles Redis detectees")
                for key in analysis['keys'][:10]:
                    print(f"      - {key}")
            if analysis.get('error'):
                print(f"   ⚠️  Erreur: {analysis['error'][:100]}")

    def show_results(self):
        print(self.colorize("\n📊 RESULTATS DU CRAWL", 'bold'))
        print(self.colorize("=" * 60, 'cyan'))
        print(f"Cible: {self.target_url or '(aucune)'}")
        print(f"\n📄 Pages decouvertes: {len(self.results['pages'])}")
        print(f"📦 Assets telecharges: {len(self.results['assets'])}")
        print(f"🔴 Fichiers sensibles: {len(self.results['sensitive_files'])}")
        print(f"🗄️  Bases de donnees: {len(self.results['databases'])}")
        print(f"📝 Formulaires: {len(self.results['forms'])}")
        print(f"📧 Emails: {len(self.results['emails'])}")
        print(f"🔐 Pages admin: {len(self.results['admin_pages'])}")
        if self.results['technologies']:
            print(f"\n⚙️ Technologies detectees:")
            for tech in self.results['technologies']:
                print(f"  - {tech}")

    def export_results(self):
        print(self.colorize("\n📤 EXPORT DES RESULTATS", 'bold'))
        print(self.colorize("=" * 60, 'cyan'))
        if not self.target_domain:
            print(self.colorize("❌ Aucun crawl effectue", 'red'))
            input(self.colorize("\nAppuyez sur Entree...", 'blue'))
            return
        print("Formats disponibles:")
        print("  1. JSON")
        print("  2. HTML")
        print("  3. CSV")
        print("  4. Tous les formats")
        choice = self.get_user_input("Choisissez le format", "4")
        site_dir = f"{self.config['output_dir']}/{self.target_domain}"
        os.makedirs(f"{site_dir}/reports", exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if choice in ('1', '4'):
            filename = f"{site_dir}/reports/crawl_report_{timestamp}.json"
            export_data = dict(self.results)
            export_data['pages'] = [{k: v for k, v in p.items() if k != 'html'}
                                    for p in export_data['pages']]
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            print(self.colorize(f"✅ JSON: {filename}", 'green'))
        if choice in ('2', '4'):
            filename = f"{site_dir}/reports/crawl_report_{timestamp}.html"
            self.export_html_report(filename)
            print(self.colorize(f"✅ HTML: {filename}", 'green'))
        if choice in ('3', '4'):
            filename = f"{site_dir}/reports/crawl_report_{timestamp}.csv"
            self.export_csv_report(filename)
            print(self.colorize(f"✅ CSV: {filename}", 'green'))
        input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))

    def export_html_report(self, filename):
        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Crawl Report - JATHNIEL v4.3</title>
<style>
body {{ font-family: Arial; margin: 20px; background: #f5f5f5; }}
.container {{ max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 10px; }}
h1 {{ color: #d32f2f; }}
.header {{ background: #1e1e1e; color: white; padding: 15px; border-radius: 5px; }}
.stats {{ display: flex; gap: 20px; flex-wrap: wrap; }}
.stat-box {{ background: #e3f2fd; padding: 15px; border-radius: 5px; flex: 1; min-width: 150px; }}
.stat-box.db {{ background: #f3e5f5; }}
.stat-value {{ font-size: 24px; font-weight: bold; color: #1976d2; }}
.stat-box.db .stat-value {{ color: #7b1fa2; }}
.stat-label {{ font-size: 14px; color: #666; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
th {{ background: #1e1e1e; color: white; padding: 10px; text-align: left; }}
td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
.sensitive {{ background: #ffebee; border-left: 4px solid #d32f2f; }}
.database {{ background: #f3e5f5; border-left: 4px solid #7b1fa2; }}
.admin {{ background: #fff3e0; border-left: 4px solid #f57c00; }}
.db-detail {{ background: #fafafa; padding: 15px; margin: 10px 0; border-left: 4px solid #7b1fa2; }}
.db-detail pre {{ background: #263238; color: #aed581; padding: 10px; overflow-x: auto; border-radius: 4px; }}
.footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 12px; }}
</style></head>
<body><div class="container">
<div class="header"><h1>🕷️ Web Crawl Report v4.3</h1>
<p>Generated by JATHNIEL-WEB-CRAWLER-PRO</p>
<p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>Target: {self.target_url}</p></div>
<h2>📊 Statistics</h2>
<div class="stats">
<div class="stat-box"><div class="stat-value">{self.results['statistics']['total_pages']}</div><div class="stat-label">Pages</div></div>
<div class="stat-box"><div class="stat-value">{self.results['statistics']['total_assets']}</div><div class="stat-label">Assets</div></div>
<div class="stat-box"><div class="stat-value">{self.results['statistics']['total_sensitive']}</div><div class="stat-label">Sensitive Files</div></div>
<div class="stat-box db"><div class="stat-value">{self.results['statistics']['total_databases']}</div><div class="stat-label">🗄️ Databases</div></div>
<div class="stat-box"><div class="stat-value">{len(self.results['emails'])}</div><div class="stat-label">Emails</div></div>
<div class="stat-box"><div class="stat-value">{self.results['statistics']['duration']:.2f}s</div><div class="stat-label">Duration</div></div>
</div>
<h2>🗄️ Databases Found ({len(self.results['databases'])})</h2>"""
        for db in self.results['databases']:
            analysis = self.results['db_contents'].get(db['filename'], {})
            html += f'<div class="db-detail"><h3>{db["filename"]} <span style="color: #7b1fa2;">({db.get("real_type", "unknown")})</span></h3>'
            html += f'<p><strong>URL:</strong> <a href="{db["url"]}" target="_blank">{db["url"]}</a></p>'
            html += f'<p><strong>Size:</strong> {db["size"]} bytes</p>'
            html += f'<p><strong>Path:</strong> {db["path"]}</p>'
            tables = analysis.get('tables', {})
            if tables:
                html += f"<p><strong>Tables ({len(tables)}):</strong></p>"
                for table_name, table_data in tables.items():
                    if 'error' in table_data:
                        html += f"<p>⚠️ {table_name}: {table_data['error']}</p>"
                    else:
                        cols = table_data.get('columns', [])
                        count = table_data.get('row_count', 0) or table_data.get('insert_count', 0)
                        html += f'<details><summary><strong>{table_name}</strong> ({count} rows, {len(cols)} columns)</summary>'
                        html += f'<p>Columns: {", ".join(cols)}</p>'
                        html += f'<pre>{json.dumps(table_data.get("sample", [])[:5], indent=2, default=str)[:2000]}</pre></details>'
            if analysis.get('keys'):
                html += f'<p><strong>Redis Keys ({len(analysis["keys"])}):</strong></p><pre>{chr(10).join(analysis["keys"][:20])}</pre>'
            html += "</div>"
        html += '<h2>🔴 Sensitive Files</h2><table><tr><th>#</th><th>File</th><th>Type</th><th>Real Type</th><th>Size</th><th>URL</th></tr>'
        for i, file in enumerate(self.results['sensitive_files'], 1):
            html += f'<tr class="sensitive"><td>{i}</td><td>{file["filename"]}</td><td>{file["type"]}</td>'
            html += f'<td>{file.get("real_type", "unknown")}</td><td>{file["size"]} bytes</td>'
            html += f'<td><a href="{file["url"]}" target="_blank">{file["url"][:60]}...</a></td></tr>'
        html += '</table><h2>🔐 Admin Pages</h2><table><tr><th>#</th><th>URL</th></tr>'
        for i, url in enumerate(self.results['admin_pages'], 1):
            html += f'<tr class="admin"><td>{i}</td><td><a href="{url}" target="_blank">{url}</a></td></tr>'
        html += '</table><h2>📧 Emails</h2><ul>'
        for email in self.results['emails'][:30]:
            html += f"<li>{email}</li>"
        html += f'''</ul><div class="footer">
<p>Generated by JATHNIEL-WEB-CRAWLER-PRO v4.3</p>
<p>CTF / Lab Tool - For educational and authorized purposes only</p>
<p>★ JATHNIEL ★</p></div></div></body></html>'''
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)

    def export_csv_report(self, filename):
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['TARGET', self.target_url])
            writer.writerow([])
            writer.writerow(['DATABASES'])
            writer.writerow(['File', 'Type', 'Size', 'URL', 'Tables'])
            for db in self.results['databases']:
                analysis = self.results['db_contents'].get(db['filename'], {})
                tables = list(analysis.get('tables', {}).keys())
                writer.writerow([db['filename'], db.get('real_type', ''), db['size'],
                                 db['url'], ', '.join(tables)])
            writer.writerow([])
            writer.writerow(['SENSITIVE FILES'])
            writer.writerow(['File', 'Type', 'Real Type', 'Size', 'URL'])
            for file in self.results['sensitive_files']:
                writer.writerow([file['filename'], file['type'],
                                 file.get('real_type', ''), file['size'], file['url']])
            writer.writerow([])
            writer.writerow(['ADMIN PAGES'])
            writer.writerow(['URL'])
            for url in self.results['admin_pages']:
                writer.writerow([url])
            writer.writerow([])
            writer.writerow(['EMAILS'])
            writer.writerow(['Email'])
            for email in self.results['emails']:
                writer.writerow([email])

    def show_statistics(self):
        stats = self.results['statistics']
        print(self.colorize("\n📊 STATISTIQUES DU CRAWL", 'bold'))
        print(self.colorize("=" * 60, 'cyan'))
        print(f"Cible: {self.target_url or '(aucune)'}")
        print(f"\n📄 Pages decouvertes: {stats['total_pages']}")
        print(f"📦 Assets telecharges: {stats['total_assets']}")
        print(f"🔴 Fichiers sensibles: {stats['total_sensitive']}")
        print(f"🗄️  Bases de donnees: {stats['total_databases']}")
        print(f"📦 Taille totale: {self.format_size(stats['total_size'])}")
        print(f"⏱️  Duree: {stats['duration']:.2f} secondes")
        if stats['duration'] > 0:
            print(f"🚀 Vitesse moyenne: {stats['total_pages'] / stats['duration']:.2f} pages/sec")

    def show_config(self):
        print(self.colorize("\n⚙️ CONFIGURATION", 'bold'))
        print(self.colorize("=" * 60, 'cyan'))
        for key, value in self.config.items():
            print(f"  {key}: {self.colorize(str(value), 'green' if value else 'yellow')}")
        input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))

    def show_help(self):
        help_text = f"""
{self.colorize('📚 WEB CRAWLER PRO v4.3 - GUIDE D UTILISATION', 'bold')}
{self.colorize('=' * 60, 'cyan')}

{self.colorize('1. Crawl complet', 'green')}
   - Explore tout le site
   - Telecharge les pages, assets et fichiers sensibles
   - Analyse les technologies et emails

{self.colorize('2. Extraction de bases de donnees', 'green')}
   - Recherche automatique des DB exposees
   - Identification par magic bytes
   - Analyse automatique du contenu

{self.colorize('3. Changer de cible', 'green')}
   - Modifie la cible actuelle
   - Reset l'etat (visited_urls, resultats)

{self.colorize('4. Telechargement specifique', 'green')}
   - Telecharge un fichier specifique

{self.colorize('5-7. Visualiser les resultats', 'green')}
   - Voir les resultats generaux, fichiers sensibles, bases

{self.colorize('8. Export des resultats', 'green')}
   - JSON / HTML / CSV

{self.colorize('🆕 NOUVEAU v4.3 :', 'yellow')}
   - visited_assets vs visited_sensitive (plus de conflits)
   - Compteur active_downloads (attend la fin des DL)
   - extract_assets epure (css/js/img uniquement)
   - Detection des 404 HTML custom
   - Logs detailles a chaque etape

{self.colorize('⚠️ RAPPEL', 'red')}
   - Cadre CTF / Labo uniquement
   - Autorisation ecrite requise pour toute cible non-locale
"""
        print(help_text)

    # ==================== MENU PRINCIPAL ====================

    def run(self):
        while True:
            self.clear_screen()
            self.show_banner()
            self.show_menu()

            choice = input(self.colorize("\n👉 Votre choix: ", 'bold')).strip()

            if choice == '1':
                url = self.get_user_input("URL cible", self.target_url or "https://example.com")
                if url:
                    if not url.startswith(('http://', 'https://')):
                        url = 'https://' + url
                    self.crawl_complete(url)
                input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))

            elif choice == '2':
                url = self.get_user_input("URL cible", self.target_url or "https://example.com")
                if url:
                    if not url.startswith(('http://', 'https://')):
                        url = 'https://' + url
                    self.config['download_sensitive'] = True
                    self.config['analyze_db'] = True
                    self.crawl_complete(url)
                input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))

            elif choice == '3':
                self.change_target()

            elif choice == '4':
                self.download_specific_file()

            elif choice == '5':
                self.show_results()
                input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))

            elif choice == '6':
                self.show_sensitive_files()
                input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))

            elif choice == '7':
                self.show_databases()
                input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))

            elif choice == '8':
                self.export_results()

            elif choice == '9':
                self.show_config()

            elif choice == '10':
                self.show_statistics()
                input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))

            elif choice == '11':
                self.show_help()
                input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))

            elif choice == '0':
                print(self.colorize("\n👋 Au revoir!", 'green'))
                sys.exit(0)

            else:
                print(self.colorize("❌ Choix invalide", 'red'))
                time.sleep(1)


# ==================== MAIN ====================

if __name__ == "__main__":
    try:
        try:
            import requests
            from bs4 import BeautifulSoup
        except ImportError:
            print("[!] Installation des dependances...")
            os.system("pip3 install requests beautifulsoup4")

        crawler = JATHNIELCrawlerPro()
        crawler.run()
    except KeyboardInterrupt:
        print("\n\n👋 Au revoir!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Erreur fatale: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)