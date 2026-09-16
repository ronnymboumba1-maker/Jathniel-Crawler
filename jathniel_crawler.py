#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
JATHNIEL-WEB-CRAWLER-PRO v4.4
Crawler web professionnel avec extraction de bases de donnees exposees

Usage educatif / CTF / pentest autorise uniquement.

CHANGELOG v4.4 (QUICK WINS):
[ADD] Forced Browsing (wordlist 180+ chemins sensibles)
[ADD] Detection & dump .git/ expose
[ADD] Detection .env + parsing credentials
[ADD] Parsing enrichi robots.txt / sitemap.xml
[ADD] Test methodes HTTP (OPTIONS/PUT/DELETE/TRACE)
[ADD] Detection security headers manquants
[ADD] Panneau dedie "Forced Browsing" dans le menu
[FIX] v4.3 : visited_assets vs visited_sensitive
[FIX] v4.3 : compteur active_downloads
[FIX] v4.3 : detection 404 HTML custom
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
import subprocess
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from typing import Dict, List, Tuple, Optional, Any, Set
from collections import deque, defaultdict

import requests
from bs4 import BeautifulSoup
import mimetypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ==================== WORDLIST FORCED BROWSING ====================

FORCED_BROWSE_PATHS = [
    # Bases de donnees
    "backup.sql", "backup.sqlite", "backup.db", "backup.json", "backup.xml",
    "db.sql", "db.sqlite", "db.db", "db.json", "db.dump",
    "database.sql", "database.sqlite", "database.db", "database.json",
    "dump.sql", "dump.sqlite", "dump.db", "dump.json", "dump.rdb", "dump.archive",
    "data.sql", "data.sqlite", "data.db", "data.json", "data.xml", "data.csv",
    "export.sql", "export.json", "export.csv", "export.xml", "export.zip",
    "users.sql", "users.db", "users.json", "users.csv", "users.xml",
    "app.sqlite", "app.db", "app.json",
    "site.sql", "site.db", "site.json",
    "mysql.sql", "postgres.sql", "postgresql.sql", "mongodb.archive",
    "schema.sql", "structure.sql", "init.sql", "seed.sql",
    "migration.sql", "migrations.sql",
    # Backups / archives
    "backup.zip", "backup.tar", "backup.tar.gz", "backup.tgz", "backup.rar", "backup.7z",
    "site.zip", "site.tar.gz", "site-backup.zip", "site_backup.zip",
    "www.zip", "www.tar.gz", "web.zip", "web.tar.gz",
    "source.zip", "src.zip", "code.zip", "code.tar.gz",
    "old.zip", "bak.zip", "archives.zip", "archive.zip",
    "backup_2023.zip", "backup_2024.zip", "backup_2025.zip",
    "backup_2023.sql", "backup_2024.sql", "backup_2025.sql",
    "backup-old.zip", "backup_old.zip", "old-backup.zip",
    # Env / config
    ".env", ".env.local", ".env.prod", ".env.production", ".env.dev",
    ".env.development", ".env.staging", ".env.test", ".env.backup",
    ".env.example", ".env.sample", ".env.bak", ".env.old",
    "config.json", "config.yml", "config.yaml", "config.xml",
    "config.php", "config.js", "config.ts", "config.py",
    "config.inc.php", "config.inc", "configuration.php",
    "config.backup", "config.bak", "config.old", "config.txt",
    "settings.json", "settings.py", "settings.yml", "settings.yaml",
    "appsettings.json", "app.config", "web.config",
    "database.yml", "database.yaml", "database.json",
    "db.php", "db.json", "db.yml", "db.yaml",
    "credentials.json", "secrets.json", "keys.json", "tokens.json",
    "parameters.yml", "params.json",
    ".htaccess", ".htpasswd", "php.ini", "nginx.conf", "httpd.conf",
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old", "wp-config.txt",
    # Git / Version control
    ".git/config", ".git/HEAD", ".git/index", ".git/description",
    ".git/packed-refs", ".git/logs/HEAD", ".git/logs/refs/heads/master",
    ".git/refs/heads/master", ".git/refs/heads/main",
    ".gitignore", ".gitattributes", ".gitmodules",
    ".svn/entries", ".svn/wc.db", ".svn/format",
    ".hg/store", ".hg/requires", ".hgignore",
    ".bzr/README", ".bzr/branch-format",
    # Admin / API
    "admin", "admin/", "admin/index.php", "admin/login", "admin/login.php",
    "admin/dashboard", "admin/panel", "admin/config", "admin/users",
    "admin/backup", "admin/db", "admin/export", "admin/dump",
    "administrator", "administrator/", "administrator/index.php",
    "admin.php", "admin.html", "admin.json",
    "login", "login.php", "login.html", "signin", "signin.php",
    "panel", "panel/", "panel.php", "dashboard", "dashboard.php",
    "cpanel", "cpanel/", "webmail", "webmail/",
    "phpmyadmin", "phpmyadmin/", "pma", "pma/", "myadmin",
    "adminer.php", "adminer/", "adminer",
    "api", "api/", "api/v1", "api/v1/", "api/v2", "api/v2/",
    "api/admin", "api/users", "api/users.json", "api/config",
    "api/dump", "api/export", "api/backup", "api/debug",
    "api/v1/users", "api/v1/admin", "api/v1/export",
    "api/v1/users.json", "api/v2/users", "api/v2/admin",
    "graphql", "graphiql", "graphql/", "graphql.php",
    "swagger", "swagger/", "swagger.json", "swagger.yaml",
    "swagger-ui", "swagger-ui/", "swagger-ui.html",
    "openapi", "openapi/", "openapi.json", "openapi.yaml",
    "api-docs", "api-docs/", "api-docs.json", "docs", "docs/",
    "redoc", "redoc/", "redoc.html",
    # Logs / debug
    "error.log", "errors.log", "access.log", "debug.log", "app.log",
    "application.log", "server.log", "php_errors.log",
    "logs/error.log", "logs/access.log", "logs/app.log",
    "log/error.log", "log/app.log",
    "var/log/app.log", "storage/logs/laravel.log",
    "debug", "debug/", "debug.php", "debug.json", "info", "info.php",
    "test", "test/", "test.php", "tests", "tests/",
    "phpinfo.php", "server-status", "server-info",
    "console", "console/", "shell", "shell.php", "c99.php", "r57.php",
    # Devops
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".dockerignore", "docker-compose.override.yml",
    "Jenkinsfile", ".gitlab-ci.yml", ".travis.yml", ".circleci/config.yml",
    "Makefile", "Vagrantfile", "Vagrantfile.local",
    "kubernetes.yml", "k8s.yml", "helm/values.yml",
    ".github/workflows/main.yml", ".github/workflows/ci.yml",
    # Package manifests
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.json", "composer.lock", "requirements.txt", "requirements-dev.txt",
    "Gemfile", "Gemfile.lock", "Pipfile", "Pipfile.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.properties",
    "Cargo.toml", "Cargo.lock", "go.mod", "go.sum",
    "README.md", "README.txt", "README", "CHANGELOG.md", "CHANGELOG.txt",
    "LICENSE", "LICENSE.txt", "COPYING", "INSTALL", "INSTALL.md",
    "VERSION", "VERSION.txt", "TODO", "TODO.md",
    # Divers / discovery
    "robots.txt", "sitemap.xml", "sitemap.xml.gz", "sitemap_index.xml",
    "humans.txt", "security.txt", ".well-known/security.txt",
    "crossdomain.xml", "clientaccesspolicy.xml", "manifest.json",
    "favicon.ico", "favicon.png", "apple-touch-icon.png",
    "nginx_status", "status", "health", "healthcheck", "healthz",
    "metrics", "prometheus", "actuator", "actuator/health", "actuator/env",
    "actuator/mappings", "actuator/beans", "actuator/heapdump",
    ".htaccess.bak", ".DS_Store", "Thumbs.db", "web.config.bak",
    "old/", "old", "backup/", "backups/", "bak/", "temp/", "tmp/", "cache/",
    "private/", "secret/", "secrets/", "internal/", "export/", "exports/",
    "files/", "uploads/", "data/", "database/", "db/", "sql/", "dump/", "dumps/",
    "tests/", "test/", "staging/", "dev/", "development/", "prod/",
]


class JATHNIELCrawlerPro:
    """Crawler web professionnel avec extraction de bases de donnees exposees."""

    def __init__(self):
        self.config = {
            'max_depth': 3,
            'max_pages': 500,
            'max_files': 100,
            'threads': 10,
            'timeout': 30,
            'delay': 0.5,
            'forced_browse_threads': 15,
            'user_agent': 'JATHNIEL-Crawler-Pro/4.4 (Educational; CTF/Lab)',
            'output_dir': './crawled_sites',
            'download_sensitive': True,
            'download_assets': True,
            'respect_robots': True,
            'follow_redirects': True,
            'verify_ssl': False,
            'analyze_db': True,
            'forced_browse': True,
            'check_git': True,
            'check_methods': True,
            'check_headers': True,
        }

        # Etat
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
        self.download_lock = threading.Lock()
        self.lock = threading.Lock()
        self.scanning = False
        self.pause = False

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
            '.log', '.bin', '.dat', '.raw', '.img', '.iso',
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

        self.security_headers = {
            'Strict-Transport-Security': 'HSTS manquant (HTTPS force)',
            'Content-Security-Policy': 'CSP manquant (XSS)',
            'X-Frame-Options': 'Clickjacking possible',
            'X-Content-Type-Options': 'MIME sniffing possible',
            'Referrer-Policy': 'Referrer leak possible',
            'Permissions-Policy': 'Permissions non restreintes',
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
            'forced_browse_hits': [],
            'git_dump': {'exposed': False, 'files': []},
            'env_leaked': {'found': False, 'credentials': []},
            'http_methods': {},
            'security_headers_missing': [],
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
            'red': '\033[91m', 'green': '\033[92m', 'yellow': '\033[93m',
            'blue': '\033[94m', 'magenta': '\033[95m', 'cyan': '\033[96m',
            'white': '\033[97m', 'bold': '\033[1m', 'end': '\033[0m'
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
{self.colorize('║', 'cyan')}  {self.colorize('              WEB CRAWLER PRO v4.4 - JATHNIEL EDITION', 'yellow')}  {self.colorize('║', 'cyan')}
{self.colorize('║', 'cyan')}  {self.colorize('   🕷️  Crawler + Forced Browse + Extraction de bases de donnees  🕷️', 'green')}  {self.colorize('║', 'cyan')}
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
{self.colorize('│', 'cyan')}  {self.colorize('MENU PRINCIPAL - WEB CRAWLER PRO v4.4', 'bold')}                                          {self.colorize('│', 'cyan')}
{self.colorize('├────────────────────────────────────────────────────────────────────────────────────┤', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('1.', 'yellow')}  {self.colorize('Crawl complet (pages + sensibles + DB)', 'white')}                              {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('2.', 'yellow')}  {self.colorize('Crawl complet + Forced Browsing', 'white')}                                   {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('3.', 'yellow')}  {self.colorize('Forced Browsing uniquement', 'white')}                                       {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('4.', 'yellow')}  {self.colorize('Changer la cible actuelle', 'white')}                                              {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('5.', 'yellow')}  {self.colorize('Telecharger un fichier specifique', 'white')}                                       {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('6.', 'yellow')}  {self.colorize('Voir les resultats du crawl', 'white')}                                             {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('7.', 'yellow')}  {self.colorize('Voir les fichiers sensibles', 'white')}                                             {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('8.', 'yellow')}  {self.colorize('Voir les bases de donnees extraites', 'white')}                                   {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('9.', 'yellow')}  {self.colorize('Voir les hits du Forced Browsing', 'white')}                                    {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('10.', 'yellow')} {self.colorize('Voir les infos securite (.git, .env, headers)', 'white')}                          {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('11.', 'yellow')} {self.colorize('Exporter les resultats (JSON/HTML/CSV)', 'white')}                                {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('12.', 'yellow')} {self.colorize('Configuration', 'white')}                                                          {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('13.', 'yellow')} {self.colorize('Statistiques du crawl', 'white')}                                                   {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('14.', 'yellow')} {self.colorize('Aide / Documentation', 'white')}                                                    {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('0.', 'yellow')}  {self.colorize('Quitter', 'white')}                                                               {self.colorize('│', 'cyan')}
{self.colorize('├────────────────────────────────────────────────────────────────────────────────────┤', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('📌 Cible:', 'bold')} {target_display[:70]:<70} {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('📄 Pages:', 'bold')} {self.results['statistics']['total_pages']}  {self.colorize('📁 Sensibles:', 'bold')} {self.results['statistics']['total_sensitive']}  {self.colorize('🗄️  DB:', 'bold')} {self.results['statistics']['total_databases']}  {self.colorize('🎯 FB:', 'bold')} {len(self.results['forced_browse_hits'])}  {self.colorize('│', 'cyan')}
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

    # ==================== PHASE 1 : FORCED BROWSING ====================

    def forced_browse(self, base_url, site_dir):
        """Teste une wordlist de chemins sensibles connus."""
        print(f"\n{self.colorize('🎯 FORCED BROWSING', 'cyan', bold=True)}")
        print(self.colorize("=" * 80, 'blue'))
        print(f"📋 Wordlist : {len(FORCED_BROWSE_PATHS)} chemins")
        print(f"🧵 Threads  : {self.config['forced_browse_threads']}")
        print(self.colorize("=" * 80, 'blue'))

        base = base_url.rstrip('/')
        results = []
        lock = threading.Lock()
        counter = [0]

        # Reference 404 (pour filtrer SPA)
        reference_status = None
        reference_size = 0
        reference_hash = None
        try:
            fake_url = f"{base}/this-does-not-exist-{random.randint(100000,999999)}"
            r404 = requests.get(fake_url,
                                headers={'User-Agent': self.config['user_agent']},
                                timeout=10, verify=self.config['verify_ssl'],
                                allow_redirects=False)
            reference_status = r404.status_code
            reference_size = len(r404.content)
            reference_hash = hashlib.md5(r404.content).hexdigest()
            if reference_status == 200:
                print(f"  {self.colorize('⚠️', 'yellow')} Site SPA détecté (404 → 200)")
                print(f"     Taille reference : {reference_size} o")
        except Exception:
            pass

        def worker():
            while True:
                try:
                    path = path_queue.get(timeout=2)
                except queue.Empty:
                    return
                try:
                    url = f"{base}/{path.lstrip('/')}"
                    try:
                        r = requests.get(
                            url,
                            headers={'User-Agent': self.config['user_agent']},
                            timeout=8,
                            verify=self.config['verify_ssl'],
                            allow_redirects=False,
                            stream=True,
                        )

                        status = r.status_code
                        size = int(r.headers.get('content-length', 0) or 0)

                        # Filtrer les faux positifs SPA
                        is_fp = False
                        if status == 200 and reference_status == 200:
                            # Test rapide : lire le debut du corps
                            content = b""
                            try:
                                for chunk in r.iter_content(4096):
                                    content += chunk
                                    if len(content) >= 8192:
                                        break
                            except Exception:
                                pass
                            content_hash = hashlib.md5(content).hexdigest()
                            if content_hash == reference_hash and len(content) >= 4096:
                                is_fp = True

                        r.close()

                        with lock:
                            counter[0] += 1

                            if is_fp:
                                # Faux positif SPA
                                pass
                            elif status in (200, 201, 202, 204):
                                # VRAI hit !
                                results.append((url, status, size, 'OK'))
                                self.results['forced_browse_hits'].append({
                                    'url': url, 'status': status, 'size': size, 'type': 'accessible'
                                })
                                print(f"  {self.colorize('🔴', 'red')} [{status}] {url} ({size} o)")
                                # Telecharger
                                self.download_sensitive_file(url, site_dir, reason=f"forced-browse [{status}]")
                            elif status in (401, 403):
                                # Existe mais protege
                                results.append((url, status, size, 'PROTECTED'))
                                self.results['forced_browse_hits'].append({
                                    'url': url, 'status': status, 'size': size, 'type': 'protected'
                                })
                                print(f"  {self.colorize('🟡', 'yellow')} [{status}] {url} (existe)")
                            elif status == 301 or status == 302:
                                # Redirection interessante
                                loc = r.headers.get('Location', '') if hasattr(r, 'headers') else ''
                                if loc and path not in loc:
                                    self.results['forced_browse_hits'].append({
                                        'url': url, 'status': status, 'size': size, 'type': 'redirect',
                                        'location': loc
                                    })
                                    print(f"  {self.colorize('🔵', 'blue')} [{status}] {url} → {loc[:60]}")

                            # Progress
                            if counter[0] % 25 == 0:
                                print(f"  {self.colorize(f'📊 {counter[0]}/{len(FORCED_BROWSE_PATHS)} testés', 'cyan')}")
                    except requests.exceptions.Timeout:
                        pass
                    except Exception as e:
                        self.log_error(f"forced_browse({url}): {e}")
                finally:
                    path_queue.task_done()
                    time.sleep(random.uniform(0.05, 0.15))

        path_queue = queue.Queue()
        for p in FORCED_BROWSE_PATHS:
            path_queue.put(p)

        threads = []
        for _ in range(self.config['forced_browse_threads']):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=60)

        print(f"\n{self.colorize('✓', 'green')} Forced browsing termine")
        print(f"  • {len([r for r in results if r[3] == 'OK'])} accessible(s)")
        print(f"  • {len([r for r in results if r[3] == 'PROTECTED'])} protege(s) (401/403)")

        return results

    # ==================== PHASE 2 : GIT ====================

    def check_git_exposed(self, base_url, site_dir):
        """Detecte et dumpe .git/ expose."""
        print(f"\n{self.colorize('🔍 VERIFICATION .git/', 'cyan', bold=True)}")
        git_url = urljoin(base_url.rstrip('/') + '/', '.git/')

        try:
            r = requests.get(git_url + "HEAD",
                             headers={'User-Agent': self.config['user_agent']},
                             timeout=10, verify=self.config['verify_ssl'])
            if r.status_code == 200 and b'ref:' in r.content:
                print(f"  {self.colorize('🚨 .git/ EXPOSE !', 'red', bold=True)}")
                self.results['git_dump']['exposed'] = True

                dump_dir = f"{site_dir}/git_dump"
                os.makedirs(dump_dir, exist_ok=True)

                # Essaie git-dumper
                if shutil.which('git-dumper'):
                    print(f"  🎯 git-dumper detecte, dump en cours...")
                    try:
                        result = subprocess.run(
                            ['git-dumper', git_url, dump_dir],
                            capture_output=True, timeout=180, text=True
                        )
                        if result.returncode == 0:
                            print(f"  {self.colorize('✅', 'green')} Repo dumpe dans {dump_dir}")
                            self._grep_secrets_in_dir(dump_dir)
                        else:
                            print(f"  {self.colorize('⚠️', 'yellow')} git-dumper partiel: {result.stderr[:100]}")
                    except subprocess.TimeoutExpired:
                        print(f"  {self.colorize('⚠️', 'yellow')} git-dumper timeout")
                else:
                    print(f"  {self.colorize('ℹ️', 'blue')} git-dumper non installe, dump manuel des fichiers cles...")
                    key_files = [
                        '.git/HEAD', '.git/config', '.git/index',
                        '.git/packed-refs', '.git/logs/HEAD', '.git/description',
                    ]
                    for kf in key_files:
                        try:
                            r2 = requests.get(urljoin(base_url.rstrip('/') + '/', kf),
                                              headers={'User-Agent': self.config['user_agent']},
                                              timeout=10, verify=self.config['verify_ssl'])
                            if r2.status_code == 200:
                                fname = kf.replace('/', '_')
                                fpath = os.path.join(dump_dir, fname)
                                with open(fpath, 'wb') as f:
                                    f.write(r2.content)
                                print(f"    ✓ {kf}")
                                self.results['git_dump']['files'].append(kf)
                        except Exception:
                            pass

                    # Essaie de recuperer les objets git (peut etre lourd)
                    for obj_dir in ['.git/refs/heads/master', '.git/refs/heads/main']:
                        try:
                            r2 = requests.get(urljoin(base_url.rstrip('/') + '/', obj_dir),
                                              headers={'User-Agent': self.config['user_agent']},
                                              timeout=10, verify=self.config['verify_ssl'])
                            if r2.status_code == 200:
                                commit_hash = r2.text.strip()
                                if re.match(r'^[a-f0-9]{40}$', commit_hash):
                                    print(f"    ✓ Commit trouve: {commit_hash[:10]}")
                        except Exception:
                            pass

                return True
        except Exception as e:
            self.log_error(f"check_git({git_url}): {e}")

        print(f"  {self.colorize('✓', 'green')} .git/ non expose")
        return False

    def _grep_secrets_in_dir(self, directory):
        """Cherche des credentials/secrets dans un dossier."""
        patterns = {
            'password': r"(?:password|passwd|pwd|secret)['\"]?\s*[:=]\s*['\"]([^'\"]{3,80})['\"]",
            'api_key': r"(?:api[_-]?key|apikey|secret[_-]?key)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]",
            'aws_key': r"AKIA[0-9A-Z]{16}",
            'jwt_secret': r"(?:JWT_SECRET|jwt_secret|jwtSecret)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
            'db_url': r"(?:mysql|postgres|postgresql|mongodb|redis)://[^\s'\"]+",
            'conn_string': r"(?:Server|Data Source|Host)=[^;\"']+",
        }

        seen = set()
        for root, _, files in os.walk(directory):
            for fname in files:
                fpath = os.path.join(root, fname)
                if os.path.getsize(fpath) > 5_000_000:
                    continue
                try:
                    with open(fpath, 'r', errors='ignore') as f:
                        content = f.read()
                    for name, pat in patterns.items():
                        for m in re.findall(pat, content, re.IGNORECASE):
                            m_str = m if isinstance(m, str) else str(m)
                            key = (name, m_str[:100])
                            if key in seen:
                                continue
                            seen.add(key)
                            self.results['git_dump']['files'].append({
                                'source': fpath, 'type': name, 'value': m_str[:200]
                            })
                            print(f"    {self.colorize('💎', 'magenta')} [{name}] {m_str[:80]}")
                except Exception:
                    pass

    # ==================== PHASE 3 : ENV ====================

    def check_env_exposed(self, base_url, site_dir):
        """Detecte et parse .env expose."""
        print(f"\n{self.colorize('🔍 VERIFICATION .env', 'cyan', bold=True)}")
        env_paths = ['.env', '.env.local', '.env.prod', '.env.production',
                     '.env.dev', '.env.development', '.env.staging', '.env.backup']

        for env_path in env_paths:
            url = urljoin(base_url.rstrip('/') + '/', env_path)
            try:
                r = requests.get(url,
                                 headers={'User-Agent': self.config['user_agent']},
                                 timeout=8, verify=self.config['verify_ssl'])
                if r.status_code == 200 and len(r.text) > 10:
                    body = r.text
                    # Filtre faux positif (page 404 custom renvoie .env)
                    if '<html' in body.lower()[:200] and len(body) < 5000:
                        continue

                    print(f"  {self.colorize('🚨 .env EXPOSE !', 'red', bold=True)} {url}")
                    self.results['env_leaked']['found'] = True

                    # Parser le .env
                    creds = []
                    for line in body.splitlines():
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        if '=' in line:
                            k, v = line.split('=', 1)
                            k = k.strip()
                            v = v.strip().strip('"').strip("'")
                            if any(x in k.upper() for x in
                                   ['DB', 'DATABASE', 'MONGO', 'MYSQL', 'POSTGRES',
                                    'REDIS', 'SECRET', 'KEY', 'TOKEN', 'PASSWORD',
                                    'JWT', 'API', 'AWS', 'S3', 'MAIL', 'SMTP']):
                                creds.append({'key': k, 'value': v[:200]})
                                print(f"    {self.colorize('🔑', 'yellow')} {k} = {v[:80]}")

                    self.results['env_leaked']['credentials'] = creds

                    # Sauvegarder
                    env_file = os.path.join(site_dir, 'sensitive', env_path.replace('/', '_'))
                    with open(env_file, 'w') as f:
                        f.write(body)

                    return True
            except Exception:
                pass

        print(f"  {self.colorize('✓', 'green')} .env non expose")
        return False

    # ==================== PHASE 4 : METHODES HTTP ====================

    def check_http_methods(self, base_url):
        """Teste les methodes HTTP dangereuses."""
        print(f"\n{self.colorize('🔍 METHODES HTTP', 'cyan', bold=True)}")
        dangerous_methods = ['OPTIONS', 'PUT', 'DELETE', 'TRACE', 'PATCH']
        findings = {}

        for method in dangerous_methods:
            try:
                r = requests.request(
                    method, base_url,
                    headers={'User-Agent': self.config['user_agent']},
                    timeout=10, verify=self.config['verify_ssl'],
                    allow_redirects=False,
                )
                findings[method] = r.status_code

                if method == 'OPTIONS' and r.status_code == 200:
                    allow = r.headers.get('Allow', '')
                    print(f"  {self.colorize('🟡', 'yellow')} OPTIONS → 200 | Allow: {allow}")
                elif method in ('PUT', 'DELETE') and r.status_code in (200, 201, 204):
                    print(f"  {self.colorize('🔴', 'red')} {method} → {r.status_code} (DANGEREUX !)")
                elif method == 'TRACE' and r.status_code == 200:
                    print(f"  {self.colorize('🔴', 'red')} TRACE → 200 (XST possible)")
                else:
                    print(f"  {self.colorize('⚪', 'white')} {method} → {r.status_code}")
            except Exception:
                pass

        self.results['http_methods'] = findings
        return findings

    # ==================== PHASE 5 : SECURITY HEADERS ====================

    def check_security_headers(self, base_url):
        """Verifie les headers de securite manquants."""
        print(f"\n{self.colorize('🔍 HEADERS DE SECURITE', 'cyan', bold=True)}")
        missing = []

        try:
            r = requests.get(base_url,
                             headers={'User-Agent': self.config['user_agent']},
                             timeout=10, verify=self.config['verify_ssl'])
            headers = {k.lower(): v for k, v in r.headers.items()}

            for header, desc in self.security_headers.items():
                if header.lower() not in headers:
                    missing.append({'header': header, 'description': desc})
                    print(f"  {self.colorize('🟡', 'yellow')} ✗ {header} — {desc}")
                else:
                    print(f"  {self.colorize('✓', 'green')} ✓ {header}")

            self.results['security_headers_missing'] = missing
        except Exception as e:
            self.log_error(f"check_headers: {e}")

        return missing

    # ==================== AMORCAGE ====================

    def seed_from_robots_and_sitemap(self, base_url):
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        seeds = []

        # robots.txt
        if self.config['respect_robots']:
            try:
                r = requests.get(f"{base}/robots.txt",
                                 headers={'User-Agent': self.config['user_agent']},
                                 timeout=10, verify=self.config['verify_ssl'])
                if r.status_code == 200:
                    print(f"  {self.colorize('ℹ️', 'blue')} robots.txt trouvé")
                    for line in r.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith('sitemap:'):
                            sitemap_url = line.split(':', 1)[1].strip()
                            seeds.append(sitemap_url)
                        elif line.lower().startswith('disallow:'):
                            path = line.split(':', 1)[1].strip()
                            if path and path != '/':
                                # Ajouter aussi les paths disallow comme seeds
                                full_url = urljoin(base + '/', path.lstrip('/'))
                                self._seed_urls.append(full_url)
                                print(f"    🚫 Disallow: {path}")
            except Exception as e:
                self.log_error(f"robots.txt: {e}")

        seeds.append(f"{base}/sitemap.xml")

        for seed in seeds:
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

    def crawl_complete(self, url, do_forced_browse=False, do_git_check=False, do_env_check=False):
        self.target_url = url
        self.target_domain = urlparse(url).netloc
        self.scanning = True

        # Reset
        self.visited_urls = set()
        self.visited_assets = set()
        self.visited_sensitive = set()
        self._crawled_urls = set()
        self._seed_urls = []
        self.queue = deque()
        self.results = self._empty_results()
        self.active_downloads = [0]

        site_dir = f"{self.config['output_dir']}/{self.target_domain}"
        for sub in ['pages', 'assets', 'sensitive', 'databases', 'reports', 'git_dump']:
            os.makedirs(f"{site_dir}/{sub}", exist_ok=True)

        print(f"\n{self.colorize('🕷️ Debut du crawl de:', 'cyan')} {url}")
        print(self.colorize("=" * 80, 'blue'))
        print(f"📁 Sortie: {site_dir}")
        print(f"📊 Max pages: {self.config['max_pages']}  |  Depth: {self.config['max_depth']}")
        print(f"🧵 Threads: {self.config['threads']}  |  Delay: {self.config['delay']}s")
        print(self.colorize("=" * 80, 'blue'))

        self.results['statistics']['start_time'] = datetime.now()

        # Amorcage
        print(self.colorize("\n🌱 Amorcage via robots.txt / sitemap.xml...", 'yellow'))
        try:
            self.seed_from_robots_and_sitemap(url)
        except Exception as e:
            self.log_error(f"seed: {e}")

        # Queue de pages
        page_queue = queue.Queue()
        page_queue.put((url, 0))
        for seed_url in self._seed_urls:
            page_queue.put((seed_url, 1))

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

        idle_count = 0
        while idle_count < 3:
            time.sleep(1.0)
            with active_lock:
                idle_crawl = (page_queue.empty() and active_workers[0] == 0)
            with self.download_lock:
                idle_dl = (self.active_downloads[0] == 0)

            if idle_crawl and idle_dl:
                idle_count += 1
            else:
                idle_count = 0

        stop_flag.set()
        for t in threads:
            t.join(timeout=10)

        # Analyses complementaires
        print(self.colorize("\n🔍 Analyse complementaire...", 'yellow'))
        try:
            self.detect_technologies()
        except Exception as e:
            self.log_error(f"tech: {e}")
        try:
            self.extract_emails()
        except Exception as e:
            self.log_error(f"emails: {e}")

        # Forced Browsing
        if do_forced_browse and self.config['forced_browse']:
            try:
                self.forced_browse(url, site_dir)
            except Exception as e:
                self.log_error(f"forced_browse: {e}")

        # Git check
        if do_git_check and self.config['check_git']:
            try:
                self.check_git_exposed(url, site_dir)
            except Exception as e:
                self.log_error(f"git: {e}")

        # Env check
        if do_env_check:
            try:
                self.check_env_exposed(url, site_dir)
            except Exception as e:
                self.log_error(f"env: {e}")

        # Methodes HTTP
        if self.config['check_methods']:
            try:
                self.check_http_methods(url)
            except Exception as e:
                self.log_error(f"methods: {e}")

        # Security headers
        if self.config['check_headers']:
            try:
                self.check_security_headers(url)
            except Exception as e:
                self.log_error(f"headers: {e}")

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
        print(f"🎯 Forced browse hits: {len(self.results['forced_browse_hits'])}")
        print(f"🚨 .git expose: {'OUI' if self.results['git_dump']['exposed'] else 'non'}")
        print(f"🚨 .env expose: {'OUI' if self.results['env_leaked']['found'] else 'non'}")
        print(f"📊 Duree: {self.results['statistics']['duration']:.2f} secondes")

    def crawl_page(self, url, depth, site_dir, page_queue):
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
                'url': url, 'depth': depth, 'status': response.status_code,
                'size': len(response.content), 'filename': page_filename,
                'html': html, 'headers': dict(response.headers),
            }

            with self.lock:
                self.results['pages'].append(page_data)
                self.results['statistics']['total_pages'] += 1
                self.results['statistics']['total_size'] += len(response.content)

            print(f"  📄 [{depth}] {url} ({len(response.content)} o)")

            if depth < self.config['max_depth']:
                links = self.extract_links(html, url)
                for link in links:
                    with self.lock:
                        if link not in self._crawled_urls:
                            page_queue.put((link, depth + 1))

            if self.config['download_sensitive']:
                self.search_sensitive_in_page(html, url, site_dir)

            if self.config['download_assets']:
                self.extract_assets(html, url, site_dir)

            forms = self.extract_forms(html, url)
            with self.lock:
                self.results['forms'].extend(forms)

            comments = self.extract_comments(html, url)
            with self.lock:
                self.results['comments'].extend(comments)

            time.sleep(random.uniform(self.config['delay'], self.config['delay'] * 2))

        except Exception as e:
            self.log_error(f"crawl_page({url}): {e}")

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
        try:
            soup = BeautifulSoup(html, 'html.parser')
        except Exception:
            return
        assets_found = []
        for link in soup.find_all('link', rel='stylesheet', href=True):
            href = link['href']
            if href and href.endswith('.css'):
                assets_found.append(urljoin(base_url, href))
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src and src.endswith('.js'):
                assets_found.append(urljoin(base_url, src))
        for img in soup.find_all('img', src=True):
            src = img['src']
            if src and any(src.lower().endswith(ext) for ext in
                           ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.ico']):
                assets_found.append(urljoin(base_url, src))
        for asset_url in assets_found:
            self.download_asset(asset_url, site_dir)

    def download_asset(self, url, site_dir):
        with self.lock:
            if url in self.visited_assets:
                return
            self.visited_assets.add(url)

        tmp_path = None
        try:
            response = requests.get(
                url, headers={'User-Agent': self.config['user_agent']},
                timeout=self.config['timeout'], verify=self.config['verify_ssl'],
                stream=True, allow_redirects=True,
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
                self.results['assets'].append({'url': url, 'filename': filename, 'size': size})
                self.results['statistics']['total_assets'] += 1
        except Exception as e:
            self.log_error(f"asset({url}): {e}")
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

    def search_sensitive_in_page(self, html, url, site_dir):
        found_urls = set()
        candidates = []

        urls_in_page = re.findall(
            r'(?:href|src|action|data-url|data-src|data-href)=["\']([^"\']+)["\']',
            html, re.IGNORECASE
        )

        for file_url in urls_in_page:
            file_url_lower = file_url.lower()
            matched_reason = None
            for ext in self.sensitive_extensions:
                if (file_url_lower.endswith(ext) or
                    ext + '?' in file_url_lower or
                    ext + '#' in file_url_lower):
                    matched_reason = f"ext {ext}"
                    break
            if not matched_reason:
                for fname in self.sensitive_filenames:
                    if fname.lower() in file_url_lower:
                        matched_reason = f"file {fname}"
                        break
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

        for absolute_url, reason in candidates:
            if urlparse(absolute_url).netloc == self.target_domain:
                self.download_sensitive_file(absolute_url, site_dir, reason=reason)

    def download_sensitive_file(self, url, site_dir, reason=""):
        with self.lock:
            if url in self.visited_sensitive:
                return False
            self.visited_sensitive.add(url)

        with self.download_lock:
            self.active_downloads[0] += 1

        tmp_path = None
        try:
            response = requests.get(
                url, headers={'User-Agent': self.config['user_agent']},
                timeout=self.config['timeout'], verify=self.config['verify_ssl'],
                stream=True, allow_redirects=True,
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
                        return False
                    f.write(chunk)
            response.close()

            with open(tmp_path, 'rb') as f:
                head = f.read(8192)

            real_type = self.identify_file_type(head)

            is_html = b'<html' in head.lower() or b'<!doctype' in head.lower()
            is_404_page = False
            if is_html and size < 10000:
                head_str = head[:3000].decode('utf-8', errors='ignore').lower()
                if any(marker in head_str for marker in
                       ['not found', '404', 'page introuvable', 'does not exist']):
                    is_404_page = True
            if is_404_page:
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
                'url': url, 'filename': filename, 'size': size,
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
                    self.log_error(f"analyze({filename}): {e}")

            return True
        except Exception as e:
            self.log_error(f"download_sensitive({url}): {e}")
            return False
        finally:
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
        return 'Other'

    # ==================== ANALYSE DB ====================

    def analyze_database(self, filepath, real_type, filename):
        print(f"    {self.colorize('🔬 Analyse de la base...', 'cyan')}")
        analysis = {'file': filename, 'type': real_type, 'tables': {}, 'error': None}
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
        with self.lock:
            self.results['db_contents'][filename] = analysis
        self.display_db_summary(analysis)

    def analyze_sqlite(self, filepath, filename):
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

    def analyze_sql_dump(self, filepath, filename):
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
                cm = create_table_re.search(content)
                columns = []
                if cm:
                    for line in cm.group(1).split(','):
                        col_match = re.match(r'\s*[`"\[]?(\w+)[`"\]]?', line)
                        if col_match:
                            cn = col_match.group(1)
                            if cn.upper() not in ['PRIMARY', 'KEY', 'UNIQUE', 'INDEX',
                                                   'CONSTRAINT', 'FOREIGN']:
                                columns.append(cn)
                result['tables'][table] = {
                    'columns': columns, 'insert_count': len(inserts),
                    'sample': [ins[:300] for ins in inserts[:3]]
                }
        except Exception as e:
            result['error'] = str(e)
        return result

    def analyze_compressed_db(self, filepath, filename):
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
        except Exception as e:
            result['error'] = str(e)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
        return result

    def analyze_zip_archive(self, filepath, filename):
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

    def analyze_redis_dump(self, filepath, filename):
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

    def analyze_bson(self, filepath, filename):
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

    def analyze_generic_db(self, filepath, filename):
        result = {'file': filename, 'type': 'Unknown', 'tables': {}, 'error': None}
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            text = content.decode('utf-8', errors='ignore')
            create_re = re.compile(r'CREATE TABLE\s+(?:IF NOT EXISTS\s+)?[`"\[]?(\w+)[`"\]]?', re.IGNORECASE)
            for table in create_re.findall(text):
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

    def display_db_summary(self, analysis):
        print(f"    {self.colorize('┌─ Resume de la base', 'cyan')}")
        print(f"    {self.colorize('│', 'cyan')} Fichier: {analysis.get('file', 'N/A')}")
        print(f"    {self.colorize('│', 'cyan')} Type: {analysis.get('type', 'N/A')}")
        tables = analysis.get('tables', {})
        if tables:
            print(f"    {self.colorize('│', 'cyan')} Tables: {len(tables)}")
            for tn, td in list(tables.items())[:10]:
                if 'error' in td:
                    print(f"    {self.colorize('│', 'cyan')}   - {tn}: [ERREUR]")
                else:
                    cols = td.get('columns', [])
                    count = td.get('row_count', 0) or td.get('insert_count', 0)
                    print(f"    {self.colorize('│', 'cyan')}   - {tn}: {count} lignes, {len(cols)} colonnes")
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

    def extract_emails(self):
        emails = set()
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        for page in self.results['pages']:
            emails.update(email_pattern.findall(page.get('html', '')))
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
            has_csrf = any('csrf' in str(f).lower() or 'token' in str(f).lower() for f in fields)
            forms.append({'url': base_url, 'action': absolute_action, 'method': method,
                          'fields': fields, 'has_csrf': has_csrf})
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
        self.reset_state()
        self.target_url = new_url
        self.target_domain = parsed.netloc
        print(self.colorize(f"\n✅ Nouvelle cible: {self.target_url}", 'green'))
        print(f"   Domaine: {self.target_domain}")
        input(self.colorize("\nAppuyez sur Entree pour continuer...", 'blue'))

    # ==================== AFFICHAGE ====================

    def download_specific_file(self):
        print(self.colorize("\n📥 TELECHARGER UN FICHIER SPECIFIQUE", 'bold'))
        url = self.get_user_input("URL du fichier", "")
        if not url:
            return
        if not self.target_domain:
            self.target_domain = urlparse(url).netloc
        site_dir = f"{self.config['output_dir']}/{self.target_domain}"
        for sub in ['sensitive', 'databases']:
            os.makedirs(f"{site_dir}/{sub}", exist_ok=True)
        success = self.download_sensitive_file(url, site_dir, reason="manuel")
        if success:
            print(self.colorize("\n✅ Fichier telecharge!", 'green'))
        else:
            print(self.colorize("\n❌ Echec", 'red'))
        input(self.colorize("\nAppuyez sur Entree...", 'blue'))

    def show_sensitive_files(self):
        if not self.results['sensitive_files']:
            print(self.colorize("\n❌ Aucun fichier sensible trouve", 'yellow'))
            return
        print(self.colorize("\n🔴 FICHIERS SENSIBLES TROUVES", 'bold'))
        for file in self.results['sensitive_files']:
            print(f"  • {self.colorize(file['filename'], 'red')} ({file['size']} o) [{file.get('real_type', '?')}]")
            print(f"    📍 {file['url']}")

    def show_databases(self):
        if not self.results['databases']:
            print(self.colorize("\n❌ Aucune base de donnees trouvee", 'yellow'))
            return
        print(self.colorize("\n🗄️  BASES DE DONNEES", 'bold'))
        for i, db in enumerate(self.results['databases'], 1):
            print(f"\n{i}. {self.colorize(db['filename'], 'magenta')} ({db['size']} o)")
            print(f"   📍 {db['url']}")
            print(f"   🔎 Type: {db.get('real_type', '?')}")
            analysis = self.results['db_contents'].get(db['filename'], {})
            tables = analysis.get('tables', {})
            if tables:
                print(f"   📊 {len(tables)} table(s):")
                for tn, td in tables.items():
                    if 'error' in td:
                        print(f"      - {tn}: [ERREUR]")
                    else:
                        cols = td.get('columns', [])
                        count = td.get('row_count', 0) or td.get('insert_count', 0)
                        print(f"      - {tn}: {count} lignes, {len(cols)} colonnes")
                        if cols:
                            print(f"        Colonnes: {', '.join(cols[:10])}")
                        for row in td.get('sample', [])[:3]:
                            if isinstance(row, list):
                                print(f"          {' | '.join(str(c)[:30] for c in row)}")

    def show_forced_browse_hits(self):
        if not self.results['forced_browse_hits']:
            print(self.colorize("\n❌ Aucun hit de forced browsing", 'yellow'))
            return
        print(self.colorize("\n🎯 HITS FORCED BROWSING", 'bold'))
        for hit in self.results['forced_browse_hits']:
            color = 'red' if hit['type'] == 'accessible' else 'yellow' if hit['type'] == 'protected' else 'blue'
            print(f"  [{hit['status']}] {self.colorize(hit['url'], color)} ({hit.get('size', 0)} o) [{hit['type']}]")

    def show_security_info(self):
        print(self.colorize("\n🛡️  INFORMATIONS SECURITE", 'bold'))
        print(self.colorize("=" * 60, 'cyan'))

        print(f"\n📁 .git/ expose: {'🚨 OUI' if self.results['git_dump']['exposed'] else '✅ non'}")
        if self.results['git_dump']['exposed']:
            print(f"   Fichiers: {len(self.results['git_dump']['files'])}")
            for f in self.results['git_dump']['files'][:10]:
                if isinstance(f, dict):
                    print(f"     💎 [{f.get('type', '?')}] {str(f.get('value', ''))[:80]}")

        print(f"\n📁 .env expose: {'🚨 OUI' if self.results['env_leaked']['found'] else '✅ non'}")
        if self.results['env_leaked']['found']:
            for c in self.results['env_leaked']['credentials'][:15]:
                print(f"     🔑 {c['key']} = {c['value'][:80]}")

        print(f"\n📡 Methodes HTTP:")
        for m, status in self.results['http_methods'].items():
            color = 'red' if (m in ('PUT', 'DELETE', 'TRACE') and status in (200, 201, 204)) else 'white'
            print(f"     {self.colorize(f'{m}: {status}', color)}")

        if self.results['security_headers_missing']:
            print(f"\n🟡 Headers manquants ({len(self.results['security_headers_missing'])}):")
            for h in self.results['security_headers_missing']:
                print(f"     • {h['header']} — {h['description']}")
        else:
            print(f"\n✅ Tous les headers de securite sont presents")

    def show_results(self):
        print(self.colorize("\n📊 RESULTATS DU CRAWL", 'bold'))
        print(self.colorize("=" * 60, 'cyan'))
        print(f"Cible: {self.target_url or '(aucune)'}")
        print(f"\n📄 Pages: {len(self.results['pages'])}")
        print(f"📦 Assets: {len(self.results['assets'])}")
        print(f"🔴 Fichiers sensibles: {len(self.results['sensitive_files'])}")
        print(f"🗄️  Bases de donnees: {len(self.results['databases'])}")
        print(f"🎯 Forced browse hits: {len(self.results['forced_browse_hits'])}")
        print(f"🚨 .git expose: {'OUI' if self.results['git_dump']['exposed'] else 'non'}")
        print(f"🚨 .env expose: {'OUI' if self.results['env_leaked']['found'] else 'non'}")
        print(f"📧 Emails: {len(self.results['emails'])}")
        if self.results['technologies']:
            print(f"\n⚙️ Technologies:")
            for t in self.results['technologies']:
                print(f"  - {t}")

    def export_results(self):
        print(self.colorize("\n📤 EXPORT", 'bold'))
        if not self.target_domain:
            print(self.colorize("❌ Aucun crawl effectue", 'red'))
            input(self.colorize("Appuyez sur Entree...", 'blue'))
            return
        print("  1. JSON\n  2. HTML\n  3. CSV\n  4. Tous")
        choice = self.get_user_input("Choix", "4")
        site_dir = f"{self.config['output_dir']}/{self.target_domain}"
        os.makedirs(f"{site_dir}/reports", exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')

        if choice in ('1', '4'):
            fn = f"{site_dir}/reports/crawl_report_{ts}.json"
            data = dict(self.results)
            data['pages'] = [{k: v for k, v in p.items() if k != 'html'} for p in data['pages']]
            with open(fn, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            print(self.colorize(f"✅ JSON: {fn}", 'green'))
        if choice in ('2', '4'):
            fn = f"{site_dir}/reports/crawl_report_{ts}.html"
            self.export_html(fn)
            print(self.colorize(f"✅ HTML: {fn}", 'green'))
        if choice in ('3', '4'):
            fn = f"{site_dir}/reports/crawl_report_{ts}.csv"
            self.export_csv(fn)
            print(self.colorize(f"✅ CSV: {fn}", 'green'))
        input(self.colorize("\nAppuyez sur Entree...", 'blue'))

    def export_html(self, filename):
        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Crawl Report v4.4</title>
<style>
body {{ font-family: Arial; margin: 20px; background: #f5f5f5; }}
.container {{ max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 10px; }}
h1 {{ color: #d32f2f; }}
.header {{ background: #1e1e1e; color: white; padding: 15px; border-radius: 5px; }}
.stats {{ display: flex; gap: 15px; flex-wrap: wrap; margin: 20px 0; }}
.stat-box {{ background: #e3f2fd; padding: 15px; border-radius: 5px; min-width: 130px; text-align: center; }}
.stat-box.warn {{ background: #fff3e0; }}
.stat-box.danger {{ background: #ffebee; }}
.stat-value {{ font-size: 28px; font-weight: bold; color: #1976d2; }}
.stat-box.danger .stat-value {{ color: #c62828; }}
.stat-box.warn .stat-value {{ color: #e65100; }}
.stat-label {{ font-size: 13px; color: #666; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
th {{ background: #1e1e1e; color: white; padding: 10px; text-align: left; }}
td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
.sensitive {{ background: #ffebee; }}
.database {{ background: #f3e5f5; }}
.git {{ background: #fff3e0; }}
.section {{ margin-top: 30px; }}
.footer {{ text-align: center; margin-top: 40px; color: #666; font-size: 12px; }}
pre {{ background: #263238; color: #aed581; padding: 10px; border-radius: 4px; overflow-x: auto; }}
</style></head>
<body><div class="container">
<div class="header">
<h1>🕷️ Web Crawl Report v4.4</h1>
<p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Cible: {self.target_url}</p>
</div>

<h2>📊 Statistiques</h2>
<div class="stats">
<div class="stat-box"><div class="stat-value">{self.results['statistics']['total_pages']}</div><div class="stat-label">Pages</div></div>
<div class="stat-box"><div class="stat-value">{self.results['statistics']['total_assets']}</div><div class="stat-label">Assets</div></div>
<div class="stat-box warn"><div class="stat-value">{self.results['statistics']['total_sensitive']}</div><div class="stat-label">Fichiers sensibles</div></div>
<div class="stat-box warn"><div class="stat-value">{self.results['statistics']['total_databases']}</div><div class="stat-label">Bases de donnees</div></div>
<div class="stat-box"><div class="stat-value">{len(self.results['forced_browse_hits'])}</div><div class="stat-label">Forced browse hits</div></div>
<div class="stat-box danger"><div class="stat-value">{'🚨' if self.results['git_dump']['exposed'] else '✅'}</div><div class="stat-label">.git</div></div>
<div class="stat-box danger"><div class="stat-value">{'🚨' if self.results['env_leaked']['found'] else '✅'}</div><div class="stat-label">.env</div></div>
</div>
"""
        if self.results['git_dump']['exposed']:
            html += '<h2>🚨 .git/ EXPOSE</h2><div class="section">'
            for f in self.results['git_dump']['files'][:20]:
                if isinstance(f, dict):
                    html += f"<p>💎 <strong>[{f.get('type', '?')}]</strong> <code>{str(f.get('value', ''))[:200]}</code></p>"
            html += '</div>'

        if self.results['env_leaked']['found']:
            html += '<h2>🚨 .env EXPOSE</h2><div class="section">'
            for c in self.results['env_leaked']['credentials'][:30]:
                html += f"<p>🔑 <strong>{c['key']}</strong> = <code>{c['value'][:200]}</code></p>"
            html += '</div>'

        if self.results['forced_browse_hits']:
            html += '<h2>🎯 Forced Browsing Hits</h2><table><tr><th>Status</th><th>URL</th><th>Type</th><th>Taille</th></tr>'
            for h in self.results['forced_browse_hits']:
                cls = 'sensitive' if h['type'] == 'accessible' else ''
                html += f'<tr class="{cls}"><td>{h["status"]}</td><td>{h["url"]}</td><td>{h["type"]}</td><td>{h.get("size", 0)}</td></tr>'
            html += '</table>'

        if self.results['databases']:
            html += '<h2>🗄️ Bases de donnees</h2><table><tr><th>Fichier</th><th>Type</th><th>Taille</th><th>URL</th></tr>'
            for db in self.results['databases']:
                html += f'<tr class="database"><td>{db["filename"]}</td><td>{db.get("real_type", "?")}</td><td>{db["size"]}</td><td>{db["url"]}</td></tr>'
            html += '</table>'

        if self.results['sensitive_files']:
            html += '<h2>🔴 Fichiers sensibles</h2><table><tr><th>Fichier</th><th>Type</th><th>Taille</th><th>URL</th></tr>'
            for f in self.results['sensitive_files']:
                html += f'<tr class="sensitive"><td>{f["filename"]}</td><td>{f["type"]}</td><td>{f["size"]}</td><td>{f["url"]}</td></tr>'
            html += '</table>'

        if self.results['security_headers_missing']:
            html += '<h2>🟡 Headers de securite manquants</h2><ul>'
            for h in self.results['security_headers_missing']:
                html += f'<li><strong>{h["header"]}</strong> — {h["description"]}</li>'
            html += '</ul>'

        html += f'''<div class="footer">
<p>Generated by JATHNIEL-WEB-CRAWLER-PRO v4.4</p>
<p>★ JATHNIEL ★</p></div></div></body></html>'''
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)

    def export_csv(self, filename):
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['TARGET', self.target_url]); w.writerow([])
            w.writerow(['FORCED BROWSE HITS']); w.writerow(['Status', 'URL', 'Type', 'Size'])
            for h in self.results['forced_browse_hits']:
                w.writerow([h['status'], h['url'], h['type'], h.get('size', 0)])
            w.writerow([])
            w.writerow(['DATABASES']); w.writerow(['File', 'Type', 'Size', 'URL'])
            for db in self.results['databases']:
                w.writerow([db['filename'], db.get('real_type', ''), db['size'], db['url']])
            w.writerow([])
            w.writerow(['SENSITIVE FILES']); w.writerow(['File', 'Type', 'Size', 'URL'])
            for file in self.results['sensitive_files']:
                w.writerow([file['filename'], file['type'], file['size'], file['url']])
            w.writerow([])
            w.writerow(['GIT EXPOSED', 'YES' if self.results['git_dump']['exposed'] else 'NO'])
            w.writerow(['ENV EXPOSED', 'YES' if self.results['env_leaked']['found'] else 'NO'])
            w.writerow([])
            w.writerow(['SECURITY HEADERS MISSING'])
            for h in self.results['security_headers_missing']:
                w.writerow([h['header'], h['description']])

    def show_statistics(self):
        s = self.results['statistics']
        print(self.colorize("\n📊 STATISTIQUES", 'bold'))
        print(f"📄 Pages: {s['total_pages']}")
        print(f"📦 Assets: {s['total_assets']}")
        print(f"🔴 Fichiers sensibles: {s['total_sensitive']}")
        print(f"🗄️  Bases: {s['total_databases']}")
        print(f"🎯 Forced browse hits: {len(self.results['forced_browse_hits'])}")
        print(f"📦 Taille: {self.format_size(s['total_size'])}")
        print(f"⏱️  Duree: {s['duration']:.2f}s")
        if s['duration'] > 0:
            print(f"🚀 Vitesse: {s['total_pages'] / s['duration']:.2f} pages/sec")

    def show_config(self):
        print(self.colorize("\n⚙️ CONFIGURATION", 'bold'))
        for k, v in self.config.items():
            print(f"  {k}: {self.colorize(str(v), 'green' if v else 'yellow')}")
        input(self.colorize("\nAppuyez sur Entree...", 'blue'))

    def show_help(self):
        print(f"""
{self.colorize('📚 WEB CRAWLER PRO v4.4 - GUIDE', 'bold')}
{self.colorize('=' * 60, 'cyan')}

{self.colorize('1. Crawl complet', 'green')} — pages + assets + sensibles + DB
{self.colorize('2. Crawl + Forced Browse', 'green')} — ajoute la wordlist de 180 chemins
{self.colorize('3. Forced Browse seul', 'green')} — teste uniquement la wordlist

{self.colorize('🆕 NOUVEAU v4.4 :', 'yellow')}
   - Forced Browsing (180+ chemins classiques)
   - Detection .git/ expose + dump
   - Detection .env + parsing credentials
   - robots.txt / sitemap.xml enrichis
   - Methodes HTTP (OPTIONS/PUT/DELETE/TRACE)
   - Security headers check

{self.colorize('⚠️ RAPPEL', 'red')}
   - Cadre CTF / Labo uniquement
   - Autorisation ecrite requise
""")
        input(self.colorize("\nAppuyez sur Entree...", 'blue'))

    # ==================== MENU ====================

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
                    self.crawl_complete(url, do_forced_browse=False, do_git_check=False, do_env_check=False)
                input(self.colorize("\nAppuyez sur Entree...", 'blue'))

            elif choice == '2':
                url = self.get_user_input("URL cible", self.target_url or "https://example.com")
                if url:
                    if not url.startswith(('http://', 'https://')):
                        url = 'https://' + url
                    self.crawl_complete(url, do_forced_browse=True, do_git_check=True, do_env_check=True)
                input(self.colorize("\nAppuyez sur Entree...", 'blue'))

            elif choice == '3':
                url = self.get_user_input("URL cible", self.target_url or "https://example.com")
                if url:
                    if not url.startswith(('http://', 'https://')):
                        url = 'https://' + url
                    self.target_url = url
                    self.target_domain = urlparse(url).netloc
                    self.results = self._empty_results()
                    site_dir = f"{self.config['output_dir']}/{self.target_domain}"
                    os.makedirs(site_dir, exist_ok=True)
                    self.forced_browse(url, site_dir)
                input(self.colorize("\nAppuyez sur Entree...", 'blue'))

            elif choice == '4':
                self.change_target()

            elif choice == '5':
                self.download_specific_file()

            elif choice == '6':
                self.show_results()
                input(self.colorize("\nAppuyez sur Entree...", 'blue'))

            elif choice == '7':
                self.show_sensitive_files()
                input(self.colorize("\nAppuyez sur Entree...", 'blue'))

            elif choice == '8':
                self.show_databases()
                input(self.colorize("\nAppuyez sur Entree...", 'blue'))

            elif choice == '9':
                self.show_forced_browse_hits()
                input(self.colorize("\nAppuyez sur Entree...", 'blue'))

            elif choice == '10':
                self.show_security_info()
                input(self.colorize("\nAppuyez sur Entree...", 'blue'))

            elif choice == '11':
                self.export_results()

            elif choice == '12':
                self.show_config()

            elif choice == '13':
                self.show_statistics()
                input(self.colorize("\nAppuyez sur Entree...", 'blue'))

            elif choice == '14':
                self.show_help()

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