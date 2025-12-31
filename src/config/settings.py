"""Configuración global de la tool"""
import os
from pathlib import Path

# Directorios
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR.parent / 'database'
DB_PATH = DATA_DIR / 'scan_results.db'
PORTS_FILE = DATA_DIR / 'ports.json'

DEFAULT_TIMEOUT = 5

# Configuración de Nmap
NMAP_ARGS = "-sV -T4"  #Argumentos por defecto para Nmap
DATA_DIR.mkdir(exist_ok=True)
