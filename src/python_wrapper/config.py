import json
import sys

CONFIG_PATH = "config.json"
EXPECTED_KEYS = ["server_port", "storage_directory", "api_secret_token"]

def load_config():
    print("Cargando configuracion...")

    try:
        with open(CONFIG_PATH, "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"Error: No se encontro el archivo de configuracion '{CONFIG_PATH}'")
        print("Por favor, crea el archivo 'config.json' en la raiz del proyecto")
        sys.exit(1)

    for key in EXPECTED_KEYS:
        if key not in config:
            print(f"Error: La clave requerida 'key' no se encontro en {CONFIG_PATH}")
            sys.exit(1)

    print("Configuracion cargada y validada")
    return config
    
