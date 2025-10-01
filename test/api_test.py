
# Archivo: tests/test_api.py

import pytest
import requests
import json
import os
import random
import string

# --- CONFIGURACIÓN DE LAS PRUEBAS ---

# Carga la configuración del cliente para obtener la URL y el token
try:
    with open("client_config.json", "r") as f:
        config = json.load(f)
    BASE_URL = config["server_url"]
    API_TOKEN = config["api_token"]
    AUTH_HEADER = {"Authorization": f"Bearer {API_TOKEN}"}
except FileNotFoundError:
    print("\nERROR: No se encontró 'client_config.json'. Asegúrate de que exista para correr las pruebas.")
    exit(1)


def test_unauthorized_access():
    url = f"{BASE_URL}/files"
    response = requests.get(url)
    
    assert response.status_code == 401
    
    error_json = response.json()
    assert error_json["code"] == "AUTH_REQUIRED"


def test_invalid_token_access():
    url = f"{BASE_URL}/files"
    invalid_header = {"Authorization": "Bearer token-falso"}
    response = requests.get(url, headers=invalid_header)
    
    assert response.status_code == 401
    assert response.json()["code"] == "TOKEN_INVALID"


def test_file_lifecycle():
    """
    Prueba el ciclo de vida completo de un archivo:
    1. Sube un archivo.
    2. Verifica que aparece en la lista.
    3. Descarga el archivo y verifica su contenido.
    4. Borra el archivo.
    5. Verifica que ya no aparece en la lista.
    """
    
    random_name = ''.join(random.choices(string.ascii_lowercase, k=10)) + ".txt"
    random_content = "Contenido de prueba aleatorio: " + ''.join(random.choices(string.ascii_letters, k=20))
    
    upload_url = f"{BASE_URL}/files/{random_name}"
    
    print(f"\n[TEST] Subiendo '{random_name}'...")
    upload_response = requests.post(upload_url, data=random_content.encode('utf-8'), headers=AUTH_HEADER)
    assert upload_response.status_code == 201 

    print(f"[TEST] Verificando que '{random_name}' está en la lista...")
    list_response = requests.get(f"{BASE_URL}/files", headers=AUTH_HEADER)
    assert list_response.status_code == 200
    file_list = list_response.json()
    assert random_name in file_list

    print(f"[TEST] Descargando '{random_name}' y verificando contenido...")
    download_response = requests.get(upload_url, headers=AUTH_HEADER)
    assert download_response.status_code == 200
    assert download_response.content == random_content.encode('utf-8')

    print(f"[TEST] Borrando '{random_name}'...")
    delete_response = requests.delete(upload_url, headers=AUTH_HEADER)
    assert delete_response.status_code == 200

    print(f"[TEST] Verificando que '{random_name}' ya no está en la lista...")
    final_list_response = requests.get(f"{BASE_URL}/files", headers=AUTH_HEADER)
    assert final_list_response.status_code == 200
    final_file_list = final_list_response.json()
    assert random_name not in final_file_list
