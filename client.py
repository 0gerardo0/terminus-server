from ast import arg
import os
import sys
import json
import requests
import argparse

CONFIG_FILE = "client_config.json"

def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)

        if "server_url" not in config or "api_token" not in config:
            print(f"Error: El archivo '{CONFIG_FILE} debe de contener 'server_url' y 'api_token'")
            sys.exit(1)

        return config
    except FileNotFoundError:
        print(f"Error: No se encontro el archivo de configuracion '{CONFIG_FILE}")
        #Hay que poner en documentacion cual es el formato de la configuracion
        sys.exit(1)
        


def handle_list(config):

    print("Solicitando lista de archivos al servidor")
    headers = {"Authorization": f"Bearer {config['api_token']}"}
    try:
        response = requests.get(f"{config['server_url']}/files", headers = headers)
        if response.status_code == 200:
            files = response.json()
            print("Archivos en el servidor")
            if not files:
                print("  (No hay archivos)")
            else:
                for filename in files:
                    print(f" - {filename}")
        else:
            print(f"Error del servidor: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error de conexion: {e}")

def handle_upload(config, local_path, remote_name):

    print(f"Subiendo '{local_path}' como '{remote_name}'")
    if  not os.path.exists(local_path):
        print(f"Error: El archivo local '{local_path}' no existe")

    headers = {"Authorization": f"Bearer {config['api_token']}"}
    url = f"{config['server_url']}/files/{remote_name}"

    try:
        with open(local_path) as f:
            file_content = f.read()

        response = requests.post(url, data=file_content, headers=headers)
        
        if response.status_code == 201:
            print(f"{response.text}")
        else:
            print(f"Error del servidor: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error de conexion: {e}")

def handle_download(config, local_path, remote_name):
    print(f"Descargando '{remote_name}' como '{local_path}'...")
    headers = {"Authorization": f"Bearer {config['api_token']}"}
    url = f"{config['server_url']}/files/{remote_name}"

    try:
        response = requests.get(url, headers=headers, stream=True)
        if response.status_code == 200:
            with open(local_path, "wb") as f:
                f.write(response.content)
            print(f"Archivo descargado en '{local_path}'.")
        else:
            print(f"Error del servidor: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error de conexión: {e}")

def handle_delete(config, remote_name):
    print(f"Solicitando borrar '{remote_name}'...")
    headers = {"Authorization": f"Bearer {config['api_token']}"}
    url = f"{config['server_url']}/files/{remote_name}"
    
    try:
        response = requests.delete(url, headers=headers)
        if response.status_code == 200:
            print(f"{response.text}")
        else:
            print(f"Error del servidor: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error de conexión: {e}")

def main():
    config = load_config()

    parser =  argparse.ArgumentParser(description="Cliente para el servidor Terminus")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Comandos disponibles")
    
    parser_list = subparsers.add_parser("list", aliases=["ls"], help="Lista los archivos en el servidor")

    parser_upload = subparsers.add_parser("upload", aliases=["upload"], help="Sube un archivos al servidor")
    parser_upload.add_argument("local_path", help="Ruta al archivo local que se va a subir")
    parser_upload.add_argument("remote_name", help="Nombre que tendra el archivo en el servidor")

    parser_download = subparsers.add_parser("download", help="Descarga un archivo del servidor.")
    parser_download.add_argument("remote_name", help="Nombre del archivo en el servidor.")
    parser_download.add_argument("local_path", help="Ruta donde se guardará el archivo descargado.")

    parser_delete = subparsers.add_parser("delete", aliases=["rm"], help="Borra un archivo del servidor.")
    parser_delete.add_argument("remote_name", help="Nombre del archivo a borrar en el servidor.")

    args = parser.parse_args()

    if args.command == "list" or args.command == "ls":
        handle_list(config)
    elif args.command == "upload":
        handle_upload(config, args.local_path, args.remote_name)
    elif args.command == "download":
        handle_download(config, args.local_path, args.remote_name)
    elif args.command == "delete" or args.command == "rm":
        handle_delete(config, args.remote_name)

if __name__ == "__main__":
    main()
