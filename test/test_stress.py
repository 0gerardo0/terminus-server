import requests
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed 
from tqdm import tqdm

URL = "http://127.0.0.1:8080/encrypt"
NUM_CONCURRENT_REQUEST = 50

def test_concurrency():
    print(f"Iniciado test de {NUM_CONCURRENT_REQUEST} peticiones concurrentes")

    def send_request(i):
        data = f"mensaje prueba con muchos valores que tiene que encriptar {i}".encode('utf-8')
        response = requests.post(URL, data=data, timeout=10)
        return response.status_code
    

    with ThreadPoolExecutor(max_workers=NUM_CONCURRENT_REQUEST) as executor:
        futures = [executor.submit(send_request, i) for i in range(NUM_CONCURRENT_REQUEST)]

        results = {}

        for future in tqdm(as_completed(futures), total=len(futures)):
            status = future.result()
            results[status] = results.get(status, 0) + 1 

    print("Resultados de test de concurrencia")
    for status, count in results.items():
        print(f"Codigo de estatus '{status}': {count} veces")
        print("- "*30) 

def test_large_payload(size_mb):
    print(f"test de carga con {size_mb}MB")

    random_data = os.urandom(size_mb * 1024 * 1024)
    star_time =  time.perf_counter()
    print("datos generados")
    response = requests.post(URL, data=random_data, headers={'Content-Type': 'application/octet-stream'}, timeout=60)
    print(f"Respuesta del servidor: {response.status_code}")
    print(f"Tamaño de la respuesta cifrada (hex): {len(response.text)}")
    end_time = time.perf_counter()

    duration_ms = (end_time - star_time) * 1000
    print(f" peticiones de gran carga tardo: {duration_ms} ms\n")

if __name__ == "__main__":
    test_concurrency()
    test_large_payload(1)
    test_large_payload(100)
    test_large_payload(1000)
