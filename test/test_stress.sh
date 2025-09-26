#!/bin/bash

PORT=8080
HOST="http://127.0.0.1:$PORT"
ENDPOINT="/encrypt"

#Test de peticiones en fila
echo "Test de 10 peticiones concurrentes"
for i in {1..10}; do
  curl -X POST --data "MENSAJE DE PRUEBA $i" "$HOST$ENDPOINT" &
done
wait
echo -e "Test de concurrencia finalizado"

#Test de carga de datos de mayor peso
echo "Test de carga de datos"
echo "Enviando 1MB de datos binarios aleatorios..."
head -c 1M /dev/urandom | curl -X POST --data-binary @- "$HOST$ENDPOINT" > /dev/null

echo "Enviando 100MB de datos binarios aleatorios..."
head -c 100M /dev/urandom | curl -X POST --data-binary @- "$HOST$ENDPOINT" > /dev/null

echo "Enviando 1000MB de datos binarios aleatorios..."
head -c 1000M /dev/urandom | curl -X POST --data-binary @- "$HOST$ENDPOINT" > /dev/null

echo "Test de stress basico terminado"
