#!/bin/bash
set -e

echo "=== Instalando dependencias ==="
pip install -r requirements.txt

echo "=== Migrando base de datos ==="
python manage.py migrate --noinput

echo "=== Recolectando archivos estaticos ==="
python manage.py collectstatic --noinput

echo "=== Cargando datos iniciales ==="
python manage.py seed_data

echo "=== Build completado ==="
