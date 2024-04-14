#!/usr/bin/bash

# Nije nužno, ali korak koji svakako preferiram izvršiti jest stvaranje python
# virtualnog okruženja
# Programi imaju shebang koji očekuje virtualno okruženje, što dodatno olakšava
# pokretanje ako je ono stvoreno
python3 -m venv venv

# Preuzimanje ovisnosti
venv/bin/pip install -r requirements.txt

# Učiniti datoteke izvršnim, ako to već nije slučaj
chmod +x usermgmt.py
chmod +x login.py

# Primjeri iz opisa funkcionalnih zahtjeva
echo "./usermgmt.py add sgros"
./usermgmt.py add sgros

echo "./usermgmt.py passwd sgros"
./usermgmt.py passwd sgros

echo "./usermgmt.py forcepass sgros"
./usermgmt.py forcepass sgros

echo "./usermgmt.py del sgros"
./usermgmt.py del sgros

echo "./login.py sgros"
./login.py sgros
