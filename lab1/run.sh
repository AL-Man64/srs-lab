#!/usr/bin/bash

# Program je pisan u Rust programskom jeziku

# Korištene zavisnosti (specificirane u ./Cargo.toml)
# clap - Parsiranje argumenata naredbenog retka
# hex - Pretvaranje iz binarnih u hex reprezentacije i obratno
# rand - Stvaranje nasumičnih salt-ova i nonce-ova
# rust-crypto - Kriptografske funkcije, glavni "radni konj" programa
# serde i serde_json - De/serijalizacija podataka u json koji se sprema na disk

# Instaliranje cargo paketa ako već nije instaliran (Ubuntu 22.04 ili bilo koji
# Debian-temeljen sustav)

apt update && apt install -y cargo

# Komplajliranje programa i premještanje u radni direktorij (cargo automatski
# dohvaća zavisnosti)

# dodati --release zastavicu za dodatne optimizacije
cargo build
# mv ./target/release/... za optimiziranu izvršnu datoteku
mv ./target/debug/tajnik ./

# Sučelje jednako primjerom danom u zadatku, pokretanje tog primjera:

echo "Inicijalizacija baze (spremljene u ~/pm_vault.json)"
./tajnik init mAsterPasswrd
echo "Dodavanje zaporke"
./tajnik put mAsterPasswrd www.fer.hr neprobojnAsifrA
echo "Dohvaćanje zaporke"
./tajnik get mAsterPasswrd www.fer.hr
echo "Dohvaćanje zaporke s pogrešnom glavnom zaporkom"
./tajnik get wrongPasswrd www.fer.hr

# Još par naredbi, slučaj nepostojeće zaporke:

echo "Zaporka ne postoji u bazi"
./tajnik get mAsterPasswrd discord.com
echo "Ubacivanje tražene zaporke"
# Ne koristim ovu šifru, generirana je za primjer BitWarden-om ;)
./tajnik put mAsterPasswrd discord.com tC7wLMQAUk46wgfSr3b5avbk
echo "Dohvaćanje zaporke koja sad postoji"
./tajnik get mAsterPasswrd discord.com
