//! # Lab 1 - Simetrična kriptografija
//!
//! ## Funkcionalni zahtjevi
//!
//! 1. Inicijalizacija alata odnosno stvaranje prazne baze zaporki.
//! 2. Pohrana para adresa, zaporka. Ako je već pohranjena zaporka pod istom adresom onda ju je
//!    potrebno zamijeniti sa zadanom.
//! 3. Dohvaćanje pohranjene zaporke za zadanu adresu.
//!
//! Primjer korištenja:
//!
//! ```bash
//! $ ./tajnik init mAsterPasswrd
//! Password manager initialized.
//! $ ./tajnik put mAsterPasswrd www.fer.hr neprobojnAsifrA
//! Stored password for www.fer.hr
//! $ ./tajnik get mAsterPasswrd www.fer.hr
//! Password for www.fer.hr is: neprobojnAsifrA.
//! $ ./tajnik get wrongPasswrd www.fer.hr
//! Master password incorrect or integrity check failed.
//! ```
//!
//! ## Sigurnosni Zahtjevi
//!
//! 1. Povjerljivost zaporki: napadač ne može odrediti nikakve informacije o zaporkama, čak niti
//!    njihovu duljinu, čak ni jesu li zaporke za dvije adrese jednake, čak ni je li nova zaporka
//!    jednaka staroj kada se promijeni
//! 2. Povjerljivost adresa: napadač ne može odrediti nikakve informacije o adresama, osim da zna
//!    koliko se različitih adresa nalazi u bazi
//! 3. Integritet adresa i zaporki: nije moguće da korisnik dobije od alata zaporku za određenu
//!    adresu, ako prethodno nije unio točno tu zaporku za točno tu adresu. Obratite pažnju na
//!    napad zamijene: napadač ne smije moći zamijeniti zaporku određene adrese zaporkom neke druge
//!    adrese.
//!
//! ## Zadatci
//!
//! 1. Samostalno istražite što su to funkcije za derivaciju ključa (key derivation function), koje
//!    sigurnosne zahtjeve moraju zadovoljavati, te kako se koriste kako bi od zaporke dobili jedan
//!    ili više kriptografskih ključeva.
//! 2. Dizajnirajte  i opišite alat za baratanje zaporkama koji zadovoljava gore opisane
//!    funkcionalne i sigurnosne zahtjeve. Dokumentirajte na koji se točno način podaci zaštićuju
//!    prilikom spremanja na disk i na koji se točno način provjerava zaštita prilikom čitanja s
//!    diska. Obratite pažnju i dokumentirajte postupke generiranja ključeva odnosno deriviranja
//!    ključeva iz zaporke.
//!
//! ## Često postavljena pitanja
//!
//! - Kako spremiti glavnu zaporku?
//!
//!   Glavnu zaporku (niti njen hash) nije niti potrebno niti poželjno spremati u bilo kojem
//!   obliku. Posljedično, nije potrebno razlikovati slučaj kada je unesena pogrešna glavna zaporka
//!   od slučaja kada je na neki način narušen integritet datoteke.
//!
//! - Što napraviti ako se dva puta inicijalizira prazna baza zaporki?
//!
//!   Odaberite sami razumno ponašanje. Na primjer, dozvoljeno je da prilikom inizijalizacije
//!   brišete sve stare podatke i počinjete sa praznom bazom i sa potencijalno novom glavnom
//!   zaporkom.

use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::{env, fs};

use clap::Parser;
use cli::{Cli, Commands};
use crypto::aead::AeadDecryptor;
use crypto::{
    aead::AeadEncryptor,
    aes::KeySize,
    aes_gcm::AesGcm,
    scrypt::{scrypt, ScryptParams},
};
use rand::random;
use vault::{DecryptedVault, Vault};

use crate::vault::Entry;

mod cli;
mod vault;

const INTEGRITY_RESULT: Result<(), &str> =
    Err("Master password incorrect or integrity check failed.");

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { master_password } => init(&master_password),
        Commands::Put {
            master_password,
            address,
            password,
        } => put(&master_password, &address, &password),
        Commands::Get {
            master_password,
            address,
        } => {
            let pass = get(&master_password, &address)?;
            println!("{pass}");
            Ok(())
        }
    }?;

    Ok(())
}

/// Initializes the password manager
fn init(master_password: &str) -> Result<(), Box<dyn Error>> {
    let salt = generate_random_bytes(16);
    let mut key = [0; 16];

    // Koristi PBKDF2 "under the hood", te ima malo jednostavniji API
    scrypt(
        master_password.as_bytes(),
        &salt,
        &ScryptParams::new(12, 8, 4),
        &mut key,
    );

    let nonce = generate_random_bytes(12);

    let (challenge_string, tag) = aes_gcm_encrypt(&key, &nonce, &generate_random_bytes(12));

    let vault = Vault {
        master_password_salt: hex::encode(salt),
        // For first authentication post-initialization, store a challenge string
        nonce: Some(hex::encode(nonce)),
        challenge_string: Some(challenge_string),
        tag: Some(tag),
        entries: Vec::new(),
    };

    let data = serde_json::to_vec(&vault)?;

    let mut file = File::create(get_vault_path()?)?;
    file.write_all(&data)?;

    Ok(())
}

/// Puts a value into the password manager
fn put(master_password: &str, address: &str, password: &str) -> Result<(), Box<dyn Error>> {
    let data = fs::read_to_string(get_vault_path()?)?;

    let mut vault: Vault = serde_json::from_str(&data)?;
    let mut key = [0; 16];

    scrypt(
        master_password.as_bytes(),
        &hex::decode(vault.master_password_salt.clone())?,
        &ScryptParams::new(12, 8, 4),
        &mut key,
    );

    if vault.entries.is_empty() {
        aes_gcm_decrypt(
            &key,
            &vault.nonce.clone().unwrap(),
            &vault.challenge_string.clone().unwrap(),
            &vault.tag.clone().unwrap(),
        )?;

        vault.nonce = None;
        vault.challenge_string = None;
        vault.tag = None;
    }

    decrypt_vault(&key, &vault)?;

    let mut existing_data = -1;
    for (i, Entry { nonce, data, tag }) in vault.entries.iter().enumerate() {
        let output = aes_gcm_decrypt(&key, nonce, data, tag)?;

        let addr_length = output[62] as usize;
        let pass_length = output[63] as usize;

        let addr = String::from_utf8(output[0..addr_length].to_vec())?;
        let pass = String::from_utf8(output[addr_length..(addr_length + pass_length)].to_vec())?;

        if addr == address {
            existing_data = i;
        }
    }

    if existing_data >= 0 {
        vault.entries.remove(existing_data);
    }

    let mut data: Vec<_> = address.bytes().chain(password.bytes()).collect();

    if data.len() > 62 {
        Err("address length and password length are too big, make sure that they are 62 bytes or lower")?;
    }
    while data.len() < 62 {
        data.push(random());
    }
    data.push(address.len() as u8);
    data.push(password.len() as u8);

    let nonce = generate_random_bytes(12);
    let (data, tag) = aes_gcm_encrypt(&key, &nonce, &data);

    vault.entries.push(Entry {
        nonce: hex::encode(nonce),
        data,
        tag,
    });

    let data = serde_json::to_string(&vault)?;
    fs::write(get_vault_path()?, data)?;

    Ok(())
}

/// Gets a value from the password manager
fn get(master_password: &str, address: &str) -> Result<String, Box<dyn Error>> {
    let data = fs::read_to_string(get_vault_path()?)?;

    let vault: Vault = serde_json::from_str(&data)?;
    let mut key = [0; 16];

    scrypt(
        master_password.as_bytes(),
        &hex::decode(vault.master_password_salt.clone())?,
        &ScryptParams::new(12, 8, 4),
        &mut key,
    );

    if vault.entries.is_empty() {
        aes_gcm_decrypt(
            &key,
            &vault.nonce.clone().unwrap(),
            &vault.challenge_string.clone().unwrap(),
            &vault.tag.clone().unwrap(),
        )?;

        Err("Vault empty")?;
    }

    let decrypted_vault = decrypt_vault(&key, &vault)?;
    if let Some(password) = decrypted_vault.get(address) {
        return Ok(password.to_owned());
    }

    Err("Entry does not exist")?
}

fn get_vault_path() -> Result<String, env::VarError> {
    Ok(env::var("HOME").or(env::var("userprofile"))? + "/pm_vault.json")
}

fn decrypt_vault(key: &[u8], vault: &Vault) -> Result<DecryptedVault, Box<dyn Error>> {
    let mut decrypted_vault = DecryptedVault::new();

    for Entry { nonce, data, tag } in &vault.entries {
        let output = aes_gcm_decrypt(key, nonce, data, tag)?;

        let addr_length = output[62] as usize;
        let pass_length = output[63] as usize;

        let addr = String::from_utf8(output[0..addr_length].to_vec())?;
        let pass = String::from_utf8(output[addr_length..(addr_length + pass_length)].to_vec())?;

        decrypted_vault.insert(addr, pass);
    }

    Ok(decrypted_vault)
}

fn generate_random_bytes(len: u8) -> Vec<u8> {
    let mut salt = Vec::new();
    for _ in 0..len {
        salt.push(random());
    }
    salt
}

fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], source: &[u8]) -> (String, String) {
    let mut output = vec![0; source.len()];
    let mut tag = vec![0; 16];

    let mut aes_gcm = AesGcm::new(KeySize::KeySize128, key, nonce, &[0; 0] /* no aad */);
    aes_gcm.encrypt(source, &mut output, &mut tag);

    (hex::encode(output), hex::encode(tag))
}

fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &str,
    cipher: &str,
    tag: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let nonce = hex::decode(nonce)?;
    let cipher = hex::decode(cipher)?;
    let tag = hex::decode(tag)?;

    let mut output = vec![0; cipher.len()];

    let mut aes_gcm = AesGcm::new(KeySize::KeySize128, key, &nonce, &[0; 0] /* no aad */);
    if !aes_gcm.decrypt(&cipher, &mut output, &tag) {
        INTEGRITY_RESULT?;
    };

    Ok(output)
}
