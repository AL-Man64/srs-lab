use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    pub master_password_salt: String,
    pub nonce: Option<String>,
    pub challenge_string: Option<String>,
    pub tag: Option<String>,
    pub entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Entry {
    pub nonce: String,
    pub data: String,
    pub tag: String,
}

pub type DecryptedVault = HashMap<String, String>;
