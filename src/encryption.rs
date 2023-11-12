use openssl::pkcs5::pbkdf2_hmac;
use openssl::hash::MessageDigest;
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::error::ErrorStack;
use serde_json::Result;
use std::io::{Read, Write};
use std::fs::File;
use openssl::rand::rand_bytes;

const ITERATIONS: usize = 100_000;
const KEY_LENGTH: usize = 32;
const IV_LENGTH: usize = 16;
const SALT_LENGTH: usize = 16;

pub struct CryptoManager {
    salt:  Vec<u8>,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    key: Vec<u8>,
    password: String,
    filepath: String
}

impl CryptoManager {

    pub fn new(filepath: &str, password: &str) -> Result<Self, Box<dyn std::error::Error>> {

        let mut file = File::open(filepath)?;
        match File::open(filepath) {
            Ok(mut file) => {
                let mut salt = vec![0u8; SALT_LENGTH];
                file.read_exact(&mut salt)?;

                let mut iv = vec![0u8; IV_LENGTH];
                file.read_exact(&mut iv)?;

                let mut ciphertext = Vec::new();
                file.read_to_end(&mut ciphertext)?;

                let key = CryptoManager::generate_key(password, &salt)?;

                Ok(CryptoManager { 
                    salt,
                    iv,
                    ciphertext,
                    password: password.to_string(),
                    key,
                    filepath
                })

            }
            Err(_) => {
                let salt = CryptoManager::generate_salt(SALT_LENGTH)?;
                let iv = CryptoManager::generate_iv(IV_LENGTH)?;
                let key = CryptoManager::generate_key(password, salt)?;

                Ok(CryptoManager { 
                    salt,
                    iv,
                    ciphertext: Vec::new(),
                    password: password.to_string(),
                    key
                })
            }
        }

    }

    pub fn encrypt_and_persist(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let encrypted_data = self.encrypt_data(data)?;
        self.ciphertext = encrypted_data;  // Store the encrypted data in the struct
        let mut file = File::create(&self.filepath)?;
        file.write_all(&self.salt)?;
        file.write_all(&self.iv)?;
        file.write_all(&self.ciphertext)?;
        Ok(())
    }

    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let cipher = Cipher::aes_256_cbc();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &self.key, Some(&self.iv))?;
        crypter.pad(true);

        let mut encrypted = vec![0; data.len() + cipher.block_size()];
        let count = crypter.update(data, &mut encrypted)?;
        let rest = crypter.finalize(&mut encrypted[count..])?;
        encrypted.truncate(count + rest);
        Ok(encrypted)
    }

    pub fn decrypt_and_retrieve(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if self.ciphertext.is_empty() {
            return Err("No ciphertext available to decrypt".into());
        }

        let decrypted_data = self.decrypt_data(&self.ciphertext)?;
        Ok(decrypted_data)
    }

    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let cipher = Cipher::aes_256_cbc();
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, &self.key, Some(&self.iv))?;
        crypter.pad(true);

        let mut decrypted = vec![0; encrypted_data.len() + cipher.block_size()];
        let count = crypter.update(encrypted_data, &mut decrypted)?;
        let rest = crypter.finalize(&mut decrypted[count..])?;
        decrypted.truncate(count + rest);
        Ok(decrypted)
    }

    fn generate_salt(length: usize) -> Result<Vec<u8>, ErrorStack> {
        let mut buffer = vec![0u8; length];
        rand_bytes(&mut buffer)?;
        Ok(buffer)
    }

    fn generate_iv() -> Result<Vec<u8>, ErrorStack> {
        let mut buffer = vec![0u8; 16]; //should match AES block size
        rand_bytes(&mut buffer)?;
        Ok(buffer)
    }

    fn generate_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let password_bytes = password.as_bytes();
        let mut key = vec![0u8; KEY_LENGTH];
        pbkdf2_hmac(password_bytes, salt, ITERATIONS, MessageDigest::sha256(), &mut key)?;
        Ok(key)
    }

}

// ENCRYPTING
// 1. collect password
// 2. create random salt of fixed length ( if creating new file ) else use one on file itself
// 3. feed KDF the salt and pass to generate DERIVED KEY ( OF FIXED LENGTH ) 
// 4. feed encryption alg the IV and DERIVED KEY to produce CIPHERTEXT
// 5. write [SALT][IV][CIPHERTEXT] to file

// DECRYPTING
// 1. collect SALT/IV/CIPHERTEXT from file
// 2. use SALT / PASS to generate DERIVED KEY
// 3. use DERIVED KEY and IV to generate PLAINTEXT from CIPHERTEXT
//
//
// NOTES
// create salt only on file creation
// NEW IV EVERYTIME REQUIRED
// Not everything should be public right? 
