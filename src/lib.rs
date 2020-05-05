//! Simple library that allows to easily encrypt and decrypt data with a secret key using sodium.

use sodiumoxide::crypto::pwhash::{argon2id13, argon2id13::Salt, argon2id13::SALTBYTES};
use sodiumoxide::crypto::secretbox::{self, Key, Nonce, KEYBYTES, MACBYTES, NONCEBYTES};
use thiserror::Error;

/// Encrypt data with an argon2id13 derived key of the given passphrase and a random nonce.
///
/// Recturns a Vec<u8> of the encrypted data with salt and nonce prepended.
///
/// Anatomy of the returned byte vector:
///
/// |index  |usage|
/// |-------|-----|
/// |0 - 15 |salt |
/// |16 - 39|nonce|
/// |40 - 55|mac  |
/// |56 -   |data |
///
/// ## Examples
///
/// ```rust
/// # use simplecrypt::encrypt;
/// #
/// let plaintext = "lord ferris says: you shall not use Go";
/// let key = "lul no generics";
///
/// let encrypted_data_with_nonce = encrypt(plaintext.as_bytes(), key.as_bytes());
/// ```
pub fn encrypt(data: &[u8], passphrase: &[u8]) -> Vec<u8> {
    sodiumoxide::init().expect("unable to init sodium");

    let (key, salt) = derive_new_key(passphrase);
    let nonce = secretbox::gen_nonce();
    let encrypted_data = secretbox::seal(data, &nonce, &key);

    // build a new vec with the hash salt and the nonce prepended.
    {
        let mut output = Vec::new();
        output.extend_from_slice(salt.0.as_ref());
        output.extend_from_slice(nonce.0.as_ref());
        output.extend_from_slice(encrypted_data.as_slice());
        output
    }
}

/// Decrypt the given data with the argon2id13 deriviation of the passphrase.
/// Returns the decrypted data on success, or an empty tuple on failure.
///
/// The given byte slice is interpreted like this:
///
/// |index  |usage|
/// |-------|-----|
/// |0 - 15 |salt |
/// |16 - 39|nonce|
/// |40 - 55|mac  |
/// |56 -   |data |
///
/// ## Examples
///
/// ```rust
/// # use simplecrypt::decrypt;
/// #
/// let encrypted_data = [
///     // salt
///     169, 41, 29, 81, 36, 11, 117, 33, 247, 2, 145, 245, 198, 17, 216, 16, 67, 46, 223, 109,
///     57, 110, 209, 163, 185, 122, 239, 245, 174, 208, 142, 227, // nonce
///     139, 139, 32, 147, 90, 92, 168, 229, 127, 92, 65, 153, 127, 38, 125, 144, 115, 104, 101,
///     187, 207, 130, 203, 39, // actual data
///     109, 12, 45, 42, 204, 139, 17, 130, 30, 97, 142, 213, 183, 126, 152, 226, 251, 225, 134,
///     201, 192, 202, 226, 71, 115, 95, 152, 71, 69, 246, 165, 147, 251, 106, 86, 47, 89, 30,
/// ];
///
/// assert_eq!(
///     Ok("lord ferris says: you shall not use Go".as_bytes().to_vec()),
///     decrypt(&encrypted_data, "lul no generics".as_bytes())
/// );
/// ```
pub fn decrypt(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, DecryptionError> {
    sodiumoxide::init().expect("unable to init sodium");

    // the first 16 bytes are interpreted as salt
    if data.len() < SALTBYTES {
        return Err(DecryptionError::IncompleteSalt(data.len()));
    }

    // the next 24 bytes after the salt are interpreted as nonce
    if data.len() < SALTBYTES + NONCEBYTES {
        return Err(DecryptionError::IncompleteNonce(data.len()));
    }

    // the next 16 bytes after the nonce are interpreted as MAC
    if data.len() < SALTBYTES + NONCEBYTES + MACBYTES {
        return Err(DecryptionError::IncompleteMac(data.len()));
    }

    // unwrapping is ok here because we already checked the length of the slice before.
    let salt = Salt::from_slice(&data[..SALTBYTES]).unwrap();
    let nonce = Nonce::from_slice(&data[SALTBYTES..SALTBYTES + NONCEBYTES]).unwrap();
    let data = &data[SALTBYTES + NONCEBYTES..];
    let key = derive_key(passphrase, salt);

    secretbox::open(data, &nonce, &key).map_err(|_| DecryptionError::Decryption)
}

/// Represents an error that can occur during decryption.
#[derive(Error, Debug, Eq, PartialEq)]
pub enum DecryptionError {
    /// Used if the data slice is too short so it can't contain a valid salt.
    #[error("expected a {} byte at index {} but only got {0} bytes", 0, SALTBYTES)]
    IncompleteSalt(usize),

    /// Used if the data slice is too short so it can't contain a valid nonce.
    #[error(
        "expected a {} byte nonce at index {} but only got {} bytes",
        NONCEBYTES,
        SALTBYTES,
        .0 - SALTBYTES
    )]
    IncompleteNonce(usize),

    /// Used if the data slice is too short so it can't contain a valid MAC.
    #[error(
        "expected a {} byte nonce at index {} but only got {} bytes",
        MACBYTES,
        NONCEBYTES + SALTBYTES,
        .0 - NONCEBYTES - SALTBYTES
    )]
    IncompleteMac(usize),

    /// Used if the data can't decrypted either because the key or the data slice are invalid.
    #[error("invalid data or secret key")]
    Decryption,
}

/// Derives a kew from the given passphrase with a random salt.
///
/// Returns a tuple containing the derived key and the generated salt
fn derive_new_key(passphrase: &[u8]) -> (Key, Salt) {
    let salt = argon2id13::gen_salt();
    let key = derive_key(passphrase, salt);

    (key, salt)
}

/// Convenience wrapper around argon2id13::derive_key
fn derive_key(passphrase: &[u8], salt: Salt) -> Key {
    let mut key = Key([0u8; KEYBYTES]);
    let Key(ref mut buffer) = key;

    argon2id13::derive_key(
        buffer,
        passphrase,
        &salt,
        argon2id13::OPSLIMIT_INTERACTIVE,
        argon2id13::MEMLIMIT_INTERACTIVE,
    )
    .unwrap(); // nothing can go wrong at this point, so we can unwrap.
    key
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    pub fn test_encrypt() {
        let text = "lord ferris says: you shall not use Go";
        let key = "lul no generics";

        let _encrypted_data = encrypt(text.as_bytes(), key.as_bytes());
    }

    #[test]
    pub fn test_encrypt_empty_data() {
        let data = Vec::new();
        let key = "some key";

        let encrypted_data = encrypt(data.as_slice(), key.as_bytes());

        // salt, nonce and mac must exist even if the given data slice was empty.
        assert_eq!(SALTBYTES + NONCEBYTES + MACBYTES, encrypted_data.len());
    }

    #[test]
    pub fn test_decrypt() {
        let encrypted_data = [
            // salt
            169, 41, 29, 81, 36, 11, 117, 33, 247, 2, 145, 245, 198, 17, 216, 16, 67, 46, 223, 109,
            57, 110, 209, 163, 185, 122, 239, 245, 174, 208, 142, 227, // nonce
            139, 139, 32, 147, 90, 92, 168, 229, 127, 92, 65, 153, 127, 38, 125, 144, 115, 104,
            101, 187, 207, 130, 203, 39, // actual data
            109, 12, 45, 42, 204, 139, 17, 130, 30, 97, 142, 213, 183, 126, 152, 226, 251, 225,
            134, 201, 192, 202, 226, 71, 115, 95, 152, 71, 69, 246, 165, 147, 251, 106, 86, 47, 89,
            30,
        ];

        assert_eq!(
            Ok("lord ferris says: you shall not use Go".as_bytes().to_vec()),
            decrypt(&encrypted_data, "lul no generics".as_bytes())
        );
    }

    #[test]
    pub fn test_decrypt_with_incomplete_salt() {
        const DATA_LENGTH: usize = 12;
        let data = [11u8; DATA_LENGTH];

        assert_eq!(
            Err(DecryptionError::IncompleteSalt(DATA_LENGTH)),
            decrypt(&data, "foo".as_bytes())
        )
    }

    #[test]
    pub fn test_decrypt_with_incomplete_nonce() {
        const DATA_LENGTH: usize = 30;
        let data = [11u8; DATA_LENGTH];

        assert_eq!(
            Err(DecryptionError::IncompleteNonce(DATA_LENGTH)),
            decrypt(&data, "foo".as_bytes())
        )
    }

    #[test]
    pub fn test_decrypt_with_incomplete_mac() {
        const DATA_LENGTH: usize = 50;
        let data = [11u8; DATA_LENGTH];

        assert_eq!(
            Err(DecryptionError::IncompleteMac(DATA_LENGTH)),
            decrypt(&data, "foo".as_bytes())
        )
    }
}
