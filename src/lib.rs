//! Simple library that allows to easily encrypt and decrypt data with a secret key using sodium.

use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::secretbox::{self, Key, Nonce, MACBYTES, NONCEBYTES};
use thiserror::Error;

/// Encrypt data with an sha256 hash of the given key and a random nonce.
///
/// Recturns a Vec<u8> of the encrypted data with a 24 byte nonce prepended.
///
/// Anatomy of the returned vector:
///
/// |index  |usage|
/// |-------|-----|
/// |0 - 23 |nonce|
/// |24 - 40|mac  |
/// |41 -   |data |
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
pub fn encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    sodiumoxide::init().expect("unable to init sodium");

    let hash = sha256::hash(key);
    let key = Key::from_slice(&hash.0).unwrap();
    let nonce = secretbox::gen_nonce();
    let encrypted_data = secretbox::seal(data, &nonce, &key);

    // build a new vec with the nonce prepended.
    {
        let mut output = Vec::new();
        output.extend_from_slice(nonce.0.as_ref());
        output.extend_from_slice(encrypted_data.as_slice());
        output
    }
}

/// Decrypt the given data with an sha256 hash of key.
/// Returns the decrypted data on success, or an empty tuple on failure.
///
/// The given data slice is interpreted like this:
///
/// |index  |usage|
/// |-------|-----|
/// |0 - 23 |nonce|
/// |24 - 40|mac  |
/// |41 -   |data |
///
/// ## Examples
///
/// ```rust
/// # use simplecrypt::decrypt;
/// #
/// let encrypted_data = [
///     // nonce
///     227, 227, 184, 154, 147, 122, 233, 133, 176, 232, 211, 37, 253, 44, 16, 185, 91, 73,
///     46, 217, 93, 28, 239, 222,
///     // mac
///     223, 47, 127, 93, 39, 196, 103, 252, 223, 19, 142, 53, 15,
///     219, 26, 76,
///     // actual data
///     50, 78, 102, 3, 85, 91, 187, 139, 184, 188, 45, 134, 131, 94, 199, 119,
///     145, 110, 200, 77, 116, 245, 45, 208, 44, 201, 53, 157, 160, 225, 30, 229, 70, 170,
///     39, 8, 176, 160,
/// ];
///
/// assert_eq!(
///     Ok("lord ferris says: you shall not use Go".as_bytes().to_vec()),
///     decrypt(&encrypted_data, "lul no generics".as_bytes())
/// );
/// ```
pub fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, DecryptionError> {
    sodiumoxide::init().expect("unable to init sodium");

    let hash = sha256::hash(key);
    let key = Key::from_slice(&hash.0).unwrap();

    // the first 24 bytes are interpreted as nonce
    if data.len() < NONCEBYTES {
        return Err(DecryptionError::IncompleteNonce(data.len()));
    }

    // the next 16 bytes after the nonce are interpreted as MAC
    if data.len() < NONCEBYTES + MACBYTES {
        return Err(DecryptionError::IncompleteMac(data.len()));
    }

    // unwrapping is ok here because we already checked the length of the slice before.
    let nonce = Nonce::from_slice(&data[..NONCEBYTES]).unwrap();
    let data = &data[NONCEBYTES..];

    secretbox::open(data, &nonce, &key).map_err(|_| DecryptionError::Decryption)
}

/// Represents an error that can occur during decryption.
#[derive(Error, Debug, Eq, PartialEq)]
pub enum DecryptionError {
    #[error(
        "expected a {} byte nonce at index {} but only got {0} bytes",
        0,
        NONCEBYTES
    )]
    IncompleteNonce(usize),
    #[error(
        "expected a {} byte nonce at index {} but only got {} bytes",
        MACBYTES,
        NONCEBYTES,
        .0 - NONCEBYTES
    )]
    IncompleteMac(usize),
    #[error("invalid data or secret key")]
    Decryption,
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
    pub fn test_decrypt() {
        let encrypted_data = [
            // nonce
            227, 227, 184, 154, 147, 122, 233, 133, 176, 232, 211, 37, 253, 44, 16, 185, 91, 73, 46,
            217, 93, 28, 239, 222, // mac
            223, 47, 127, 93, 39, 196, 103, 252, 223, 19, 142, 53, 15, 219, 26, 76,
            // actual data
            50, 78, 102, 3, 85, 91, 187, 139, 184, 188, 45, 134, 131, 94, 199, 119, 145, 110, 200,
            77, 116, 245, 45, 208, 44, 201, 53, 157, 160, 225, 30, 229, 70, 170, 39, 8, 176, 160,
        ];

        assert_eq!(
            Ok("lord ferris says: you shall not use Go".as_bytes().to_vec()),
            decrypt(&encrypted_data, "lul no generics".as_bytes())
        );
    }

    #[test]
    pub fn test_decrypt_with_incomplete_nonce() {
        const DATA_LENGTH: usize = 20;
        let data = [11u8; DATA_LENGTH];

        assert_eq!(
            Err(DecryptionError::IncompleteNonce(DATA_LENGTH)),
            decrypt(&data, "foo".as_bytes())
        )
    }

    #[test]
    pub fn test_decrypt_with_incomplete_mac() {
        const DATA_LENGTH: usize = 30;
        let data = [11u8; DATA_LENGTH];

        assert_eq!(
            Err(DecryptionError::IncompleteMac(DATA_LENGTH)),
            decrypt(&data, "foo".as_bytes())
        )
    }
}
