use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::secretbox::{self, Key, Nonce, NONCEBYTES};

/// Encrypt data with an sha256 hash of the given key and a random nonce.
/// Returns a tuple consisting of the encrypted data and the none.
///
/// ## Examples
///
/// ```rust
/// # use simplecrypt::encrypt;
/// #
/// let plaintext = "lord ferris says: you shall not use Go";
/// let key = "lul no generics";
///
/// let (encrypted_data, nonce) = encrypt(plaintext.as_bytes(), key.as_bytes());
/// ```
pub fn encrypt(data: &[u8], key: &[u8]) -> (Vec<u8>, [u8; NONCEBYTES]) {
    let hash = sha256::hash(key);
    let key = Key::from_slice(&hash.0).unwrap();
    let nonce = secretbox::gen_nonce();

    (secretbox::seal(data, &nonce, &key), nonce.0)
}

/// Decrypt the given data with an sha256 hash of key and the given nonce.
/// Returns the decrypted data on success, or an empty tuple on failure.
///
/// ## Examples
///
/// ```rust
/// # use simplecrypt::decrypt;
/// #
/// let encrypted_data = [
///     223, 47, 127, 93, 39, 196, 103, 252, 223, 19, 142, 53, 15, 219, 26, 76, 50, 78, 102, 3,
///     85, 91, 187, 139, 184, 188, 45, 134, 131, 94, 199, 119, 145, 110, 200, 77, 116, 245,
///     45, 208, 44, 201, 53, 157, 160, 225, 30, 229, 70, 170, 39, 8, 176, 160,
/// ];
///
/// let nonce = [
///     227, 227, 184, 154, 147, 122, 233, 133, 176, 232, 211, 37, 253, 44, 16, 185, 91, 73,
///     46, 217, 93, 28, 239, 222,
/// ];
///
/// assert_eq!(
///     Ok("lord ferris says: you shall not use Go".as_bytes().to_vec()),
///     decrypt(&encrypted_data, "lul no generics".as_bytes(), &nonce)
/// );
/// ```
///
pub fn decrypt(data: &[u8], key: &[u8], nonce: &[u8; NONCEBYTES]) -> Result<Vec<u8>, ()> {
    let hash = sha256::hash(key);
    let key = Key::from_slice(&hash.0).unwrap();
    let nonce = Nonce::from_slice(nonce).unwrap();

    secretbox::open(data, &nonce, &key)
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    pub fn test_encrypt() {
        let text = "lord ferris says: you shall not use Go";
        let key = "lul no generics";

        let (encrypted_data, nonce) = encrypt(text.as_bytes(), key.as_bytes());
    }

    #[test]
    pub fn test_decrypt() {
        let encrypted_data = [
            223, 47, 127, 93, 39, 196, 103, 252, 223, 19, 142, 53, 15, 219, 26, 76, 50, 78, 102, 3,
            85, 91, 187, 139, 184, 188, 45, 134, 131, 94, 199, 119, 145, 110, 200, 77, 116, 245,
            45, 208, 44, 201, 53, 157, 160, 225, 30, 229, 70, 170, 39, 8, 176, 160,
        ];

        let nonce = [
            227, 227, 184, 154, 147, 122, 233, 133, 176, 232, 211, 37, 253, 44, 16, 185, 91, 73,
            46, 217, 93, 28, 239, 222,
        ];

        assert_eq!(
            Ok("lord ferris says: you shall not use Go".as_bytes().to_vec()),
            decrypt(&encrypted_data, "lul no generics".as_bytes(), &nonce)
        );
    }
}
