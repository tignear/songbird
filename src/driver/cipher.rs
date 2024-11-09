use aead::{AeadInPlace as _, Error as CryptoError, KeySizeUser};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::XChaCha20Poly1305;
use crypto_secretbox::XSalsa20Poly1305;
#[derive(Clone)]
pub enum Cipher {
    XSalsa20(XSalsa20Poly1305),
    XChaCha20(XChaCha20Poly1305),
    Aes256Gcm(Box<Aes256Gcm>),
}

impl Cipher {
    pub fn encrypt_in_place_detached(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Ok(match self {
            Self::XSalsa20(inner) => inner
                .encrypt_in_place_detached(
                    crypto_secretbox::Nonce::from_slice(nonce),
                    associated_data,
                    buffer,
                )?
                .to_vec(),
            Self::XChaCha20(inner) => inner
                .encrypt_in_place_detached(
                    chacha20poly1305::XNonce::from_slice(nonce),
                    associated_data,
                    buffer,
                )?
                .to_vec(),
            Self::Aes256Gcm(inner) => inner
                .encrypt_in_place_detached(
                    aes_gcm::Nonce::from_slice(nonce),
                    associated_data,
                    buffer,
                )?
                .to_vec(),
        })
    }
    pub fn decrypt_in_place_detached(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        match self {
            Self::XSalsa20(inner) => {
                inner.decrypt_in_place_detached(
                    crypto_secretbox::Nonce::from_slice(nonce),
                    associated_data,
                    buffer,
                    crypto_secretbox::Tag::from_slice(tag),
                )?;
                Ok(())
            },
            Self::XChaCha20(inner) => {
                inner.decrypt_in_place_detached(
                    chacha20poly1305::XNonce::from_slice(nonce),
                    associated_data,
                    buffer,
                    chacha20poly1305::Tag::from_slice(tag),
                )?;
                Ok(())
            },
            Self::Aes256Gcm(inner) => {
                inner.decrypt_in_place_detached(
                    aes_gcm::Nonce::from_slice(nonce),
                    associated_data,
                    buffer,
                    aes_gcm::Tag::from_slice(tag),
                )?;
                Ok(())
            },
        }
    }
    pub fn key_size(&self) -> usize {
        match self {
            Cipher::XSalsa20(_) => XSalsa20Poly1305::key_size(),
            Cipher::XChaCha20(_) => XChaCha20Poly1305::key_size(),
            Cipher::Aes256Gcm(_) => Aes256Gcm::key_size(),
        }
    }
}
