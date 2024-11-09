//! Encryption schemes supported by Discord's secure RTP negotiation.
use super::Cipher;
use aead::AeadCore;
use aes_gcm::Aes256Gcm;
use byteorder::{NetworkEndian, WriteBytesExt};
use chacha20poly1305::XChaCha20Poly1305;
use crypto_secretbox::{Error as CryptoError, KeyInit as _, XSalsa20Poly1305};
use discortp::{rtp::RtpPacket, MutablePacket};
use rand::Rng;
use std::num::Wrapping;

/// Variants of the `XSalsa20Poly1305` encryption scheme.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CryptoMode {
    /// The RTP header is used as the source of nonce bytes for the packet.
    ///
    /// Equivalent to a nonce of at most 48b (6B) at no extra packet overhead:
    /// the RTP sequence number and timestamp are the varying quantities.
    #[deprecated]
    Normal,
    /// An additional random 24B suffix is used as the source of nonce bytes for the packet.
    /// This is regenerated randomly for each packet.
    ///
    /// Full nonce width of 24B (192b), at an extra 24B per packet (~1.2 kB/s).
    #[deprecated]
    Suffix,
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// Nonce width of 4B (32b), at an extra 4B per packet (~0.2 kB/s).
    #[deprecated]
    Lite,
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// Nonce width of 4B (32b), at an extra 4B per packet (~0.2 kB/s).
    XChaCha20,
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// Nonce width of 4B (32b), at an extra 4B per packet (~0.2 kB/s).
    Aes256Gcm,
}

impl From<CryptoState> for CryptoMode {
    fn from(val: CryptoState) -> Self {
        match val {
            #[allow(deprecated)]
            CryptoState::Normal => Self::Normal,
            #[allow(deprecated)]
            CryptoState::Suffix => Self::Suffix,
            #[allow(deprecated)]
            CryptoState::Lite(_) => Self::Lite,
            CryptoState::Aes256Gcm(_) => Self::Aes256Gcm,
            CryptoState::XChaCha20(_) => Self::XChaCha20,
        }
    }
}

impl CryptoMode {
    /// Returns the name of a mode as it will appear during negotiation.
    #[must_use]
    pub fn to_request_str(self) -> &'static str {
        match self {
            #[allow(deprecated)]
            Self::Normal => "xsalsa20_poly1305",
            #[allow(deprecated)]
            Self::Suffix => "xsalsa20_poly1305_suffix",
            #[allow(deprecated)]
            Self::Lite => "xsalsa20_poly1305_lite",
            Self::Aes256Gcm => "aead_aes256_gcm_rtpsize",
            Self::XChaCha20 => "aead_xchacha20_poly1305_rtpsize",
        }
    }

    /// Returns the nonce length in bytes required by algorithm.
    #[must_use]
    pub const fn algorithm_nonce_size(self) -> usize {
        use typenum::Unsigned as _;
        match self {
            #[allow(deprecated)]
            Self::Lite | Self::Normal | Self::Suffix => XSalsa20Poly1305::NONCE_SIZE,
            Self::XChaCha20 => <XChaCha20Poly1305 as AeadCore>::NonceSize::USIZE, // => 24
            Self::Aes256Gcm => <Aes256Gcm as AeadCore>::NonceSize::USIZE,         // => 12
        }
    }

    /// Returns the number of bytes each nonce is stored as within
    /// a packet.
    #[must_use]
    pub const fn nonce_size(self) -> usize {
        match self {
            #[allow(deprecated)]
            Self::Normal => RtpPacket::minimum_packet_size(),
            #[allow(deprecated)]
            Self::Suffix => XSalsa20Poly1305::NONCE_SIZE,
            #[allow(deprecated)]
            Self::Lite | Self::Aes256Gcm | Self::XChaCha20 => 4,
        }
    }
    /// Returns the number of bytes occupied by the encryption scheme
    /// which fall before the payload.
    #[must_use]
    pub const fn payload_prefix_len(self) -> usize {
        match self {
            #[allow(deprecated)]
            Self::Lite | Self::Normal | Self::Suffix => XSalsa20Poly1305::TAG_SIZE,
            Self::XChaCha20 | Self::Aes256Gcm => 0,
        }
    }
    /// Returns the tag length in bytes.
    #[must_use]
    pub const fn tag_size(self) -> usize {
        use typenum::Unsigned as _;
        match self {
            #[allow(deprecated)]
            Self::Lite | Self::Normal | Self::Suffix => XSalsa20Poly1305::TAG_SIZE,
            Self::XChaCha20 => <XChaCha20Poly1305 as AeadCore>::TagSize::USIZE, // => 16
            Self::Aes256Gcm => <Aes256Gcm as AeadCore>::TagSize::USIZE,         // => 16
        }
    }

    /// Returns the number of bytes occupied by the encryption scheme
    /// which fall after the payload.
    #[must_use]
    pub const fn payload_suffix_len(self) -> usize {
        match self {
            #[allow(deprecated)]
            Self::Normal => 0,
            #[allow(deprecated)]
            Self::Suffix | Self::Lite => self.nonce_size(),
            Self::Aes256Gcm | Self::XChaCha20 => self.tag_size() + self.nonce_size(),
        }
    }

    /// Calculates the number of additional bytes required compared
    /// to an unencrypted payload.
    #[must_use]
    pub const fn payload_overhead(self) -> usize {
        self.tag_size() + self.nonce_size()
    }

    /// Extracts the byte slice in a packet used as the nonce, and the remaining mutable
    /// portion of the packet.
    fn nonce_slice<'a>(
        self,
        header: &'a [u8],
        body: &'a mut [u8],
    ) -> Result<(&'a [u8], &'a mut [u8]), CryptoError> {
        match self {
            #[allow(deprecated)]
            Self::Normal => Ok((header, body)),
            #[allow(deprecated)]
            Self::Suffix | Self::Lite | Self::Aes256Gcm | Self::XChaCha20 => {
                let len = body.len();
                if len < self.nonce_size() {
                    Err(CryptoError)
                } else {
                    let (body_left, nonce_loc) = body.split_at_mut(len - self.nonce_size());
                    Ok((nonce_loc, body_left))
                }
            },
        }
    }

    #[cfg(any(feature = "receive", test))]
    /// Decrypts a Discord RT(C)P packet using the given key.
    ///
    /// If successful, this returns the number of bytes to be ignored from the
    /// start and end of the packet payload.
    #[inline]
    pub(crate) fn decrypt_in_place(
        self,
        packet: &mut impl MutablePacket,
        cipher: &Cipher,
    ) -> Result<(usize, usize), CryptoError> {
        // FIXME on next: packet encrypt/decrypt should use an internal error
        //  to denote "too small" vs. "opaque".
        let extension_size = (packet.packet()[0] as usize >> 4 & 1) * 4;
        let header_len = packet.packet().len() - packet.payload().len() + extension_size;
        let (header, body) = packet.packet_mut().split_at_mut(header_len);
        let (slice_to_use, body_remaining) = self.nonce_slice(header, body)?;
        let mut nonce = vec![0; self.algorithm_nonce_size()];
        let nonce_slice = if slice_to_use.len() == self.algorithm_nonce_size() {
            slice_to_use
        } else {
            let max_bytes_avail = slice_to_use.len();
            nonce[..self.nonce_size().min(max_bytes_avail)].copy_from_slice(slice_to_use);
            &nonce
        };
        match self {
            #[allow(deprecated)]
            Self::Lite | Self::Normal | Self::Suffix => {
                let body_start = self.tag_size();
                let body_tail = self.payload_suffix_len();

                if body_start > body_remaining.len() {
                    return Err(CryptoError);
                }

                let (tag_bytes, data_bytes) = body_remaining.split_at_mut(body_start);

                cipher
                    .decrypt_in_place_detached(nonce_slice, b"", data_bytes, tag_bytes)
                    .map(|()| (body_start, body_tail))
            },
            Self::Aes256Gcm | Self::XChaCha20 => {
                let body_tail = self.payload_suffix_len();

                if self.tag_size() > body_remaining.len() {
                    return Err(CryptoError);
                }

                let (data_bytes, tag_bytes) =
                    body_remaining.split_at_mut(body_remaining.len() - self.tag_size());
                cipher
                    .decrypt_in_place_detached(nonce_slice, header, data_bytes, tag_bytes)
                    .map(|()| (extension_size + self.payload_prefix_len(), body_tail))
            },
        }
    }

    /// Encrypts a Discord RT(C)P packet using the given key.
    ///
    /// Use of this requires that the input packet has had a nonce generated in the correct location,
    /// and `payload_len` specifies the number of bytes after the header including this nonce.
    #[inline]
    pub fn encrypt_in_place(
        self,
        packet: &mut impl MutablePacket,
        cipher: &Cipher,
        payload_len: usize,
    ) -> Result<(), CryptoError> {
        let header_len = packet.packet().len() - packet.payload().len();
        let (header, body) = packet.packet_mut().split_at_mut(header_len);
        let (slice_to_use, body_remaining) = self.nonce_slice(header, &mut body[..payload_len])?;

        let mut nonce = vec![0; self.algorithm_nonce_size()];
        let nonce_slice = if slice_to_use.len() == self.algorithm_nonce_size() {
            slice_to_use
        } else {
            nonce[..self.nonce_size()].copy_from_slice(slice_to_use);
            &nonce
        };
        match self {
            #[allow(deprecated)]
            Self::Lite | Self::Normal | Self::Suffix => {
                // body_remaining is now correctly truncated by this point.
                // the true_payload to encrypt follows after the first TAG_LEN bytes.
                let tag = cipher.encrypt_in_place_detached(
                    nonce_slice,
                    b"",
                    &mut body_remaining[XSalsa20Poly1305::TAG_SIZE..],
                )?;
                body_remaining[..XSalsa20Poly1305::TAG_SIZE].copy_from_slice(&tag[..]);

                Ok(())
            },
            Self::Aes256Gcm | Self::XChaCha20 => {
                // tag follows the data.
                let body_len = body_remaining.len();
                let tag = cipher.encrypt_in_place_detached(
                    nonce_slice,
                    header,
                    &mut body_remaining[..body_len - self.tag_size()],
                )?;
                body_remaining[body_len - self.tag_size()..].copy_from_slice(&tag);
                Ok(())
            },
        }
    }
    /// Create a Cipher for the mode.
    pub fn new_cipher(self, key: &[u8]) -> Cipher {
        use aead::KeySizeUser as _;
        match self {
            #[allow(deprecated)]
            CryptoMode::Lite | CryptoMode::Normal | CryptoMode::Suffix => Cipher::XSalsa20(
                XSalsa20Poly1305::new_from_slice(&key[..XSalsa20Poly1305::KEY_SIZE]).unwrap(),
            ),
            CryptoMode::Aes256Gcm => {
                Cipher::Aes256Gcm(Aes256Gcm::new_from_slice(&key[..Aes256Gcm::key_size()]).unwrap())
            },
            CryptoMode::XChaCha20 => Cipher::XChaCha20(
                XChaCha20Poly1305::new_from_slice(&key[..XChaCha20Poly1305::key_size()]).unwrap(),
            ),
        }
    }
}

/// State used in nonce generation for the `XSalsa20Poly1305` encryption variants
/// in [`CryptoMode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CryptoState {
    /// The RTP header is used as the source of nonce bytes for the packet.
    ///
    /// No state is required.
    #[deprecated = "This will be discontinued by discord on November 18th, 2024."]
    Normal,
    /// An additional random 24B suffix is used as the source of nonce bytes for the packet.
    /// This is regenerated randomly for each packet.
    ///
    /// No state is required.
    #[deprecated = "This will be discontinued by discord on November 18th, 2024."]
    Suffix,
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// The last used nonce is stored.
    #[deprecated = "This will be discontinued by discord on November 18th, 2024."]
    Lite(Wrapping<u32>),
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// The RTP encryption range is determined dynamically and the header is validated as AEAD.
    ///
    /// The last used nonce is stored.
    Aes256Gcm(Wrapping<u32>),
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// The RTP encryption range is determined dynamically and the header is validated as AEAD.
    ///
    /// The last used nonce is stored.
    XChaCha20(Wrapping<u32>),
}

impl From<CryptoMode> for CryptoState {
    fn from(val: CryptoMode) -> Self {
        match val {
            #[allow(deprecated)]
            CryptoMode::Normal => CryptoState::Normal,
            #[allow(deprecated)]
            CryptoMode::Suffix => CryptoState::Suffix,
            #[allow(deprecated)]
            CryptoMode::Lite => CryptoState::Lite(Wrapping(rand::random::<u32>())),
            CryptoMode::Aes256Gcm => CryptoState::Aes256Gcm(Wrapping(rand::random::<u32>())),
            CryptoMode::XChaCha20 => CryptoState::XChaCha20(Wrapping(rand::random::<u32>())),
        }
    }
}

impl CryptoState {
    /// Writes packet nonce into the body, if required, returning the new length.
    pub fn write_packet_nonce(
        &mut self,
        packet: &mut impl MutablePacket,
        payload_end: usize,
    ) -> usize {
        let mode = self.kind();
        let endpoint = payload_end + mode.nonce_size();

        match self {
            #[allow(deprecated)]
            Self::Suffix => {
                rand::thread_rng().fill(&mut packet.payload_mut()[payload_end..endpoint]);
            },
            #[allow(deprecated)]
            Self::Lite(mut i) => {
                (&mut packet.payload_mut()[payload_end..endpoint])
                    .write_u32::<NetworkEndian>(i.0)
                    .expect(
                        "Nonce size is guaranteed to be sufficient to write u32 for lite tagging.",
                    );
                i += Wrapping(1);
            },
            Self::Aes256Gcm(mut i) => {
                (&mut packet.payload_mut()[payload_end..endpoint])
                    .write_u32::<NetworkEndian>(i.0)
                    .expect(
                        "Nonce size is guaranteed to be sufficient to write u32 for lite tagging.",
                    );
                i += Wrapping(1);
            },
            Self::XChaCha20(mut i) => {
                (&mut packet.payload_mut()[payload_end..endpoint])
                    .write_u32::<NetworkEndian>(i.0)
                    .expect(
                        "Nonce size is guaranteed to be sufficient to write u32 for lite tagging.",
                    );
                i += Wrapping(1);
            },
            _ => {},
        }

        endpoint
    }

    /// Returns the underlying (stateless) type of the active crypto mode.
    #[must_use]
    pub fn kind(self) -> CryptoMode {
        CryptoMode::from(self)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crypto_secretbox::{KeyInit, XSalsa20Poly1305};
    use discortp::rtp::MutableRtpPacket;

    #[test]
    fn small_packet_decrypts_error() {
        let mut buf = [0u8; MutableRtpPacket::minimum_packet_size()];
        let modes = [
            #[allow(deprecated)]
            CryptoMode::Normal,
            #[allow(deprecated)]
            CryptoMode::Suffix,
            #[allow(deprecated)]
            CryptoMode::Lite,
            CryptoMode::Aes256Gcm,
            CryptoMode::XChaCha20,
        ];
        let mut pkt = MutableRtpPacket::new(&mut buf[..]).unwrap();

        let cipher = Cipher::XSalsa20(
            XSalsa20Poly1305::new_from_slice(&[1u8; XSalsa20Poly1305::KEY_SIZE]).unwrap(),
        );

        for mode in modes {
            // AIM: should error, and not panic.
            assert!(mode.decrypt_in_place(&mut pkt, &cipher).is_err());
        }
    }

    #[test]
    #[allow(deprecated)]
    fn symmetric_encrypt_decrypt_xsalsa20() {
        const TRUE_PAYLOAD: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut buf = [0u8; MutableRtpPacket::minimum_packet_size()
            + TRUE_PAYLOAD.len()
            + XSalsa20Poly1305::TAG_SIZE
            + XSalsa20Poly1305::NONCE_SIZE];
        let modes = [CryptoMode::Normal, CryptoMode::Lite, CryptoMode::Suffix];

        for mode in modes {
            buf.fill(0);
            let cipher = mode.new_cipher(&[7u8; XSalsa20Poly1305::KEY_SIZE]);
            let mut pkt = MutableRtpPacket::new(&mut buf[..]).unwrap();
            let mut crypto_state = CryptoState::from(mode);
            let payload = pkt.payload_mut();
            payload[XSalsa20Poly1305::TAG_SIZE..XSalsa20Poly1305::TAG_SIZE + TRUE_PAYLOAD.len()]
                .copy_from_slice(&TRUE_PAYLOAD[..]);

            let final_payload_size = crypto_state
                .write_packet_nonce(&mut pkt, XSalsa20Poly1305::TAG_SIZE + TRUE_PAYLOAD.len());

            let enc_succ = mode.encrypt_in_place(&mut pkt, &cipher, final_payload_size);

            assert!(enc_succ.is_ok());

            let final_pkt_len = MutableRtpPacket::minimum_packet_size() + final_payload_size;
            let mut pkt = MutableRtpPacket::new(&mut buf[..final_pkt_len]).unwrap();

            assert!(mode.decrypt_in_place(&mut pkt, &cipher).is_ok());
        }
    }

    #[test]
    fn symmetric_encrypt_decrypt_tag_after_data() {
        const TRUE_PAYLOAD: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        for mode in [CryptoMode::Aes256Gcm, CryptoMode::XChaCha20] {
            let mut buf = vec![
                0u8;
                MutableRtpPacket::minimum_packet_size()
                    + TRUE_PAYLOAD.len()
                    + mode.nonce_size()
                    + mode.tag_size()
            ];

            buf.fill(0);
            let cipher = mode.new_cipher(&[7u8; 32]);
            let mut pkt = MutableRtpPacket::new(&mut buf[..]).unwrap();
            let mut crypto_state = CryptoState::from(mode);
            let payload = pkt.payload_mut();
            payload[mode.payload_prefix_len()..TRUE_PAYLOAD.len()].copy_from_slice(&TRUE_PAYLOAD);

            let final_payload_size =
                crypto_state.write_packet_nonce(&mut pkt, TRUE_PAYLOAD.len() + mode.tag_size());

            let enc_succ = mode.encrypt_in_place(&mut pkt, &cipher, final_payload_size);

            assert!(enc_succ.is_ok());

            let final_pkt_len = MutableRtpPacket::minimum_packet_size() + final_payload_size;
            let mut pkt = MutableRtpPacket::new(&mut buf[..final_pkt_len]).unwrap();

            assert!(mode.decrypt_in_place(&mut pkt, &cipher).is_ok());
        }
    }
}
