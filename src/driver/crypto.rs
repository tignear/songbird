//! Encryption schemes supported by Discord's secure RTP negotiation.
use super::tasks::error::Error as InternalError;
use aead::AeadCore;
use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit};
use byteorder::{NetworkEndian, WriteBytesExt};
use chacha20poly1305::XChaCha20Poly1305;
use crypto_secretbox::{cipher::InvalidLength, Error as CryptoError, XSalsa20Poly1305};
#[cfg(feature = "receive")]
use discortp::rtcp::MutableRtcpPacket;
use discortp::{rtp::RtpPacket, MutablePacket};
#[cfg(any(feature = "receive", test))]
use discortp::{
    rtp::{MutableRtpPacket, RtpExtensionPacket},
    Packet,
};
use rand::Rng;
use std::{num::Wrapping, str::FromStr};
use typenum::Unsigned;

use crate::error::ConnectionError;

/// Variants of the `XSalsa20Poly1305` encryption scheme.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default, Hash)]
#[non_exhaustive]
pub enum CryptoMode {
    #[default]
    /// Discord's currently preferred non-E2EE encryption scheme.
    ///
    /// Packets are encrypted and decrypted using the `AES256GCM` encryption scheme.
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// Encrypted content begins *after* the RTP header and extensions, following the SRTP
    /// specification.
    ///
    /// Nonce width of 4B (32b), at an extra 4B per packet (~0.2 kB/s).
    Aes256Gcm,
    /// A fallback non-E2EE encryption scheme.
    ///
    /// Packets are encrypted and decrypted using the `XChaCha20Poly1305` encryption scheme.
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// Encrypted content begins *after* the RTP header and extensions, following the SRTP
    /// specification.
    ///
    /// Nonce width of 4B (32b), at an extra 4B per packet (~0.2 kB/s).
    XChaCha20Poly1305,
    #[deprecated(
        since = "0.4.4",
        note = "This voice encryption mode will no longer be accepted by Discord\
                as of 2024-11-18. This variant will be removed in `v0.5`."
    )]
    /// The RTP header is used as the source of nonce bytes for the packet.
    ///
    /// Equivalent to a nonce of at most 48b (6B) at no extra packet overhead:
    /// the RTP sequence number and timestamp are the varying quantities.
    Normal,
    #[deprecated(
        since = "0.4.4",
        note = "This voice encryption mode will no longer be accepted by Discord\
                as of 2024-11-18. This variant will be removed in `v0.5`."
    )]
    /// An additional random 24B suffix is used as the source of nonce bytes for the packet.
    /// This is regenerated randomly for each packet.
    ///
    /// Full nonce width of 24B (192b), at an extra 24B per packet (~1.2 kB/s).
    Suffix,
    #[deprecated(
        since = "0.4.4",
        note = "This voice encryption mode will no longer be accepted by Discord\
                as of 2024-11-18. This variant will be removed in `v0.5`."
    )]
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// Nonce width of 4B (32b), at an extra 4B per packet (~0.2 kB/s).
    Lite,
}

#[allow(deprecated)]
impl From<CryptoState> for CryptoMode {
    fn from(val: CryptoState) -> Self {
        match val {
            CryptoState::Normal => Self::Normal,
            CryptoState::Suffix => Self::Suffix,
            CryptoState::Lite(_) => Self::Lite,
            CryptoState::Aes256Gcm(_) => Self::Aes256Gcm,
            CryptoState::XChaCha20Poly1305(_) => Self::XChaCha20Poly1305,
        }
    }
}

/// The input string could not be parsed as an encryption scheme supported by songbird.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct UnrecognisedCryptoMode;

impl FromStr for CryptoMode {
    type Err = UnrecognisedCryptoMode;

    #[allow(deprecated)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "aead_aes256_gcm_rtpsize" => Ok(Self::Aes256Gcm),
            "aead_xchacha20_poly1305_rtpsize" => Ok(Self::XChaCha20Poly1305),
            "xsalsa20_poly1305" => Ok(Self::Normal),
            "xsalsa20_poly1305_suffix" => Ok(Self::Suffix),
            "xsalsa20_poly1305_lite" => Ok(Self::Lite),
            _ => Err(UnrecognisedCryptoMode),
        }
    }
}

#[allow(deprecated)]
impl CryptoMode {
    /// Returns the underlying crypto algorithm used by a given [`CryptoMode`].
    #[must_use]
    pub(crate) const fn algorithm(self) -> EncryptionAlgorithm {
        match self {
            CryptoMode::Aes256Gcm => EncryptionAlgorithm::Aes256Gcm,
            CryptoMode::XChaCha20Poly1305 => EncryptionAlgorithm::XChaCha20Poly1305,
            CryptoMode::Normal | CryptoMode::Suffix | CryptoMode::Lite =>
                EncryptionAlgorithm::XSalsa20Poly1305,
        }
    }

    /// Returns whether this [`CryptoMode`] dynamically sizes the ciphertext region
    /// to begin in the middle of RTP extensions.
    ///
    /// Compliant SRTP would leave all extensions in cleartext, hence 'more' SRTP
    /// compliant.
    #[must_use]
    #[cfg(any(feature = "receive", test))]
    pub(crate) const fn is_more_srtp_compliant(self) -> bool {
        match self {
            CryptoMode::Aes256Gcm | CryptoMode::XChaCha20Poly1305 => true,
            CryptoMode::Normal | CryptoMode::Suffix | CryptoMode::Lite => false,
        }
    }

    /// Returns an encryption cipher based on the supplied key.
    ///
    /// Creation fails if the key is the incorrect length for the target cipher.
    pub(crate) fn cipher_from_key(self, key: &[u8]) -> Result<Cipher, InvalidLength> {
        match self.algorithm() {
            EncryptionAlgorithm::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map(Box::new)
                .map(Cipher::Aes256Gcm),
            EncryptionAlgorithm::XChaCha20Poly1305 =>
                XChaCha20Poly1305::new_from_slice(key).map(Cipher::XChaCha20Poly1305),
            EncryptionAlgorithm::XSalsa20Poly1305 =>
                XSalsa20Poly1305::new_from_slice(key).map(|v| Cipher::XSalsa20Poly1305(v, self)),
        }
    }

    /// Returns a local priority score for a given [`CryptoMode`].
    ///
    /// Higher values are preferred.
    #[must_use]
    pub(crate) fn priority(self) -> u64 {
        match self {
            CryptoMode::Aes256Gcm => 4,
            CryptoMode::XChaCha20Poly1305 => 3,
            CryptoMode::Normal => 2,
            CryptoMode::Suffix => 1,
            CryptoMode::Lite => 0,
        }
    }

    /// Returns the best available crypto mode, given the `modes` offered by the Discord voice server.
    ///
    /// If `preferred` is set and the mode exists in the server's supported algorithms, then that
    /// mode will be chosen. Otherwise we select the highest-scoring option which is mutually understood.
    pub(crate) fn negotiate<It, T>(
        modes: It,
        preferred: Option<Self>,
    ) -> Result<Self, ConnectionError>
    where
        T: AsRef<str>,
        It: IntoIterator<Item = T>,
    {
        let mut best = None;
        for el in modes {
            let Ok(el) = CryptoMode::from_str(el.as_ref()) else {
                // Unsupported mode. Ignore.
                continue;
            };

            let mut el_priority = el.priority();
            if let Some(preferred) = preferred {
                if el == preferred {
                    el_priority = u64::MAX;
                }
            }

            let accept = match best {
                None => true,
                Some((_, score)) if el_priority > score => true,
                _ => false,
            };

            if accept {
                best = Some((el, el_priority));
            }
        }

        best.map(|(v, _)| v)
            .ok_or(ConnectionError::CryptoModeUnavailable)
    }

    /// Returns the name of a mode as it will appear during negotiation.
    #[must_use]
    pub fn to_request_str(self) -> &'static str {
        match self {
            Self::Normal => "xsalsa20_poly1305",
            Self::Suffix => "xsalsa20_poly1305_suffix",
            Self::Lite => "xsalsa20_poly1305_lite",
            Self::Aes256Gcm => "aead_aes256_gcm_rtpsize",
            Self::XChaCha20Poly1305 => "aead_xchacha20_poly1305_rtpsize",
        }
    }

    /// Returns the nonce length in bytes required by algorithm.
    #[must_use]
    pub const fn algorithm_nonce_size(self) -> usize {
        use typenum::Unsigned as _;
        match self {
            Self::Lite | Self::Normal | Self::Suffix => XSalsa20Poly1305::NONCE_SIZE,
            Self::XChaCha20Poly1305 => <XChaCha20Poly1305 as AeadCore>::NonceSize::USIZE, // => 24
            Self::Aes256Gcm => <Aes256Gcm as AeadCore>::NonceSize::USIZE,                 // => 12
        }
    }

    /// Returns the number of bytes each nonce is stored as within
    /// a packet.
    #[must_use]
    pub const fn nonce_size(self) -> usize {
        match self {
            Self::Aes256Gcm | Self::XChaCha20Poly1305 | Self::Lite => 4,
            Self::Normal => RtpPacket::minimum_packet_size(),
            Self::Suffix => XSalsa20Poly1305::NONCE_SIZE,
        }
    }

    /// Returns the number of bytes occupied by the XSalsa20Poly1305
    /// encryption schemes which fall before the payload.
    #[must_use]
    #[deprecated(
        since = "0.4.4",
        note = "This method returns the fixed payload prefix for older encryption modes,\
                which will no longer be accepted by Discord as of 2024-11-18. It is an\
                implementation detail and will be removed in `v0.5`."
    )]
    pub fn payload_prefix_len() -> usize {
        XSalsa20Poly1305::TAG_SIZE
    }

    /// Returns the number of bytes occupied by the encryption scheme
    /// which fall before the payload.
    ///
    /// Method name duplicated until v0.5, to prevent breaking change.
    #[must_use]
    pub(crate) const fn payload_prefix_len2(self) -> usize {
        match self {
            CryptoMode::Aes256Gcm | CryptoMode::XChaCha20Poly1305 => 0,
            CryptoMode::Normal | CryptoMode::Suffix | CryptoMode::Lite =>
                XSalsa20Poly1305::TAG_SIZE,
        }
    }

    /// Returns the tag length in bytes.
    #[must_use]
    pub(crate) const fn encryption_tag_len(self) -> usize {
        self.algorithm().encryption_tag_len()
    }

    /// Returns the number of bytes occupied by the encryption scheme
    /// which fall after the payload.
    #[must_use]
    pub const fn payload_suffix_len(self) -> usize {
        match self {
            Self::Normal => 0,
            Self::Suffix | Self::Lite => self.nonce_size(),
            Self::Aes256Gcm | Self::XChaCha20Poly1305 =>
                self.nonce_size() + self.encryption_tag_len(),
        }
    }

    /// Returns the number of bytes occupied by an encryption scheme's tag which
    /// fall *after* the payload.
    #[must_use]
    pub const fn tag_suffix_len(self) -> usize {
        match self {
            Self::Normal | Self::Suffix | Self::Lite => 0,
            Self::Aes256Gcm | Self::XChaCha20Poly1305 => self.encryption_tag_len(),
        }
    }

    /// Calculates the number of additional bytes required compared
    /// to an unencrypted payload.
    #[must_use]
    pub const fn payload_overhead(self) -> usize {
        self.payload_prefix_len2() + self.payload_suffix_len()
    }

    /// Extracts the byte slice in a packet used as the nonce, and the remaining mutable
    /// portion of the packet.
    fn nonce_slice<'a>(
        self,
        header: &'a [u8],
        body: &'a mut [u8],
    ) -> Result<(&'a [u8], &'a mut [u8]), CryptoError> {
        match self {
            Self::Normal => Ok((header, body)),
            Self::Suffix | Self::Lite | Self::Aes256Gcm | Self::XChaCha20Poly1305 => {
                let len = body.len();
                if len < self.payload_suffix_len() {
                    Err(CryptoError)
                } else {
                    let (body_left, nonce_loc) = body.split_at_mut(len - self.nonce_size());
                    Ok((nonce_loc, body_left))
                }
            },
        }
    }

    /// Encrypts a Discord RT(C)P packet using the given XSalsa20Poly1305 cipher.
    ///
    /// Use of this requires that the input packet has had a nonce generated in the correct location,
    /// and `payload_len` specifies the number of bytes after the header including this nonce.
    #[deprecated(
        since = "0.4.4",
        note = "This method performs encryption for older encryption modes,\
                which will no longer be accepted by Discord as of 2024-11-18. It is an\
                implementation detail and will be removed in `v0.5`."
    )]
    #[inline]
    pub fn encrypt_in_place(
        self,
        packet: &mut impl MutablePacket,
        cipher: &XSalsa20Poly1305,
        payload_len: usize,
    ) -> Result<(), CryptoError> {
        let header_len = packet.packet().len() - packet.payload().len();
        let (header, body) = packet.packet_mut().split_at_mut(header_len);
        let (slice_to_use, body_remaining) = self.nonce_slice(header, &mut body[..payload_len])?;

        let nonce_size = self.nonce_size();
        let tag_size = self.encryption_tag_len();

        let mut nonce = crypto_secretbox::Nonce::default();
        let nonce_slice = if slice_to_use.len() == nonce_size {
            crypto_secretbox::Nonce::from_slice(&slice_to_use[..nonce_size])
        } else {
            nonce[..self.nonce_size()].copy_from_slice(slice_to_use);
            &nonce
        };

        // body_remaining is now correctly truncated by this point.
        // the true_payload to encrypt follows after the first TAG_LEN bytes.
        let tag =
            cipher.encrypt_in_place_detached(nonce_slice, b"", &mut body_remaining[tag_size..])?;
        body_remaining[..tag_size].copy_from_slice(&tag[..]);

        Ok(())
    }
}

/// State used in nonce generation for the encryption variants in [`CryptoMode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CryptoState {
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// The last used nonce is stored.
    Aes256Gcm(Wrapping<u32>),
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// The last used nonce is stored.
    XChaCha20Poly1305(Wrapping<u32>),
    /// The RTP header is used as the source of nonce bytes for the packet.
    ///
    /// No state is required.
    Normal,
    /// An additional random 24B suffix is used as the source of nonce bytes for the packet.
    /// This is regenerated randomly for each packet.
    ///
    /// No state is required.
    Suffix,
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// The last used nonce is stored.
    Lite(Wrapping<u32>),
}

#[allow(deprecated)]
impl From<CryptoMode> for CryptoState {
    fn from(val: CryptoMode) -> Self {
        match val {
            CryptoMode::Normal => CryptoState::Normal,
            CryptoMode::Suffix => CryptoState::Suffix,
            CryptoMode::Lite => CryptoState::Lite(Wrapping(rand::random::<u32>())),
            CryptoMode::Aes256Gcm => CryptoState::Aes256Gcm(Wrapping(rand::random::<u32>())),
            CryptoMode::XChaCha20Poly1305 =>
                CryptoState::XChaCha20Poly1305(Wrapping(rand::random::<u32>())),
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
        let endpoint = payload_end + mode.payload_suffix_len();
        let startpoint = endpoint - mode.nonce_size();

        match self {
            Self::Suffix => {
                rand::thread_rng().fill(&mut packet.payload_mut()[startpoint..endpoint]);
            },
            Self::Lite(ref mut i)
            | Self::Aes256Gcm(ref mut i)
            | Self::XChaCha20Poly1305(ref mut i) => {
                (&mut packet.payload_mut()[startpoint..endpoint])
                    .write_u32::<NetworkEndian>(i.0)
                    .expect(
                        "Nonce size is guaranteed to be sufficient to write u32 for lite tagging.",
                    );
                *i += Wrapping(1);
            },
            Self::Normal => {},
        }

        endpoint
    }

    /// Returns the underlying (stateless) type of the active crypto mode.
    #[must_use]
    pub fn kind(self) -> CryptoMode {
        CryptoMode::from(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) enum EncryptionAlgorithm {
    Aes256Gcm,
    XChaCha20Poly1305,
    XSalsa20Poly1305,
}

impl EncryptionAlgorithm {
    #[must_use]
    pub(crate) const fn encryption_tag_len(self) -> usize {
        match self {
            Self::Aes256Gcm => <Aes256Gcm as AeadCore>::TagSize::USIZE, // 16
            Self::XChaCha20Poly1305 => <XChaCha20Poly1305 as AeadCore>::TagSize::USIZE, // 16
            Self::XSalsa20Poly1305 => XSalsa20Poly1305::TAG_SIZE,       // 16
        }
    }
}

impl From<&Cipher> for EncryptionAlgorithm {
    fn from(value: &Cipher) -> Self {
        match value {
            Cipher::XSalsa20Poly1305(..) => EncryptionAlgorithm::XSalsa20Poly1305,
            Cipher::XChaCha20Poly1305(_) => EncryptionAlgorithm::XChaCha20Poly1305,
            Cipher::Aes256Gcm(_) => EncryptionAlgorithm::Aes256Gcm,
        }
    }
}

#[derive(Clone)]
pub enum Cipher {
    XSalsa20Poly1305(XSalsa20Poly1305, CryptoMode),
    XChaCha20Poly1305(XChaCha20Poly1305),
    Aes256Gcm(Box<Aes256Gcm>),
}

impl Cipher {
    #[must_use]
    pub(crate) fn mode(&self) -> CryptoMode {
        match self {
            Cipher::XSalsa20Poly1305(_, mode) => *mode,
            Cipher::XChaCha20Poly1305(_) => CryptoMode::XChaCha20Poly1305,
            Cipher::Aes256Gcm(_) => CryptoMode::Aes256Gcm,
        }
    }

    #[must_use]
    pub(crate) fn encryption_tag_len(&self) -> usize {
        EncryptionAlgorithm::from(self).encryption_tag_len()
    }

    /// Encrypts a Discord RT(C)P packet using the given key.
    ///
    /// Use of this requires that the input packet has had a nonce generated in the correct location,
    /// and `payload_len` specifies the number of bytes after the header including this nonce.
    #[inline]
    pub fn encrypt_pkt_in_place(
        &self,
        packet: &mut impl MutablePacket,
        payload_len: usize,
    ) -> Result<(), CryptoError> {
        let mode = self.mode();
        let header_len = packet.packet().len() - packet.payload().len();

        let (header, body) = packet.packet_mut().split_at_mut(header_len);
        let (slice_to_use, body_remaining) = mode.nonce_slice(header, &mut body[..payload_len])?;

        let tag_size = self.encryption_tag_len();

        // body_remaining is now correctly truncated to exclude the nonce by this point.
        // the true_payload to encrypt is within the buf[prefix:-suffix].
        let (pre_payload, body_remaining) = body_remaining.split_at_mut(mode.payload_prefix_len2());
        let (body, post_payload) =
            body_remaining.split_at_mut(body_remaining.len() - mode.tag_suffix_len());

        // All these Nonce types are distinct at the type level
        // (96b for AES, 192b for XSalsa/XChaCha).
        match self {
            // Older modes place the tag before the payload and do not authenticate
            // cleartext.
            Self::XSalsa20Poly1305(secret_box, _) => {
                let mut nonce = crypto_secretbox::Nonce::default();
                nonce[..mode.nonce_size()].copy_from_slice(slice_to_use);

                let tag = secret_box.encrypt_in_place_detached(&nonce, b"", body)?;
                pre_payload[..tag_size].copy_from_slice(&tag[..]);
            },

            // The below variants follow part of the SRTP spec (RFC3711, sec 3.1)
            // by requiring that we include the cleartext header portion as
            // authenticated data.
            Self::Aes256Gcm(aes_gcm) => {
                let mut nonce = aes_gcm::Nonce::default();
                nonce[..mode.nonce_size()].copy_from_slice(slice_to_use);

                let tag = aes_gcm.encrypt_in_place_detached(&nonce, header, body)?;
                post_payload[..tag_size].copy_from_slice(&tag[..]);
            },
            Self::XChaCha20Poly1305(cha_cha_poly1305) => {
                let mut nonce = chacha20poly1305::XNonce::default();
                nonce[..mode.nonce_size()].copy_from_slice(slice_to_use);

                let tag = cha_cha_poly1305.encrypt_in_place_detached(&nonce, header, body)?;
                post_payload[..tag_size].copy_from_slice(&tag[..]);
            },
        }

        Ok(())
    }

    #[cfg(any(feature = "receive", test))]
    pub(crate) fn decrypt_rtp_in_place(
        &self,
        packet: &mut MutableRtpPacket<'_>,
    ) -> Result<(usize, usize), InternalError> {
        let mode = self.mode();
        // An exciting difference from the SRTP spec: Discord begins encryption
        // after the RTP extension *header*, encrypting the extensions themselves,
        // whereas the spec leaves all extensions in the clear.
        // This header is described as the 'extension preamble'.
        let has_extension = packet.get_extension() != 0;

        let plain_bytes = if mode.is_more_srtp_compliant() && has_extension {
            // CSRCs and extension bytes will be in the plaintext segment.
            // We will need these demarcated to select the right bytes to
            // decrypt, and to use as auth data.
            RtpExtensionPacket::minimum_packet_size()
        } else {
            0
        };

        let (mut start_estimate, end) = self.decrypt_pkt_in_place(packet, plain_bytes)?;

        // Update the start estimate to account for bytes occupied by extension headers.
        if has_extension {
            let packet = packet.packet();
            if let Some((_, exts_and_opus)) = split_at_checked(packet, start_estimate) {
                let extension = RtpExtensionPacket::new(exts_and_opus)
                    .ok_or(InternalError::IllegalVoicePacket)?;
                start_estimate += extension.packet().len() - extension.payload().len();
            }
        }

        Ok((start_estimate, end))
    }

    #[cfg(feature = "receive")]
    pub(crate) fn decrypt_rtcp_in_place(
        &self,
        packet: &mut MutableRtcpPacket<'_>,
    ) -> Result<(usize, usize), InternalError> {
        // RTCP/SRTCP have identical handling -- no var-length elements
        // are included as part of the plaintext.
        self.decrypt_pkt_in_place(packet, 0)
    }

    /// Decrypts an arbitrary packet using the given key.
    ///
    /// If successful, this returns the number of bytes to be ignored from the
    /// start and end of the packet payload.
    #[inline]
    pub(crate) fn decrypt_pkt_in_place(
        &self,
        packet: &mut impl MutablePacket,
        n_plaintext_body_bytes: usize,
    ) -> Result<(usize, usize), InternalError> {
        let mode = self.mode();
        let header_len = packet.packet().len() - packet.payload().len();
        let plaintext_end = header_len + n_plaintext_body_bytes;

        let (plaintext, ciphertext) =
            split_at_mut_checked(packet.packet_mut(), plaintext_end).ok_or(CryptoError)?;
        let (slice_to_use, body_remaining) = mode.nonce_slice(plaintext, ciphertext)?;

        let (pre_payload, body_remaining) =
            split_at_mut_checked(body_remaining, mode.payload_prefix_len2()).ok_or(CryptoError)?;

        let suffix_split_point = body_remaining
            .len()
            .checked_sub(mode.tag_suffix_len())
            .ok_or(CryptoError)?;

        let (body, post_payload) =
            split_at_mut_checked(body_remaining, suffix_split_point).ok_or(CryptoError)?;

        let tag_size = self.encryption_tag_len();

        match self {
            // Older modes place the tag before the payload and do not authenticate
            // cleartext.
            Self::XSalsa20Poly1305(secret_box, _) => {
                let mut nonce = crypto_secretbox::Nonce::default();
                nonce[..mode.nonce_size().min(slice_to_use.len())].copy_from_slice(slice_to_use);

                let tag = crypto_secretbox::Tag::from_slice(&pre_payload[..tag_size]);
                secret_box.decrypt_in_place_detached(&nonce, b"", body, tag)?;
            },

            // The below variants follow part of the SRTP spec (RFC3711, sec 3.1)
            // by requiring that we include the cleartext header portion as
            // authenticated data.
            Self::Aes256Gcm(aes_gcm) => {
                let mut nonce = aes_gcm::Nonce::default();
                nonce[..mode.nonce_size()].copy_from_slice(slice_to_use);

                let tag = aes_gcm::Tag::from_slice(&post_payload[..tag_size]);
                aes_gcm.decrypt_in_place_detached(&nonce, plaintext, body, tag)?;
            },
            Self::XChaCha20Poly1305(cha_cha_poly1305) => {
                let mut nonce = chacha20poly1305::XNonce::default();
                nonce[..mode.nonce_size()].copy_from_slice(slice_to_use);

                let tag = chacha20poly1305::Tag::from_slice(&post_payload[..tag_size]);
                cha_cha_poly1305.decrypt_in_place_detached(&nonce, plaintext, body, tag)?;
            },
        }

        Ok((plaintext_end + pre_payload.len(), post_payload.len()))
    }
}

// Temporary functions -- MSRV is ostensibly 1.74, slice::split_at(_mut)_checked is 1.80+.
// TODO: Remove in v0.5+ with MSRV bump to 1.81+.
#[inline]
#[must_use]
const fn split_at_checked(els: &[u8], mid: usize) -> Option<(&[u8], &[u8])> {
    if mid <= els.len() {
        Some(els.split_at(mid))
    } else {
        None
    }
}

#[inline]
#[must_use]
fn split_at_mut_checked(els: &mut [u8], mid: usize) -> Option<(&mut [u8], &mut [u8])> {
    if mid <= els.len() {
        Some(els.split_at_mut(mid))
    } else {
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
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
            CryptoMode::XChaCha20Poly1305,
        ];
        let mut pkt = MutableRtpPacket::new(&mut buf[..]).unwrap();

        for mode in modes {
            // Coincidentally, these are all 32B for now.
            let cipher = mode.cipher_from_key(&[1u8; 32]).unwrap();
            // AIM: should error, and not panic.
            assert!(cipher.decrypt_rtp_in_place(mode, &mut pkt).is_err());
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
            let cipher = mode
                .cipher_from_key(&[7u8; XSalsa20Poly1305::KEY_SIZE])
                .unwrap();
            let mut pkt = MutableRtpPacket::new(&mut buf[..]).unwrap();
            let mut crypto_state = CryptoState::from(mode);
            let payload = pkt.payload_mut();
            payload[XSalsa20Poly1305::TAG_SIZE..XSalsa20Poly1305::TAG_SIZE + TRUE_PAYLOAD.len()]
                .copy_from_slice(&TRUE_PAYLOAD[..]);

            let final_payload_size = crypto_state
                .write_packet_nonce(&mut pkt, XSalsa20Poly1305::TAG_SIZE + TRUE_PAYLOAD.len());

            let enc_succ = cipher.encrypt_pkt_in_place(mode, &mut pkt, final_payload_size);

            assert!(enc_succ.is_ok());

            let final_pkt_len = MutableRtpPacket::minimum_packet_size() + final_payload_size;
            let mut pkt = MutableRtpPacket::new(&mut buf[..final_pkt_len]).unwrap();

            assert!(cipher.decrypt_rtp_in_place(mode, &mut pkt).is_ok());
        }
    }

    #[test]
    fn symmetric_encrypt_decrypt_tag_after_data() {
        const TRUE_PAYLOAD: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        for mode in [CryptoMode::Aes256Gcm, CryptoMode::XChaCha20Poly1305] {
            let mut buf = vec![
                0u8;
                MutableRtpPacket::minimum_packet_size()
                    + TRUE_PAYLOAD.len()
                    + mode.nonce_size()
                    + mode.encryption_tag_len()
            ];

            buf.fill(0);
            let cipher = mode.cipher_from_key(&[7u8; 32]).unwrap();
            let mut pkt = MutableRtpPacket::new(&mut buf[..]).unwrap();
            let mut crypto_state = CryptoState::from(mode);
            let payload = pkt.payload_mut();
            payload[mode.payload_prefix_len2()..TRUE_PAYLOAD.len()].copy_from_slice(&TRUE_PAYLOAD);

            let final_payload_size = crypto_state.write_packet_nonce(&mut pkt, TRUE_PAYLOAD.len());

            let enc_succ = cipher.encrypt_pkt_in_place(mode, &mut pkt, final_payload_size);

            assert!(enc_succ.is_ok());

            let final_pkt_len = MutableRtpPacket::minimum_packet_size() + final_payload_size;
            let mut pkt = MutableRtpPacket::new(&mut buf[..final_pkt_len]).unwrap();

            assert!(cipher.decrypt_rtp_in_place(mode, &mut pkt).is_ok());
        }
    }
}
