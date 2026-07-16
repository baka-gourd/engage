//! Standard `age1pq` / `AGE-SECRET-KEY-PQ-1` recipient support.
//!
//! The adapter is derived from `age-recipient-pq` at commit
//! 966d530d33dec94f171634d78b6aa5c97eea89bc and updated for age 0.12.
//! The upstream implementation is MIT OR Apache-2.0 and has not been independently audited.

use age::{Identity as AgeIdentity, Recipient as AgeRecipient};
use age_core::{
    format::{FileKey, Stanza},
    secrecy::{ExposeSecret, SecretBox, SecretString},
};
use age_hpke_pq::{
    aead::new_aead,
    hpke::{new_sender, open},
    kdf::new_kdf,
    kem::{Kem, MlKem768X25519},
};
use base64::prelude::{BASE64_STANDARD_NO_PAD, Engine as _};
use bech32::{
    Bech32, Fe32, Fe1024, Hrp, encode,
    primitives::{checksum::Checksum, decode::CheckedHrpstring},
};
use std::{collections::HashSet, fmt, str::FromStr};
use zeroize::Zeroizing;

use crate::{Error, Result, error::message};

const STANZA_TAG: &str = "mlkem768x25519";
const PQ_LABEL: &[u8] = b"age-encryption.org/mlkem768x25519";
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0003;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum LongBech32 {}

impl Checksum for LongBech32 {
    type MidstateRepr = u32;
    type CorrectionField = Fe1024;
    const ROOT_GENERATOR: Self::CorrectionField = Fe1024::new([Fe32::P, Fe32::X]);
    const ROOT_EXPONENTS: core::ops::RangeInclusive<usize> = 24..=26;
    const CODE_LENGTH: usize = 8192;
    const CHECKSUM_LENGTH: usize = 6;
    const GENERATOR_SH: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    const TARGET_RESIDUE: u32 = 1;
}

#[derive(Clone)]
pub struct HybridRecipient {
    public_key: Vec<u8>,
}

pub struct HybridIdentity {
    seed: SecretBox<[u8; 32]>,
}

pub fn generate_pq_keypair() -> Result<(HybridRecipient, HybridIdentity)> {
    HybridRecipient::generate()
}

impl HybridRecipient {
    pub fn generate() -> Result<(Self, HybridIdentity)> {
        let kem = MlKem768X25519;
        let private = kem
            .generate_key()
            .map_err(|e| message(format!("post-quantum key error: {e}")))?;
        let seed_bytes = Zeroizing::new(
            private
                .bytes()
                .map_err(|e| message(format!("post-quantum key error: {e}")))?,
        );
        let seed: [u8; 32] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| message("post-quantum key error: invalid PQ seed length"))?;
        Ok((
            Self {
                public_key: private.public_key().bytes(),
            },
            HybridIdentity {
                seed: SecretBox::new(Box::new(seed)),
            },
        ))
    }

    pub fn parse(value: &str) -> Result<Self> {
        let checked = CheckedHrpstring::new::<LongBech32>(value)
            .map_err(|e| message(format!("invalid PQ recipient: {e}")))?;
        let expected = Hrp::parse("age1pq").expect("constant HRP");
        if checked.hrp() != expected {
            return Err(message("post-quantum key error: wrong PQ recipient HRP"));
        }
        Ok(Self {
            public_key: checked.byte_iter().collect(),
        })
    }
}

impl fmt::Display for HybridRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = Hrp::parse("age1pq").expect("constant HRP");
        let encoded = encode::<LongBech32>(hrp, &self.public_key).map_err(|_| fmt::Error)?;
        f.write_str(&encoded)
    }
}

impl fmt::Debug for HybridRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for HybridRecipient {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl AgeRecipient for HybridRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> std::result::Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let io_err = |message: String| {
            age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                message,
            ))
        };
        let kem = MlKem768X25519;
        let public = kem
            .new_public_key(&self.public_key)
            .map_err(|e| io_err(format!("invalid PQ public key: {e:?}")))?;
        let kdf = new_kdf(KDF_ID).map_err(|e| io_err(format!("PQ KDF: {e:?}")))?;
        let aead = new_aead(AEAD_ID).map_err(|e| io_err(format!("PQ AEAD: {e:?}")))?;
        let (encapsulation, mut sender) = new_sender(public, kdf, aead, PQ_LABEL)
            .map_err(|e| io_err(format!("PQ HPKE setup: {e:?}")))?;
        let wrapped = sender
            .seal(&[], file_key.expose_secret())
            .map_err(|e| io_err(format!("PQ HPKE seal: {e:?}")))?;
        Ok((
            vec![Stanza {
                tag: STANZA_TAG.into(),
                args: vec![BASE64_STANDARD_NO_PAD.encode(encapsulation)],
                body: wrapped,
            }],
            HashSet::from(["postquantum".to_owned()]),
        ))
    }
}

impl HybridIdentity {
    pub fn parse(value: &str) -> Result<Self> {
        let checked = CheckedHrpstring::new::<Bech32>(value)
            .map_err(|e| message(format!("invalid PQ identity: {e}")))?;
        let expected = Hrp::parse("age-secret-key-pq-").expect("constant HRP");
        if checked.hrp() != expected {
            return Err(message("post-quantum key error: wrong PQ identity HRP"));
        }
        let bytes = Zeroizing::new(checked.byte_iter().collect::<Vec<_>>());
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| message("post-quantum key error: invalid PQ identity length"))?;
        Ok(Self {
            seed: SecretBox::new(Box::new(seed)),
        })
    }

    pub fn to_secret_string(&self) -> SecretString {
        let hrp = Hrp::parse("age-secret-key-pq-").expect("constant HRP");
        let mut encoded = Zeroizing::new(
            encode::<Bech32>(hrp, self.seed.expose_secret()).expect("valid identity encoding"),
        );
        encoded.make_ascii_uppercase();
        SecretString::from(core::mem::take(&mut *encoded))
    }

    pub fn to_public(&self) -> Result<HybridRecipient> {
        let kem = MlKem768X25519;
        let private = kem
            .new_private_key(self.seed.expose_secret())
            .map_err(|e| message(format!("post-quantum key error: {e}")))?;
        Ok(HybridRecipient {
            public_key: private.public_key().bytes(),
        })
    }
}

impl fmt::Debug for HybridIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridIdentity([REDACTED])")
    }
}

impl FromStr for HybridIdentity {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl AgeIdentity for HybridIdentity {
    fn unwrap_stanza(
        &self,
        stanza: &Stanza,
    ) -> Option<std::result::Result<FileKey, age::DecryptError>> {
        if stanza.tag != STANZA_TAG || stanza.args.len() != 1 {
            return None;
        }
        let encapsulation = BASE64_STANDARD_NO_PAD.decode(&stanza.args[0]).ok()?;
        let kem = MlKem768X25519;
        let private = kem.new_private_key(self.seed.expose_secret()).ok()?;
        let kdf = new_kdf(KDF_ID).ok()?;
        let aead = new_aead(AEAD_ID).ok()?;
        let mut ciphertext = encapsulation;
        ciphertext.extend_from_slice(&stanza.body);
        let file_key = Zeroizing::new(open(private, kdf, aead, PQ_LABEL, &[], &ciphertext).ok()?);
        let key: [u8; 16] = file_key.as_slice().try_into().ok()?;
        Some(Ok(FileKey::new(Box::new(key))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::{Decryptor, Encryptor};
    use std::io::{Read, Write};

    #[test]
    fn pq_round_trip() {
        let (recipient, identity) = HybridRecipient::generate().unwrap();
        let mut ciphertext = Vec::new();
        let encryptor =
            Encryptor::with_recipients(std::iter::once(&recipient as &dyn AgeRecipient)).unwrap();
        let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
        writer.write_all(b"engage pq").unwrap();
        writer.finish().unwrap();
        let decryptor = Decryptor::new(&ciphertext[..]).unwrap();
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn AgeIdentity))
            .unwrap();
        let mut plaintext = Vec::new();
        reader.read_to_end(&mut plaintext).unwrap();
        assert_eq!(plaintext, b"engage pq");
        assert_eq!(
            identity.to_public().unwrap().to_string(),
            recipient.to_string()
        );
    }

    #[test]
    fn either_recipient_can_decrypt_a_multi_recipient_message() {
        let (first_recipient, first_identity) = HybridRecipient::generate().unwrap();
        let (second_recipient, second_identity) = HybridRecipient::generate().unwrap();
        let recipients: [&dyn AgeRecipient; 2] = [&first_recipient, &second_recipient];
        let mut ciphertext = Vec::new();
        let encryptor = Encryptor::with_recipients(recipients.into_iter()).unwrap();
        let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
        writer.write_all(b"shared archive").unwrap();
        writer.finish().unwrap();

        for identity in [&first_identity, &second_identity] {
            let decryptor = Decryptor::new(&ciphertext[..]).unwrap();
            let mut reader = decryptor
                .decrypt(std::iter::once(identity as &dyn AgeIdentity))
                .unwrap();
            let mut plaintext = Vec::new();
            reader.read_to_end(&mut plaintext).unwrap();
            assert_eq!(plaintext, b"shared archive");
        }
    }
}
