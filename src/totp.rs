use constant_time_eq::constant_time_eq;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha1::Sha1;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::secret_source::{SecretSourceError, from_environment};

const PERIOD_SECONDS: i64 = 30;
const DIGITS: u32 = 6;
const SECRET_BYTES: usize = 20;
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug, Error, Eq, PartialEq)]
pub enum TotpSecretError {
    #[error("TOTP secret environment variable is unavailable")]
    Missing,
    #[error("TOTP secret environment variable is not valid Unicode")]
    NonUnicode,
    #[error("TOTP secret source is unreadable, oversized, or ambiguous")]
    Unavailable,
    #[error("TOTP secret must be an unpadded Base32 value containing 160 through 512 bits")]
    InvalidEncoding,
}

pub fn secret_from_reference(reference: &Value) -> Result<Zeroizing<Vec<u8>>, TotpSecretError> {
    let key = reference
        .get("key")
        .and_then(Value::as_str)
        .ok_or(TotpSecretError::Missing)?;
    let encoded = match from_environment(key) {
        Ok(Some(value)) => value,
        Ok(None) => return Err(TotpSecretError::Missing),
        Err(
            SecretSourceError::NonUnicodeEnvironment { .. }
            | SecretSourceError::NonUnicodeFile { .. },
        ) => return Err(TotpSecretError::NonUnicode),
        Err(_) => return Err(TotpSecretError::Unavailable),
    };
    decode_base32(&encoded)
        .map(Zeroizing::new)
        .ok_or(TotpSecretError::InvalidEncoding)
}

pub fn generate_secret() -> Result<Zeroizing<String>, getrandom::Error> {
    let mut secret = [0_u8; SECRET_BYTES];
    getrandom::fill(&mut secret)?;
    let encoded = encode_base32(secret.as_slice());
    secret.zeroize();
    Ok(Zeroizing::new(encoded))
}

pub fn verify(secret: &[u8], submitted: &str, unix_time: i64) -> Option<i64> {
    if secret.len() < 20
        || secret.len() > 64
        || submitted.len() != DIGITS as usize
        || !submitted.bytes().all(|byte| byte.is_ascii_digit())
        || unix_time < 0
    {
        return None;
    }
    let current = unix_time / PERIOD_SECONDS;
    [
        current,
        current.saturating_sub(1),
        current.saturating_add(1),
    ]
    .into_iter()
    .find(|counter| {
        let expected = format!(
            "{:0width$}",
            hotp(secret, *counter as u64, DIGITS),
            width = DIGITS as usize
        );
        constant_time_eq(expected.as_bytes(), submitted.as_bytes())
    })
}

pub fn generate(secret: &[u8], unix_time: i64) -> Option<String> {
    if !(20..=64).contains(&secret.len()) || unix_time < 0 {
        return None;
    }
    Some(format!(
        "{:0width$}",
        hotp(secret, (unix_time / PERIOD_SECONDS) as u64, DIGITS),
        width = DIGITS as usize
    ))
}

fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts every key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    binary % 10_u32.pow(digits)
}

fn decode_base32(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    if value.is_empty() || value.contains('=') || !matches!(value.len() % 8, 0 | 2 | 4 | 5 | 7) {
        return None;
    }
    let mut output = Vec::with_capacity(value.len().saturating_mul(5) / 8);
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for byte in value.bytes() {
        let symbol = match byte.to_ascii_uppercase() {
            b'A'..=b'Z' => byte.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(symbol);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1_u32 << bits).saturating_sub(1);
        }
    }
    if bits > 0 && buffer != 0 {
        return None;
    }
    (20..=64).contains(&output.len()).then_some(output)
}

fn encode_base32(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len().saturating_mul(8).div_ceil(5));
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for byte in value {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(char::from(
                BASE32_ALPHABET[((buffer >> bits) & 31) as usize],
            ));
            buffer &= (1_u32 << bits).saturating_sub(1);
        }
    }
    if bits > 0 {
        output.push(char::from(
            BASE32_ALPHABET[((buffer << (5 - bits)) & 31) as usize],
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc_6238_sha1_vectors() {
        let secret = b"12345678901234567890";
        let vectors = [
            (59_u64, 94_287_082),
            (1_111_111_109, 7_081_804),
            (1_111_111_111, 14_050_471),
            (1_234_567_890, 89_005_924),
            (2_000_000_000, 69_279_037),
            (20_000_000_000, 65_353_130),
        ];
        for (time, expected) in vectors {
            assert_eq!(hotp(secret, time / 30, 8), expected);
        }
    }

    #[test]
    fn decodes_unpadded_base32_and_rejects_noncanonical_or_weak_values() {
        assert_eq!(
            decode_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
            Some(b"12345678901234567890".to_vec())
        );
        assert!(decode_base32("GEZDGNBVGY3TQOJQ=").is_none());
        assert!(decode_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQA").is_none());
        assert!(decode_base32("JBSWY3DPEHPK3PXP").is_none());
        assert!(decode_base32("not base32!").is_none());
    }

    #[test]
    fn accepts_one_adjacent_time_step_and_rejects_reformatted_codes() {
        let secret = b"12345678901234567890";
        let current = 1_234_567_890_i64 / 30;
        let code = format!("{:06}", hotp(secret, current as u64, 6));
        assert_eq!(verify(secret, &code, 1_234_567_890), Some(current));
        assert_eq!(verify(secret, &code, 1_234_567_920), Some(current));
        assert_eq!(verify(secret, &code, 1_234_567_950), None);
        assert_eq!(verify(secret, &format!(" {code}"), 1_234_567_890), None);
        assert_eq!(
            generate(secret, 1_234_567_890).as_deref(),
            Some(code.as_str())
        );
    }

    #[test]
    fn generates_independent_canonical_160_bit_secrets() {
        let first = generate_secret().expect("TOTP secret");
        let second = generate_secret().expect("TOTP secret");
        assert_eq!(first.len(), 32);
        assert_ne!(first.as_str(), second.as_str());
        assert!(first.bytes().all(|byte| BASE32_ALPHABET.contains(&byte)));
        assert_eq!(decode_base32(&first).map(|value| value.len()), Some(20));
        assert_eq!(
            encode_base32(b"12345678901234567890"),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
    }
}
