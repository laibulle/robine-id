use constant_time_eq::constant_time_eq;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
const RAW_CODE_LENGTH: usize = 16;
const FORMATTED_CODE_LENGTH: usize = 19;

pub fn generate_code() -> Result<Zeroizing<String>, getrandom::Error> {
    let mut random = [0_u8; RAW_CODE_LENGTH];
    getrandom::fill(&mut random)?;
    let mut code = String::with_capacity(FORMATTED_CODE_LENGTH);
    for (index, byte) in random.iter().copied().enumerate() {
        if index > 0 && index % 4 == 0 {
            code.push('-');
        }
        code.push(char::from(ALPHABET[usize::from(byte & 31)]));
    }
    random.zeroize();
    Ok(Zeroizing::new(code))
}

pub fn hash_code(code: &str) -> Option<Zeroizing<String>> {
    let normalized = normalize(code)?;
    Some(Zeroizing::new(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(normalized.as_bytes()))
    )))
}

pub fn matching_fingerprint(hashes: &[String], submitted: &str) -> Option<Vec<u8>> {
    let normalized = normalize(submitted)?;
    let submitted_digest = Sha256::digest(normalized.as_bytes());
    let mut matched = false;
    for hash in hashes {
        if let Some(expected) = hash
            .strip_prefix("sha256:")
            .and_then(|value| hex::decode(value).ok())
            .filter(|value| value.len() == 32)
        {
            matched |= constant_time_eq(&expected, &submitted_digest);
        }
    }
    matched.then(|| submitted_digest.to_vec())
}

pub fn valid_hash(hash: &str) -> bool {
    hash.len() == 71
        && hash.strip_prefix("sha256:").is_some_and(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
}

fn normalize(code: &str) -> Option<Zeroizing<String>> {
    let code = code.trim();
    if code.len() != FORMATTED_CODE_LENGTH {
        return None;
    }
    let mut normalized = String::with_capacity(FORMATTED_CODE_LENGTH);
    for (index, byte) in code.bytes().enumerate() {
        if matches!(index, 4 | 9 | 14) {
            if byte != b'-' {
                return None;
            }
            normalized.push('-');
            continue;
        }
        let byte = byte.to_ascii_uppercase();
        if !ALPHABET.contains(&byte) {
            return None;
        }
        normalized.push(char::from(byte));
    }
    Some(Zeroizing::new(normalized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_unambiguous_high_entropy_codes() {
        let first = generate_code().expect("recovery code");
        let second = generate_code().expect("recovery code");
        assert_ne!(first.as_str(), second.as_str());
        assert!(normalize(&first).is_some());
        assert_eq!(first.len(), FORMATTED_CODE_LENGTH);
        assert!(!first.contains(['0', '1', 'I', 'O']));
    }

    #[test]
    fn verifies_normalized_codes_and_returns_a_stable_hash_fingerprint() {
        let code = "2345-6789-ABCD-EFGH";
        let hash = hash_code(code).expect("recovery hash");
        let hashes = vec![hash.to_string()];
        let fingerprint =
            matching_fingerprint(&hashes, "2345-6789-abcd-efgh").expect("matching recovery code");
        assert_eq!(fingerprint, Sha256::digest(code.as_bytes()).to_vec());
        assert!(matching_fingerprint(&hashes, "2345-6789-ABCD-EFGJ").is_none());
        assert!(matching_fingerprint(&hashes, "23456789ABCDEFGH").is_none());
        assert!(valid_hash(&hash));
        assert!(!valid_hash(&hash.to_ascii_uppercase()));
    }
}
