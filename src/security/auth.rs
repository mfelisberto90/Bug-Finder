use crate::runtime::trim_heap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::rngs::OsRng;
use rand::RngCore;
use scrypt::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Params, Scrypt,
};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

static SCRYPT_SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn scrypt_semaphore() -> Arc<Semaphore> {
    SCRYPT_SEMAPHORE
        .get_or_init(|| Arc::new(Semaphore::new(2)))
        .clone()
}

pub async fn hash_password(password: String) -> Result<String, String> {
    let permit = scrypt_semaphore()
        .acquire_owned()
        .await
        .map_err(|e| format!("scrypt semaphore error: {e}"))?;

    tokio::task::spawn_blocking(move || {
        let _guard = permit;
        let salt = SaltString::generate(&mut OsRng);
        // N = 2^14 (16384), r = 8, p = 1 => 16 MiB transient work factor, ~35-50ms
        let params = Params::new(14, 8, 1, 32).map_err(|e| format!("scrypt params: {e}"))?;
        let hash = Scrypt
            .hash_password_customized(password.as_bytes(), None, None, params, &salt)
            .map_err(|e| format!("scrypt hash: {e}"))?
            .to_string();
        trim_heap();
        Ok(hash)
    })
    .await
    .map_err(|e| format!("join scrypt: {e}"))?
}

pub async fn verify_password(password: String, encoded_hash: String) -> bool {
    let Ok(permit) = scrypt_semaphore().acquire_owned().await else {
        return false;
    };
    tokio::task::spawn_blocking(move || {
        let _guard = permit;
        let ok = match PasswordHash::new(&encoded_hash) {
            Ok(parsed) => Scrypt.verify_password(password.as_bytes(), &parsed).is_ok(),
            Err(_) => false,
        };
        trim_heap();
        ok
    })
    .await
    .unwrap_or(false)
}

pub fn sha256_hex(input: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(input);
    hex::encode(h.finalize())
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

pub fn random_token_b64(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(&buf)
}

pub fn generate_api_token() -> (String, String, String) {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let plaintext = format!("bf_{}", hex::encode(raw));
    let prefix = plaintext[..11].to_string();
    let hash = sha256_hex(plaintext.as_bytes());
    (plaintext, prefix, hash)
}

pub fn generate_dsn_public_key() -> String {
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    hex::encode(raw)
}

/// Generate a cryptographic 256-bit (64 hex chars) BUGFINDER_APP_KEY from OS CSPRNG.
pub fn generate_app_key_hex() -> String {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    hex::encode(raw)
}

/// Exponential lockout duration in seconds matching enterprise auth policy.
pub fn compute_lockout_seconds(failed_attempts: i64) -> Option<i64> {
    match failed_attempts {
        0..=4 => None,
        5 => Some(60),
        6 => Some(300),
        7 => Some(900),
        8 => Some(3600),
        _ => Some(86400),
    }
}

pub fn canonical_json_sha256(val: &serde_json::Value) -> String {
    let sorted = sort_json_keys(val);
    let bytes = serde_json::to_vec(&sorted).unwrap_or_default();
    sha256_hex(&bytes)
}

const COMMON_WEAK_PASSWORDS: &[&str] = &[
    "1234567890",
    "123456789012",
    "password123",
    "password1234",
    "qwerty12345",
    "qwertyuiop",
    "admin12345",
    "welcome123",
    "letmein123",
    "changeme123",
    "bugfinder123",
    "1111111111",
    "0000000000",
    "iloveyou12",
    "abc1234567",
    "football123",
    "monkey1234",
    "dragon1234",
    "baseball12",
    "master1234",
    "trustno123",
    "sunshine12",
    "princess12",
    "adminadmin",
    "passw0rd12",
    "p@ssword12",
    "qwerty123!",
    "zaq12wsxcde",
    "superman12",
    "shadow1234",
];

/// Enforces NIST SP 800-63B style password strength: >= 10 chars, common breach blocklist,
/// and rejection of email/local-part substrings.
pub fn validate_password_strength(password: &str, email: &str, name: &str) -> Result<(), String> {
    let char_len = password.chars().count();
    if char_len < 10 {
        return Err("Password must be at least 10 characters long".into());
    }
    if char_len > 256 || password.len() > 1024 {
        return Err("Password must not exceed 256 characters".into());
    }
    if password.chars().all(|c| c.is_ascii_whitespace()) {
        return Err("Password cannot consist solely of whitespace".into());
    }
    let lower = password.to_ascii_lowercase();
    if COMMON_WEAK_PASSWORDS.iter().any(|&w| lower == w) {
        return Err("Password is too common; choose a stronger passphrase".into());
    }
    let email_norm = email.trim().to_ascii_lowercase();
    if !email_norm.is_empty() && lower.contains(&email_norm) {
        return Err("Password must not contain your email address".into());
    }
    if let Some((local, _)) = email_norm.split_once('@') {
        if local.len() >= 4 && lower.contains(local) {
            return Err("Password must not contain your email username".into());
        }
    }
    let name_norm = name.trim().to_ascii_lowercase();
    if name_norm.len() >= 4 && lower == name_norm {
        return Err("Password must not match your display name".into());
    }
    if password
        .chars()
        .collect::<std::collections::HashSet<char>>()
        .len()
        < 4
    {
        return Err("Password must include more character variety".into());
    }
    Ok(())
}

pub struct AuditEntryHashInput<'a> {
    pub prev_hash: &'a str,
    pub org_id: i64,
    pub actor_user_id: Option<i64>,
    pub action: &'a str,
    pub target_type: &'a str,
    pub target_id: &'a str,
    pub metadata: &'a serde_json::Value,
    pub created_at: i64,
}

/// Computes an injective SHA-256 link in the immutable per-organization audit hash chain.
pub fn compute_audit_entry_hash(entry: &AuditEntryHashInput<'_>) -> String {
    let mut h = Sha256::new();
    let feed = |h: &mut Sha256, bytes: &[u8]| {
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
    };
    let meta_sha = canonical_json_sha256(entry.metadata);
    feed(&mut h, entry.prev_hash.as_bytes());
    h.update(entry.org_id.to_be_bytes());
    h.update(entry.actor_user_id.unwrap_or(-1).to_be_bytes());
    feed(&mut h, entry.action.as_bytes());
    feed(&mut h, entry.target_type.as_bytes());
    feed(&mut h, entry.target_id.as_bytes());
    feed(&mut h, meta_sha.as_bytes());
    h.update(entry.created_at.to_be_bytes());
    hex::encode(h.finalize())
}

fn sort_json_keys(val: &serde_json::Value) -> serde_json::Value {
    match val {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let mut out = serde_json::Map::new();
            for (k, v) in entries {
                out.insert(k.clone(), sort_json_keys(v));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_json_keys).collect())
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn scrypt_and_canonical_hash_work() {
        let h = hash_password("correct-horse-battery-staple".into())
            .await
            .unwrap();
        assert!(verify_password("correct-horse-battery-staple".into(), h.clone()).await);
        assert!(!verify_password("wrong-pass".into(), h).await);

        let a = json!({"b": 2, "a": {"y": 1, "x": 0}});
        let b = json!({"a": {"x": 0, "y": 1}, "b": 2});
        assert_eq!(canonical_json_sha256(&a), canonical_json_sha256(&b));
        assert_eq!(compute_lockout_seconds(4), None);
        assert_eq!(compute_lockout_seconds(5), Some(60));
        assert_eq!(compute_lockout_seconds(9), Some(86400));
    }
}
