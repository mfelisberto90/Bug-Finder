use crate::security::auth::fill_os_random;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::hkdf;

const AEAD_PREFIX: &str = "enc:v1:";
const AEAD_PREFIX_V2: &str = "enc:v2:";
const HKDF_SALT_BYTES: &[u8] = b"bugfinder-hkdf-v1";
const AEAD_KEY_INFO: &[u8] = b"bugfinder:aead:v1";

struct KeyBytesLen;

impl hkdf::KeyType for KeyBytesLen {
    fn len(&self) -> usize {
        32
    }
}

/// Derive a 256-bit domain-separated subkey from the application master key via HKDF-SHA256.
pub fn derive_subkey(app_key: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT_BYTES);
    let prk = salt.extract(app_key);
    let info = [domain];
    let okm = prk
        .expand(&info, KeyBytesLen)
        .expect("32-byte HKDF expansion never fails");
    let mut out = [0u8; 32];
    okm.fill(&mut out).expect("32-byte HKDF fill never fails");
    out
}

/// Seal a sensitive secret with AES-256-GCM and record-bound AAD (`enc:v2:` prefix).
pub fn seal_secret_v2(app_key: &[u8; 32], aad: &[u8], plaintext: &str) -> Result<String, String> {
    seal_with_prefix(app_key, aad, plaintext, AEAD_PREFIX_V2)
}

/// Seal a sensitive secret with AES-256-GCM and record-bound AAD (`enc:v1:` prefix).
/// Empty strings remain empty so optional secrets (e.g. unconfigured webhook secret) stay unset.
pub fn seal_secret(app_key: &[u8; 32], aad: &[u8], plaintext: &str) -> Result<String, String> {
    seal_with_prefix(app_key, aad, plaintext, AEAD_PREFIX)
}

fn seal_with_prefix(
    app_key: &[u8; 32],
    aad: &[u8],
    plaintext: &str,
    prefix: &str,
) -> Result<String, String> {
    if plaintext.is_empty() {
        return Ok(String::new());
    }
    let key_bytes = derive_subkey(app_key, AEAD_KEY_INFO);
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| "AEAD key initialization failed".to_string())?;
    let key = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    fill_os_random(&mut nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| "AEAD seal failed".to_string())?;

    let mut combined = Vec::with_capacity(NONCE_LEN + in_out.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&in_out);
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(&combined)))
}

/// Open a sealed AEAD secret with record-bound AAD, supporting `enc:v1:` and `enc:v2:`.
pub fn open_secret(
    app_key: &[u8; 32],
    aad: &[u8],
    stored: &str,
    allow_legacy_plaintext: bool,
) -> Result<String, String> {
    if stored.is_empty() {
        return Ok(String::new());
    }
    let Some(b64) = stored
        .strip_prefix(AEAD_PREFIX_V2)
        .or_else(|| stored.strip_prefix(AEAD_PREFIX))
    else {
        if allow_legacy_plaintext {
            return Ok(stored.to_string());
        }
        return Err("Rejected unencrypted secret payload".to_string());
    };
    let mut raw = URL_SAFE_NO_PAD
        .decode(b64.as_bytes())
        .map_err(|_| "Malformed encrypted secret encoding".to_string())?;
    if raw.len() <= NONCE_LEN + 16 {
        return Err("Encrypted secret payload truncated".to_string());
    }
    let nonce_bytes: [u8; NONCE_LEN] = raw[..NONCE_LEN]
        .try_into()
        .map_err(|_| "Invalid AEAD nonce length".to_string())?;
    let key_bytes = derive_subkey(app_key, AEAD_KEY_INFO);
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|_| "AEAD key initialization failed".to_string())?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let plaintext_bytes = key
        .open_in_place(nonce, Aad::from(aad), &mut raw[NONCE_LEN..])
        .map_err(|_| "Secret authentication tag verification failed".to_string())?;

    String::from_utf8(plaintext_bytes.to_vec())
        .map_err(|_| "Decrypted secret is not valid UTF-8".to_string())
}

/// Open a secret trying `primary` first, then each rotated key in `previous` (`BUGFINDER_PREVIOUS_APP_KEYS`).
pub fn open_secret_with_keyring(
    primary: &[u8; 32],
    previous: &[[u8; 32]],
    aad: &[u8],
    stored: &str,
    allow_legacy_plaintext: bool,
) -> Result<String, String> {
    if let Ok(plain) = open_secret(primary, aad, stored, allow_legacy_plaintext) {
        return Ok(plain);
    }
    for old_key in previous {
        if let Ok(plain) = open_secret(old_key, aad, stored, false) {
            return Ok(plain);
        }
    }
    Err("Secret authentication tag verification failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip_tamper_and_aad_isolation() {
        let app_key = [42u8; 32];
        let aad = b"alert_rules:webhook_secret:org1";
        let sealed = seal_secret(&app_key, aad, "whsec_live_super_secret").unwrap();
        assert!(sealed.starts_with("enc:v1:"));
        assert!(!sealed.contains("whsec_live"));

        let opened = open_secret(&app_key, aad, &sealed, false).unwrap();
        assert_eq!(opened, "whsec_live_super_secret");

        // Cross-tenant / wrong AAD swap must fail fail-closed
        assert!(open_secret(&app_key, b"alert_rules:webhook_secret:org2", &sealed, false).is_err());

        // 1-char tamper must fail
        let mut tampered = sealed.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        assert!(open_secret(&app_key, aad, &tampered, false).is_err());

        // Legacy plaintext enforcement
        assert!(open_secret(&app_key, aad, "legacy-plain", false).is_err());
        assert_eq!(
            open_secret(&app_key, aad, "legacy-plain", true).unwrap(),
            "legacy-plain"
        );
    }
}
