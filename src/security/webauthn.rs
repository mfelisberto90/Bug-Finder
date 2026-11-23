use crate::security::auth::constant_time_eq;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ED25519};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct VerifiedCredential {
    pub credential_id_b64: String,
    pub cose_alg: i32,
    pub public_key_b64: String,
    pub sign_count: u32,
}

#[derive(Debug, Clone)]
enum CborVal {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    #[allow(dead_code)]
    Array(Vec<CborVal>),
    Map(Vec<(CborVal, CborVal)>),
    Simple,
}

pub fn b64url_decode(raw: &str) -> Result<Vec<u8>, String> {
    let clean: String = raw
        .trim()
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    URL_SAFE_NO_PAD
        .decode(clean.as_bytes())
        .or_else(|_| URL_SAFE.decode(raw.trim().as_bytes()))
        .or_else(|_| STANDARD.decode(raw.trim().as_bytes()))
        .map_err(|_| "Malformed base64url payload".to_string())
}

struct CborCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> CborCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        let b = *self.buf.get(self.pos).ok_or("CBOR unexpected EOF")?;
        self.pos += 1;
        Ok(b)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(len).ok_or("CBOR length overflow")?;
        let s = self.buf.get(self.pos..end).ok_or("CBOR truncated slice")?;
        self.pos = end;
        Ok(s)
    }

    fn read_arg(&mut self, ai: u8) -> Result<u64, String> {
        match ai {
            0..=23 => Ok(ai as u64),
            24 => Ok(self.read_u8()? as u64),
            25 => {
                let s = self.read_slice(2)?;
                Ok(u16::from_be_bytes([s[0], s[1]]) as u64)
            }
            26 => {
                let s = self.read_slice(4)?;
                Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64)
            }
            27 => {
                let s = self.read_slice(8)?;
                Ok(u64::from_be_bytes([
                    s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
                ]))
            }
            _ => Err("Unsupported indefinite CBOR length".into()),
        }
    }

    fn decode(&mut self, depth: usize) -> Result<CborVal, String> {
        if depth > 8 {
            return Err("CBOR nesting exceeds limit".into());
        }
        let head = self.read_u8()?;
        let major = head >> 5;
        let ai = head & 0x1F;
        match major {
            0 => {
                let n = self.read_arg(ai)?;
                let v = i64::try_from(n).map_err(|_| "CBOR integer overflow".to_string())?;
                Ok(CborVal::Int(v))
            }
            1 => {
                let n = self.read_arg(ai)?;
                let v = i64::try_from(n).map_err(|_| "CBOR integer overflow".to_string())?;
                Ok(CborVal::Int(-1 - v))
            }
            2 => {
                let len = self.read_arg(ai)? as usize;
                if len > 8192 {
                    return Err("CBOR bytes too large".into());
                }
                Ok(CborVal::Bytes(self.read_slice(len)?.to_vec()))
            }
            3 => {
                let len = self.read_arg(ai)? as usize;
                if len > 4096 {
                    return Err("CBOR text too large".into());
                }
                let s = std::str::from_utf8(self.read_slice(len)?)
                    .map_err(|_| "Invalid UTF-8 in CBOR text".to_string())?;
                Ok(CborVal::Text(s.to_string()))
            }
            4 => {
                let len = self.read_arg(ai)? as usize;
                if len > 64 {
                    return Err("CBOR array too large".into());
                }
                let mut arr = Vec::with_capacity(len);
                for _ in 0..len {
                    arr.push(self.decode(depth + 1)?);
                }
                Ok(CborVal::Array(arr))
            }
            5 => {
                let len = self.read_arg(ai)? as usize;
                if len > 64 {
                    return Err("CBOR map too large".into());
                }
                let mut map = Vec::with_capacity(len);
                for _ in 0..len {
                    let k = self.decode(depth + 1)?;
                    let v = self.decode(depth + 1)?;
                    map.push((k, v));
                }
                Ok(CborVal::Map(map))
            }
            6 => {
                let _tag = self.read_arg(ai)?;
                self.decode(depth + 1)
            }
            7 => {
                if ai >= 24 {
                    let _ = self.read_arg(ai)?;
                }
                Ok(CborVal::Simple)
            }
            _ => Err("Invalid CBOR major type".into()),
        }
    }
}

fn cbor_map_get_text<'a>(entries: &'a [(CborVal, CborVal)], key: &str) -> Option<&'a CborVal> {
    entries.iter().find_map(|(k, v)| match k {
        CborVal::Text(t) if t == key => Some(v),
        _ => None,
    })
}

fn cbor_map_get_int(entries: &[(CborVal, CborVal)], key: i64) -> Option<&CborVal> {
    entries.iter().find_map(|(k, v)| match k {
        CborVal::Int(i) if *i == key => Some(v),
        _ => None,
    })
}

fn parse_client_data(
    client_data_b64: &str,
    expected_type: &str,
    expected_challenge_b64: &str,
    expected_origins: &[String],
) -> Result<Vec<u8>, String> {
    let raw = b64url_decode(client_data_b64)?;
    if raw.len() > 4096 {
        return Err("clientDataJSON exceeds maximum size".into());
    }
    let val: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| "Malformed clientDataJSON".to_string())?;
    let typ = val.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if typ != expected_type {
        return Err(format!("Unexpected WebAuthn type: {typ}"));
    }
    let chall = val
        .get("challenge")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim_end_matches('=');
    let want_chall = expected_challenge_b64.trim_end_matches('=');
    if !constant_time_eq(chall.as_bytes(), want_chall.as_bytes()) {
        return Err("WebAuthn challenge mismatch".into());
    }
    let origin = val
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim_end_matches('/')
        .to_ascii_lowercase();
    let origin_ok = expected_origins
        .iter()
        .any(|o| o.trim_end_matches('/').eq_ignore_ascii_case(&origin));
    if !origin_ok {
        return Err(format!("Untrusted WebAuthn origin: {origin}"));
    }
    Ok(raw)
}

fn parse_cose_public_key(cose_bytes: &[u8]) -> Result<(i32, Vec<u8>), String> {
    let mut cur = CborCursor::new(cose_bytes);
    let CborVal::Map(map) = cur.decode(0)? else {
        return Err("COSE key is not a CBOR map".into());
    };
    let kty = match cbor_map_get_int(&map, 1) {
        Some(CborVal::Int(v)) => *v,
        _ => return Err("Missing COSE kty".into()),
    };
    let alg = match cbor_map_get_int(&map, 3) {
        Some(CborVal::Int(v)) => *v as i32,
        _ => return Err("Missing COSE alg".into()),
    };

    match (kty, alg) {
        // EC2 P-256 + ES256 (-7)
        (2, -7) => {
            let crv = match cbor_map_get_int(&map, -1) {
                Some(CborVal::Int(v)) => *v,
                _ => return Err("Missing EC2 crv".into()),
            };
            if crv != 1 {
                return Err("Unsupported EC2 curve (only P-256 allowed)".into());
            }
            let Some(CborVal::Bytes(x)) = cbor_map_get_int(&map, -2) else {
                return Err("Missing EC2 x coordinate".into());
            };
            let Some(CborVal::Bytes(y)) = cbor_map_get_int(&map, -3) else {
                return Err("Missing EC2 y coordinate".into());
            };
            if x.len() != 32 || y.len() != 32 {
                return Err("Invalid P-256 coordinate length".into());
            }
            let mut uncompressed = Vec::with_capacity(65);
            uncompressed.push(0x04);
            uncompressed.extend_from_slice(x);
            uncompressed.extend_from_slice(y);
            Ok((-7, uncompressed))
        }
        // OKP Ed25519 + EdDSA (-8)
        (1, -8) => {
            let crv = match cbor_map_get_int(&map, -1) {
                Some(CborVal::Int(v)) => *v,
                _ => return Err("Missing OKP crv".into()),
            };
            if crv != 6 {
                return Err("Unsupported OKP curve (only Ed25519 allowed)".into());
            }
            let Some(CborVal::Bytes(x)) = cbor_map_get_int(&map, -2) else {
                return Err("Missing Ed25519 public key bytes".into());
            };
            if x.len() != 32 {
                return Err("Invalid Ed25519 key length".into());
            }
            Ok((-8, x.clone()))
        }
        _ => Err("Unsupported Passkey algorithm (expected ES256 or Ed25519)".into()),
    }
}

pub fn verify_registration(
    expected_challenge_b64: &str,
    expected_origins: &[String],
    expected_rp_id: &str,
    client_data_b64: &str,
    attestation_object_b64: &str,
) -> Result<VerifiedCredential, String> {
    let _client_raw = parse_client_data(
        client_data_b64,
        "webauthn.create",
        expected_challenge_b64,
        expected_origins,
    )?;

    let att_raw = b64url_decode(attestation_object_b64)?;
    if att_raw.len() > 8192 {
        return Err("attestationObject exceeds size limit".into());
    }
    let mut cur = CborCursor::new(&att_raw);
    let CborVal::Map(att_map) = cur.decode(0)? else {
        return Err("attestationObject is not a CBOR map".into());
    };
    let Some(CborVal::Bytes(auth_data)) = cbor_map_get_text(&att_map, "authData") else {
        return Err("Missing authData in attestationObject".into());
    };
    if auth_data.len() < 55 {
        return Err("authData truncated".into());
    }

    let rp_hash = Sha256::digest(expected_rp_id.as_bytes());
    if !constant_time_eq(&auth_data[0..32], rp_hash.as_slice()) {
        return Err("WebAuthn RP ID hash mismatch".into());
    }

    let flags = auth_data[32];
    let up = (flags & 0x01) != 0;
    let at = (flags & 0x40) != 0;
    if !up || !at {
        return Err("WebAuthn UP or AT flag missing during registration".into());
    }

    let sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    if cred_len == 0 || cred_len > 1024 || auth_data.len() < 55 + cred_len + 2 {
        return Err("Invalid attested credentialId length".into());
    }
    let cred_id = &auth_data[55..55 + cred_len];
    let cose_slice = &auth_data[55 + cred_len..];
    let (cose_alg, pubkey_bytes) = parse_cose_public_key(cose_slice)?;

    Ok(VerifiedCredential {
        credential_id_b64: URL_SAFE_NO_PAD.encode(cred_id),
        cose_alg,
        public_key_b64: URL_SAFE_NO_PAD.encode(pubkey_bytes),
        sign_count,
    })
}

pub struct WebAuthnAssertionInput<'a> {
    pub expected_challenge_b64: &'a str,
    pub expected_origins: &'a [String],
    pub expected_rp_id: &'a str,
    pub cose_alg: i32,
    pub public_key_b64: &'a str,
    pub stored_sign_count: u32,
    pub client_data_b64: &'a str,
    pub auth_data_b64: &'a str,
    pub signature_b64: &'a str,
    pub require_uv: bool,
}

pub fn verify_assertion(input: &WebAuthnAssertionInput<'_>) -> Result<u32, String> {
    let client_raw = parse_client_data(
        input.client_data_b64,
        "webauthn.get",
        input.expected_challenge_b64,
        input.expected_origins,
    )?;
    let auth_data = b64url_decode(input.auth_data_b64)?;
    if auth_data.len() < 37 {
        return Err("WebAuthn authData too short".into());
    }
    let rp_hash = Sha256::digest(input.expected_rp_id.as_bytes());
    if !constant_time_eq(&auth_data[0..32], rp_hash.as_slice()) {
        return Err("WebAuthn RP ID hash mismatch".into());
    }
    let flags = auth_data[32];
    if (flags & 0x01) == 0 {
        return Err("WebAuthn User Present (UP) flag missing".into());
    }
    if input.require_uv && (flags & 0x04) == 0 {
        return Err("WebAuthn User Verification (UV) required".into());
    }
    let new_sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    if (input.stored_sign_count > 0 || new_sign_count > 0)
        && new_sign_count <= input.stored_sign_count
    {
        return Err("WebAuthn signature counter regression detected".into());
    }

    let pub_bytes = b64url_decode(input.public_key_b64)?;
    let sig_bytes = b64url_decode(input.signature_b64)?;

    let client_hash = Sha256::digest(&client_raw);
    let mut signed_data = Vec::with_capacity(auth_data.len() + 32);
    signed_data.extend_from_slice(&auth_data);
    signed_data.extend_from_slice(client_hash.as_slice());

    let verifier = match input.cose_alg {
        -7 => UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &pub_bytes),
        -8 => UnparsedPublicKey::new(&ED25519, &pub_bytes),
        _ => return Err("Unsupported stored Passkey algorithm".into()),
    };
    verifier
        .verify(&signed_data, &sig_bytes)
        .map_err(|_| "WebAuthn cryptographic signature verification failed".to_string())?;

    Ok(new_sign_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    fn encode_cbor_bytes(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if b.len() < 24 {
            out.push(0x40 | (b.len() as u8));
        } else {
            out.push(0x58);
            out.push(b.len() as u8);
        }
        out.extend_from_slice(b);
        out
    }

    fn encode_p256_cose(pub_uncompressed: &[u8]) -> Vec<u8> {
        // { 1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y }
        let mut out = vec![0xA5]; // map(5)
        out.extend_from_slice(&[0x01, 0x02]); // 1: 2
        out.extend_from_slice(&[0x03, 0x26]); // 3: -7
        out.extend_from_slice(&[0x20, 0x01]); // -1: 1
        out.push(0x21); // -2
        out.extend_from_slice(&encode_cbor_bytes(&pub_uncompressed[1..33]));
        out.push(0x22); // -3
        out.extend_from_slice(&encode_cbor_bytes(&pub_uncompressed[33..65]));
        out
    }

    pub(crate) fn build_test_attestation(
        rp_id: &str,
        cred_id: &[u8],
        pub_uncompressed: &[u8],
        sign_count: u32,
    ) -> String {
        let rp_hash = Sha256::digest(rp_id.as_bytes());
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(rp_hash.as_slice());
        auth_data.push(0x45); // UP | UV | AT
        auth_data.extend_from_slice(&sign_count.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]); // aaguid
        auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(cred_id);
        auth_data.extend_from_slice(&encode_p256_cose(pub_uncompressed));

        let mut att = vec![0xA1]; // map(1)
        att.push(0x68); // text(8) "authData"
        att.extend_from_slice(b"authData");
        // bstr length
        let l = auth_data.len();
        att.push(0x58);
        att.push(l as u8);
        att.extend_from_slice(&auth_data);
        URL_SAFE_NO_PAD.encode(att)
    }

    #[test]
    fn webauthn_es256_registration_and_assertion_verify_and_reject_tamper() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let pub_bytes = kp.public_key().as_ref();

        let rp_id = "bugs.example.com";
        let origins = vec!["https://bugs.example.com".to_string()];
        let reg_chall = URL_SAFE_NO_PAD.encode(b"reg-challenge-12345");
        let reg_cd_json = serde_json::json!({
            "type": "webauthn.create",
            "challenge": reg_chall,
            "origin": "https://bugs.example.com"
        })
        .to_string();
        let reg_cd_b64 = URL_SAFE_NO_PAD.encode(reg_cd_json.as_bytes());
        let att_b64 = build_test_attestation(rp_id, b"cred-alpha-1", pub_bytes, 1);

        let verified =
            verify_registration(&reg_chall, &origins, rp_id, &reg_cd_b64, &att_b64).unwrap();
        assert_eq!(verified.cose_alg, -7);
        assert_eq!(verified.sign_count, 1);

        // Now assert
        let auth_chall = URL_SAFE_NO_PAD.encode(b"login-challenge-999");
        let auth_cd_json = serde_json::json!({
            "type": "webauthn.get",
            "challenge": auth_chall,
            "origin": "https://bugs.example.com"
        })
        .to_string();
        let auth_cd_raw = auth_cd_json.as_bytes();
        let auth_cd_b64 = URL_SAFE_NO_PAD.encode(auth_cd_raw);

        let rp_hash = Sha256::digest(rp_id.as_bytes());
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(rp_hash.as_slice());
        auth_data.push(0x05); // UP | UV
        auth_data.extend_from_slice(&2u32.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(Sha256::digest(auth_cd_raw).as_slice());
        let sig = kp.sign(&rng, &signed).unwrap();

        let ad_b64 = URL_SAFE_NO_PAD.encode(&auth_data);
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
        let next_cnt = verify_assertion(&WebAuthnAssertionInput {
            expected_challenge_b64: &auth_chall,
            expected_origins: &origins,
            expected_rp_id: rp_id,
            cose_alg: verified.cose_alg,
            public_key_b64: &verified.public_key_b64,
            stored_sign_count: verified.sign_count,
            client_data_b64: &auth_cd_b64,
            auth_data_b64: &ad_b64,
            signature_b64: &sig_b64,
            require_uv: true,
        })
        .unwrap();
        assert_eq!(next_cnt, 2);

        // Missing UV flag (UP-only 0x01) must fail when require_uv = true
        let mut ad_no_uv = auth_data.clone();
        ad_no_uv[32] = 0x01;
        let mut signed_no_uv = ad_no_uv.clone();
        signed_no_uv.extend_from_slice(Sha256::digest(auth_cd_raw).as_slice());
        let sig_no_uv = kp.sign(&rng, &signed_no_uv).unwrap();
        assert!(verify_assertion(&WebAuthnAssertionInput {
            expected_challenge_b64: &auth_chall,
            expected_origins: &origins,
            expected_rp_id: rp_id,
            cose_alg: verified.cose_alg,
            public_key_b64: &verified.public_key_b64,
            stored_sign_count: verified.sign_count,
            client_data_b64: &auth_cd_b64,
            auth_data_b64: &URL_SAFE_NO_PAD.encode(&ad_no_uv),
            signature_b64: &URL_SAFE_NO_PAD.encode(sig_no_uv.as_ref()),
            require_uv: true,
        })
        .is_err());

        // Sign count regression -> rejected (clone protection)
        assert!(verify_assertion(&WebAuthnAssertionInput {
            expected_challenge_b64: &auth_chall,
            expected_origins: &origins,
            expected_rp_id: rp_id,
            cose_alg: verified.cose_alg,
            public_key_b64: &verified.public_key_b64,
            stored_sign_count: 5,
            client_data_b64: &auth_cd_b64,
            auth_data_b64: &ad_b64,
            signature_b64: &sig_b64,
            require_uv: true,
        })
        .is_err());

        // Evil origin -> rejected
        let bad_origins = vec!["https://evil.attacker.com".to_string()];
        assert!(verify_assertion(&WebAuthnAssertionInput {
            expected_challenge_b64: &auth_chall,
            expected_origins: &bad_origins,
            expected_rp_id: rp_id,
            cose_alg: verified.cose_alg,
            public_key_b64: &verified.public_key_b64,
            stored_sign_count: 1,
            client_data_b64: &auth_cd_b64,
            auth_data_b64: &ad_b64,
            signature_b64: &sig_b64,
            require_uv: true,
        })
        .is_err());
    }
}
