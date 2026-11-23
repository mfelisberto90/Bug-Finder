use crate::config::OidcConfig;
use crate::security::auth::constant_time_eq;
use crate::security::crypto::{open_secret, seal_secret};
use crate::security::ssrf::validate_webhook_url;
use crate::security::webauthn::b64url_decode;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature::{
    UnparsedPublicKey, ECDSA_P256_SHA256_FIXED, ED25519, RSA_PKCS1_2048_8192_SHA256,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const OIDC_TX_AAD: &[u8] = b"oidc_tx_v1";
const OIDC_CACHE_TTL: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcTxState {
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub issued_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkKey {
    pub kid: Option<String>,
    pub kty: String,
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
    pub alg: Option<String>,
    pub crv: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<JwkKey>,
}

#[derive(Debug, Clone)]
pub struct OidcClaims {
    pub sub: String,
    pub email: String,
    pub iss: String,
    pub nonce: String,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawOidcClaims {
    iss: String,
    sub: String,
    aud: Value,
    #[serde(default)]
    azp: Option<String>,
    exp: i64,
    #[serde(default)]
    nbf: Option<i64>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
}

struct CachedOidcMeta {
    doc: OidcDiscovery,
    jwks: JwkSet,
    fetched_at: Instant,
}

pub struct OidcClient {
    config: OidcConfig,
    allow_http_dev: bool,
    allow_loopback_for_test: bool,
    cache: Mutex<Option<CachedOidcMeta>>,
}

struct PinnedOidcResolver {
    expected_plain: String,
    expected_bracketed: String,
    addrs: Vec<SocketAddr>,
}

impl ureq::Resolver for PinnedOidcResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        if netloc.eq_ignore_ascii_case(&self.expected_plain)
            || netloc.eq_ignore_ascii_case(&self.expected_bracketed)
        {
            Ok(self.addrs.clone())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Blocked unpinned OIDC host resolution",
            ))
        }
    }
}

pub fn pkce_s256_challenge(verifier: &str) -> String {
    let mut h = Sha256::new();
    h.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(h.finalize())
}

pub fn url_encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn seal_oidc_tx_cookie(app_key: &[u8; 32], st: &OidcTxState) -> Result<String, String> {
    let json = serde_json::to_string(st).map_err(|e| format!("OIDC state encode: {e}"))?;
    seal_secret(app_key, OIDC_TX_AAD, &json)
}

pub fn open_oidc_tx_cookie(
    app_key: &[u8; 32],
    sealed: &str,
    now_sec: i64,
) -> Result<OidcTxState, String> {
    let plain = open_secret(app_key, OIDC_TX_AAD, sealed, false)?;
    let st: OidcTxState =
        serde_json::from_str(&plain).map_err(|_| "Malformed OIDC state".to_string())?;
    if now_sec - st.issued_at > 300 || st.issued_at - now_sec > 30 {
        return Err("OIDC login state expired".into());
    }
    Ok(st)
}

fn push_der_len(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len <= 0xff {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xff) as u8);
    }
}

fn push_der_integer(buf: &mut Vec<u8>, raw: &[u8]) {
    let stripped = raw
        .iter()
        .position(|&b| b != 0)
        .map(|i| &raw[i..])
        .unwrap_or(&[0]);
    let needs_pad = stripped.first().map(|&b| b & 0x80 != 0).unwrap_or(false);
    let len = stripped.len() + usize::from(needs_pad);
    buf.push(0x02);
    push_der_len(buf, len);
    if needs_pad {
        buf.push(0x00);
    }
    buf.extend_from_slice(stripped);
}

fn encode_pkcs1_rsa_pub_der(n: &[u8], e: &[u8]) -> Result<Vec<u8>, String> {
    if n.len() < 128 || e.is_empty() {
        return Err("Invalid RSA JWK parameters".into());
    }
    let mut inner = Vec::with_capacity(n.len() + e.len() + 16);
    push_der_integer(&mut inner, n);
    push_der_integer(&mut inner, e);
    let mut seq = Vec::with_capacity(inner.len() + 4);
    seq.push(0x30);
    push_der_len(&mut seq, inner.len());
    seq.extend_from_slice(&inner);
    Ok(seq)
}

fn verify_with_jwk(
    alg: &str,
    key: &JwkKey,
    signing_input: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    if let Some(ref k_use) = key.use_ {
        if k_use != "sig" {
            return Err("JWK key use is not sig".into());
        }
    }
    if let Some(ref k_alg) = key.alg {
        if k_alg != alg {
            return Err("JWK alg mismatch with JWT header".into());
        }
    }
    match alg {
        "RS256" => {
            if key.kty != "RSA" {
                return Err("JWK kty mismatch for RS256".into());
            }
            let n = b64url_decode(key.n.as_deref().ok_or("Missing RSA modulus")?)?;
            let e = b64url_decode(key.e.as_deref().ok_or("Missing RSA exponent")?)?;
            let der = encode_pkcs1_rsa_pub_der(&n, &e)?;
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &der)
                .verify(signing_input, sig)
                .map_err(|_| "RS256 signature verification failed".to_string())
        }
        "ES256" => {
            if key.kty != "EC" || key.crv.as_deref() != Some("P-256") {
                return Err("JWK kty/crv mismatch for ES256".into());
            }
            let x = b64url_decode(key.x.as_deref().ok_or("Missing EC x")?)?;
            let y = b64url_decode(key.y.as_deref().ok_or("Missing EC y")?)?;
            if x.len() != 32 || y.len() != 32 {
                return Err("Invalid P-256 coordinate length".into());
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
                .verify(signing_input, sig)
                .map_err(|_| "ES256 signature verification failed".to_string())
        }
        "EdDSA" => {
            if key.kty != "OKP" || key.crv.as_deref() != Some("Ed25519") {
                return Err("JWK kty/crv mismatch for EdDSA".into());
            }
            let x = b64url_decode(key.x.as_deref().ok_or("Missing Ed25519 key")?)?;
            if x.len() != 32 {
                return Err("Invalid Ed25519 public key length".into());
            }
            UnparsedPublicKey::new(&ED25519, &x)
                .verify(signing_input, sig)
                .map_err(|_| "EdDSA signature verification failed".to_string())
        }
        other => Err(format!("Unsupported or rejected OIDC JWT alg: {other}")),
    }
}

pub fn verify_id_token_jwt(
    jwt: &str,
    jwks: &JwkSet,
    expected_issuer: &str,
    expected_aud: &str,
    expected_nonce: &str,
    now_sec: i64,
) -> Result<OidcClaims, String> {
    let mut parts = jwt.split('.');
    let h_b64 = parts.next().ok_or("Malformed JWT")?;
    let p_b64 = parts.next().ok_or("Malformed JWT")?;
    let s_b64 = parts.next().ok_or("Malformed JWT")?;
    if parts.next().is_some() || h_b64.is_empty() || p_b64.is_empty() || s_b64.is_empty() {
        return Err("Malformed OIDC id_token structure".into());
    }

    let hdr_bytes = b64url_decode(h_b64)?;
    let hdr: JwtHeader =
        serde_json::from_slice(&hdr_bytes).map_err(|_| "Invalid JWT header".to_string())?;
    if !matches!(hdr.alg.as_str(), "RS256" | "ES256" | "EdDSA") {
        return Err(format!("Rejected insecure OIDC JWT alg: {}", hdr.alg));
    }

    let sig = b64url_decode(s_b64)?;
    let signing_input = format!("{h_b64}.{p_b64}");

    let mut matched_any = false;
    let mut verified = false;
    for key in &jwks.keys {
        if let Some(ref want_kid) = hdr.kid {
            if key.kid.as_deref() != Some(want_kid.as_str()) {
                continue;
            }
        }
        matched_any = true;
        if verify_with_jwk(&hdr.alg, key, signing_input.as_bytes(), &sig).is_ok() {
            verified = true;
            break;
        }
    }
    if !matched_any {
        return Err("OIDC signing key not found in JWKS".into());
    }
    if !verified {
        return Err("OIDC id_token signature verification failed".into());
    }

    let pay_bytes = b64url_decode(p_b64)?;
    let claims: RawOidcClaims =
        serde_json::from_slice(&pay_bytes).map_err(|_| "Invalid OIDC claims JSON".to_string())?;

    if claims.iss.trim_end_matches('/') != expected_issuer.trim_end_matches('/') {
        return Err("OIDC issuer mismatch".into());
    }

    let aud_ok = match &claims.aud {
        Value::String(s) => s == expected_aud,
        Value::Array(arr) => {
            let contains = arr.iter().any(|v| v.as_str() == Some(expected_aud));
            let azp_ok = if arr.len() > 1 {
                claims.azp.as_deref() == Some(expected_aud)
            } else {
                true
            };
            contains && azp_ok
        }
        _ => false,
    };
    if !aud_ok {
        return Err("OIDC audience mismatch".into());
    }
    if claims.exp + 30 <= now_sec {
        return Err("OIDC id_token expired".into());
    }
    if claims.nbf.unwrap_or(0) > now_sec + 60 {
        return Err("OIDC id_token not yet valid".into());
    }

    let got_nonce = claims.nonce.as_deref().unwrap_or("");
    if got_nonce.is_empty() || !constant_time_eq(got_nonce.as_bytes(), expected_nonce.as_bytes()) {
        return Err("OIDC nonce mismatch".into());
    }
    if claims.email_verified != Some(true) {
        return Err("OIDC account email is not verified".into());
    }
    let email = claims
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty() && e.contains('@'))
        .ok_or_else(|| "OIDC token missing verified email".to_string())?;

    Ok(OidcClaims {
        sub: claims.sub,
        email: email.to_ascii_lowercase(),
        iss: claims.iss,
        nonce: got_nonce.to_string(),
    })
}

impl OidcClient {
    pub fn new(config: OidcConfig, allow_http_dev: bool) -> Self {
        Self {
            config,
            allow_http_dev,
            allow_loopback_for_test: false,
            cache: Mutex::new(None),
        }
    }

    pub fn new_with_loopback_for_test(config: OidcConfig) -> Self {
        Self {
            config,
            allow_http_dev: true,
            allow_loopback_for_test: true,
            cache: Mutex::new(None),
        }
    }

    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    fn build_http_agent(&self, raw_url: &str) -> Result<(String, ureq::Agent), String> {
        if self.allow_loopback_for_test {
            if let Some(rest) = raw_url.strip_prefix("http://") {
                let authority = rest.split(&['/', '?', '#'][..]).next().unwrap_or("");
                if authority.starts_with("127.0.0.1:") || authority.starts_with("localhost:") {
                    let agent = ureq::AgentBuilder::new()
                        .timeout_connect(Duration::from_secs(3))
                        .timeout(Duration::from_secs(5))
                        .redirects(0)
                        .build();
                    return Ok((raw_url.to_string(), agent));
                }
            }
        }
        let target = validate_webhook_url(raw_url, self.allow_http_dev)
            .map_err(|e| format!("SSRF blocked OIDC endpoint: {e}"))?;
        let resolver = PinnedOidcResolver {
            expected_plain: format!("{}:{}", target.host, target.port),
            expected_bracketed: format!("[{}]:{}", target.host, target.port),
            addrs: target.resolved_addrs,
        };
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .redirects(0)
            .resolver(resolver)
            .build();
        Ok((target.url, agent))
    }

    fn read_bounded_json<T: for<'de> Deserialize<'de>>(
        &self,
        resp: ureq::Response,
        label: &str,
    ) -> Result<T, String> {
        use std::io::Read;
        const MAX_OIDC_BODY: usize = 512 * 1024;
        let mut buf = Vec::with_capacity(8192);
        resp.into_reader()
            .take((MAX_OIDC_BODY + 1) as u64)
            .read_to_end(&mut buf)
            .map_err(|_| format!("{label} read failed"))?;
        if buf.len() > MAX_OIDC_BODY {
            return Err(format!("{label} exceeded 512 KiB"));
        }
        serde_json::from_slice(&buf).map_err(|_| format!("Invalid {label} JSON"))
    }

    fn fetch_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T, String> {
        let (safe_url, agent) = self.build_http_agent(url)?;
        let resp = agent
            .get(&safe_url)
            .set("Accept", "application/json")
            .call()
            .map_err(|e| format!("OIDC HTTP GET failed: {e}"))?;
        self.read_bounded_json(resp, "OIDC metadata")
    }

    pub fn load_metadata_blocking(
        &self,
        force_refresh: bool,
    ) -> Result<(OidcDiscovery, JwkSet), String> {
        if !force_refresh {
            let guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(c) = guard.as_ref() {
                if c.fetched_at.elapsed() < OIDC_CACHE_TTL {
                    return Ok((c.doc.clone(), c.jwks.clone()));
                }
            }
        }

        let well_known = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let doc: OidcDiscovery = self.fetch_json(&well_known)?;
        if doc.issuer.trim_end_matches('/') != self.config.issuer.trim_end_matches('/') {
            return Err("OIDC discovery issuer mismatch".into());
        }
        let jwks: JwkSet = self.fetch_json(&doc.jwks_uri)?;

        let mut guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(CachedOidcMeta {
            doc: doc.clone(),
            jwks: jwks.clone(),
            fetched_at: Instant::now(),
        });
        Ok((doc, jwks))
    }

    pub fn build_authorize_url_blocking(
        &self,
        state: &str,
        nonce: &str,
        code_verifier: &str,
    ) -> Result<String, String> {
        let (doc, _) = self.load_metadata_blocking(false)?;
        let auth_ep = doc.authorization_endpoint.trim();
        if auth_ep.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err("OIDC authorization_endpoint contains invalid characters".into());
        }
        if !auth_ep.starts_with("https://")
            && !(self.allow_http_dev && auth_ep.starts_with("http://"))
        {
            return Err("OIDC authorization_endpoint must use https://".into());
        }
        let challenge = pkce_s256_challenge(code_verifier);
        let sep = if auth_ep.contains('?') { '&' } else { '?' };
        Ok(format!(
            "{auth_ep}{sep}response_type=code&client_id={}&redirect_uri={}&scope=openid%20email%20profile&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            url_encode(&self.config.client_id),
            url_encode(&self.config.redirect_uri),
            url_encode(state),
            url_encode(nonce),
            url_encode(&challenge),
        ))
    }

    pub fn exchange_and_verify_blocking(
        &self,
        code: &str,
        expected_nonce: &str,
        code_verifier: &str,
        now_sec: i64,
    ) -> Result<OidcClaims, String> {
        let (doc, jwks) = self.load_metadata_blocking(false)?;
        let (safe_url, agent) = self.build_http_agent(&doc.token_endpoint)?;

        let body = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}",
            url_encode(code),
            url_encode(&self.config.redirect_uri),
            url_encode(&self.config.client_id),
            url_encode(&self.config.client_secret),
            url_encode(code_verifier),
        );

        let resp = agent
            .post(&safe_url)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .set("Accept", "application/json")
            .send_string(&body)
            .map_err(|_| "OIDC token exchange request failed".to_string())?;
        let val: Value = self.read_bounded_json(resp, "OIDC token response")?;
        let id_token = val
            .get("id_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "OIDC token response missing id_token".to_string())?;

        match verify_id_token_jwt(
            id_token,
            &jwks,
            &self.config.issuer,
            &self.config.client_id,
            expected_nonce,
            now_sec,
        ) {
            Ok(claims) => Ok(claims),
            Err(err) if err.contains("JWKS") => {
                // Key rotation recovery: force refresh JWKS once before failing
                let (_, fresh_jwks) = self.load_metadata_blocking(true)?;
                verify_id_token_jwt(
                    id_token,
                    &fresh_jwks,
                    &self.config.issuer,
                    &self.config.client_id,
                    expected_nonce,
                    now_sec,
                )
            }
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use serde_json::json;

    #[test]
    fn pkce_and_tx_state_aead_roundtrip_and_tamper_fail() {
        let ch = pkce_s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        assert_eq!(ch, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");

        let key = [42u8; 32];
        let st = OidcTxState {
            state: "st_123".into(),
            nonce: "nn_456".into(),
            code_verifier: "cv_789".into(),
            issued_at: 1_700_000_000,
        };
        let sealed = seal_oidc_tx_cookie(&key, &st).unwrap();
        let opened = open_oidc_tx_cookie(&key, &sealed, 1_700_000_120).unwrap();
        assert_eq!(opened.state, "st_123");
        assert_eq!(opened.nonce, "nn_456");

        // Tamper + expiry + wrong key fail closed
        assert!(open_oidc_tx_cookie(&key, &sealed, 1_700_000_400).is_err());
        assert!(open_oidc_tx_cookie(&[9u8; 32], &sealed, 1_700_000_010).is_err());
    }

    #[test]
    fn jwt_verification_supports_es256_and_eddsa_and_rejects_downgrades() {
        let rng = SystemRandom::new();

        // 1. ES256 P-256 test key & token
        let pkcs8_ec =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let ec_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_ec.as_ref(), &rng)
                .unwrap();
        let ec_pub = ec_kp.public_key().as_ref();
        assert_eq!(ec_pub.len(), 65);

        let jwks = JwkSet {
            keys: vec![JwkKey {
                kid: Some("ec1".into()),
                kty: "EC".into(),
                use_: Some("sig".into()),
                alg: Some("ES256".into()),
                crv: Some("P-256".into()),
                n: None,
                e: None,
                x: Some(URL_SAFE_NO_PAD.encode(&ec_pub[1..33])),
                y: Some(URL_SAFE_NO_PAD.encode(&ec_pub[33..65])),
            }],
        };

        let hdr = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"ec1"}"#);
        let pay = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "iss": "https://idp.example.com",
                "sub": "u-1",
                "aud": "client-1",
                "exp": 2_000_000_000i64,
                "nonce": "n-ok",
                "email": "Dev@Example.com",
                "email_verified": true
            }))
            .unwrap(),
        );
        let msg = format!("{hdr}.{pay}");
        let sig = ec_kp.sign(&rng, msg.as_bytes()).unwrap();
        let jwt = format!("{msg}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()));

        let claims = verify_id_token_jwt(
            &jwt,
            &jwks,
            "https://idp.example.com",
            "client-1",
            "n-ok",
            1_900_000_000,
        )
        .unwrap();
        assert_eq!(claims.email, "dev@example.com");

        // Negative cases: alg:none, HS256, expired, wrong nonce, unverified email
        let none_hdr = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let none_jwt = format!("{none_hdr}.{pay}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()));
        assert!(verify_id_token_jwt(
            &none_jwt,
            &jwks,
            "https://idp.example.com",
            "client-1",
            "n-ok",
            1_900_000_000
        )
        .is_err());

        let hs_hdr = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","kid":"ec1"}"#);
        let hs_jwt = format!("{hs_hdr}.{pay}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()));
        assert!(verify_id_token_jwt(
            &hs_jwt,
            &jwks,
            "https://idp.example.com",
            "client-1",
            "n-ok",
            1_900_000_000
        )
        .is_err());

        assert!(verify_id_token_jwt(
            &jwt,
            &jwks,
            "https://idp.example.com",
            "client-1",
            "wrong-nonce",
            1_900_000_000
        )
        .is_err());
        assert!(verify_id_token_jwt(
            &jwt,
            &jwks,
            "https://idp.example.com",
            "client-1",
            "n-ok",
            2_000_000_500
        )
        .is_err());

        // 2. EdDSA Ed25519 test key & token
        let pkcs8_ed = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let ed_kp = Ed25519KeyPair::from_pkcs8(pkcs8_ed.as_ref()).unwrap();
        let ed_jwks = JwkSet {
            keys: vec![JwkKey {
                kid: Some("ed1".into()),
                kty: "OKP".into(),
                use_: Some("sig".into()),
                alg: Some("EdDSA".into()),
                crv: Some("Ed25519".into()),
                n: None,
                e: None,
                x: Some(URL_SAFE_NO_PAD.encode(ed_kp.public_key().as_ref())),
                y: None,
            }],
        };
        let ed_hdr = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"ed1"}"#);
        let ed_msg = format!("{ed_hdr}.{pay}");
        let ed_sig = ed_kp.sign(ed_msg.as_bytes());
        let ed_jwt = format!("{ed_msg}.{}", URL_SAFE_NO_PAD.encode(ed_sig.as_ref()));
        assert!(verify_id_token_jwt(
            &ed_jwt,
            &ed_jwks,
            "https://idp.example.com",
            "client-1",
            "n-ok",
            1_900_000_000
        )
        .is_ok());

        // Reject unverified email and enc-use JWK
        let unverified_pay = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "iss": "https://idp.example.com",
                "sub": "u-1",
                "aud": "client-1",
                "exp": 2_000_000_000i64,
                "nonce": "n-ok",
                "email": "dev@example.com",
                "email_verified": false
            }))
            .unwrap(),
        );
        let unv_msg = format!("{hdr}.{unverified_pay}");
        let unv_sig = ec_kp.sign(&rng, unv_msg.as_bytes()).unwrap();
        let unv_jwt = format!("{unv_msg}.{}", URL_SAFE_NO_PAD.encode(unv_sig.as_ref()));
        assert!(verify_id_token_jwt(
            &unv_jwt,
            &jwks,
            "https://idp.example.com",
            "client-1",
            "n-ok",
            1_900_000_000
        )
        .is_err());

        let mut enc_only = ed_jwks.clone();
        enc_only.keys[0].use_ = Some("enc".into());
        assert!(verify_id_token_jwt(
            &ed_jwt,
            &enc_only,
            "https://idp.example.com",
            "client-1",
            "n-ok",
            1_900_000_000
        )
        .is_err());

        // Also validate PKCS#1 RSA DER encoder produces valid ASN.1 sequence
        let fake_n = vec![0xab; 256];
        let fake_e = vec![0x01, 0x00, 0x01];
        let der = encode_pkcs1_rsa_pub_der(&fake_n, &fake_e).unwrap();
        assert_eq!(der[0], 0x30);
    }
}
