use crate::alerts::smtp::send_smtp_alert;
use crate::config::AppConfig;
use crate::security::ssrf::validate_webhook_url;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::Semaphore;

type HmacSha256 = Hmac<Sha256>;

static WEBHOOK_SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();

struct PinnedResolver {
    expected_plain: String,
    expected_bracketed: String,
    addrs: Vec<SocketAddr>,
}

impl ureq::Resolver for PinnedResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        if netloc.eq_ignore_ascii_case(&self.expected_plain)
            || netloc.eq_ignore_ascii_case(&self.expected_bracketed)
        {
            Ok(self.addrs.clone())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Blocked unpinned webhook host resolution",
            ))
        }
    }
}

fn webhook_semaphore() -> Arc<Semaphore> {
    WEBHOOK_SEM.get_or_init(|| Arc::new(Semaphore::new(4))).clone()
}

#[derive(Debug, Clone)]
pub struct AlertDispatchJob {
    pub rule_id: i64,
    pub rule_name: String,
    pub channel_type: String, // "webhook" | "slack" | "discord" | "email"
    pub target_url: String,
    pub webhook_secret: String,
    pub email_to: String,
    pub title: String,
    pub message: String,
    pub level: String,
    pub project_slug: String,
    pub short_id: Option<String>,
}

pub fn sign_webhook_body(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("t={timestamp},v1={sig}")
}

pub fn format_alert_payload(job: &AlertDispatchJob) -> Value {
    match job.channel_type.as_str() {
        "slack" => json!({
            "text": format!("[{}] {}: {}", job.level.to_ascii_uppercase(), job.project_slug, job.title),
            "blocks": [{
                "type": "section",
                "text": { "type": "mrkdwn", "text": format!("*[{}] {}*\n{}", job.project_slug, job.title, job.message) }
            }]
        }),
        "discord" => json!({
            "content": format!("**[{}] {}** ({})\n{}", job.project_slug, job.title, job.level, job.message)
        }),
        _ => json!({
            "event": "bugfinder.alert",
            "rule": job.rule_name,
            "project": job.project_slug,
            "short_id": job.short_id,
            "level": job.level,
            "title": job.title,
            "message": job.message,
            "timestamp": chrono::Utc::now().to_rfc3339()
        }),
    }
}

pub async fn dispatch_alert(config: Arc<AppConfig>, job: AlertDispatchJob) -> Result<(), String> {
    if job.channel_type == "email" {
        let Some(smtp_cfg) = config.smtp.clone() else {
            return Err("SMTP is not configured".into());
        };
        let to = job.email_to.clone();
        let subj = format!("[Bug-Finder][{}] {}", job.project_slug, job.title);
        let body = format!("{}\n\nProject: {}\nLevel: {}\nShort ID: {}", job.message, job.project_slug, job.level, job.short_id.as_deref().unwrap_or("-"));
        return tokio::task::spawn_blocking(move || send_smtp_alert(&smtp_cfg, &to, &subj, &body))
            .await
            .map_err(|e| format!("SMTP join error: {e}"))?;
    }

    let permit = webhook_semaphore()
        .acquire_owned()
        .await
        .map_err(|e| format!("webhook semaphore: {e}"))?;

    let allow_http_dev = config.dev_allow_http_webhooks;
    tokio::task::spawn_blocking(move || {
        let _guard = permit;
        let target = validate_webhook_url(&job.target_url, allow_http_dev)
            .map_err(|e| format!("SSRF blocked webhook: {e}"))?;

        let pinned = PinnedResolver {
            expected_plain: format!("{}:{}", target.host, target.port),
            expected_bracketed: format!("[{}]:{}", target.host, target.port),
            addrs: target.resolved_addrs,
        };
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .redirects(0)
            .resolver(pinned)
            .build();

        let payload = format_alert_payload(&job);
        let body_bytes = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        let ts = chrono::Utc::now().timestamp();
        let mut req = agent
            .post(&target.url)
            .set("Content-Type", "application/json")
            .set("User-Agent", "BugFinder-Alerts/1.0");
        if !job.webhook_secret.is_empty() {
            let sig = sign_webhook_body(&job.webhook_secret, ts, &body_bytes);
            req = req.set("X-BugFinder-Signature", &sig);
        }
        let resp = req.send_bytes(&body_bytes).map_err(|e| format!("Webhook HTTP error: {e}"))?;
        if resp.status() >= 200 && resp.status() < 300 {
            Ok(())
        } else {
            Err(format!("Webhook returned HTTP {}", resp.status()))
        }
    })
    .await
    .map_err(|e| format!("Webhook join error: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_hmac_signature_format() {
        let sig = sign_webhook_body("my-secret", 1700000000, br#"{"ok":true}"#);
        assert!(sig.starts_with("t=1700000000,v1="));
        assert_eq!(sig.len(), "t=1700000000,v1=".len() + 64);
    }
}
