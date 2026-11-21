use crate::alerts::smtp::send_smtp_alert;
use crate::config::AppConfig;
use crate::security::ssrf::validate_webhook_url;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::Semaphore;

type HmacSha256 = Hmac<Sha256>;

static HTTP_AGENT: OnceLock<ureq::Agent> = OnceLock::new();
static WEBHOOK_SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn http_agent() -> &'static ureq::Agent {
    HTTP_AGENT.get_or_init(|| {
        ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .redirects(0)
            .build()
    })
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

    let target = validate_webhook_url(&job.target_url, config.dev_allow_http_webhooks)
        .map_err(|e| format!("SSRF blocked webhook: {e}"))?;

    let permit = webhook_semaphore()
        .acquire_owned()
        .await
        .map_err(|e| format!("webhook semaphore: {e}"))?;

    tokio::task::spawn_blocking(move || {
        let _guard = permit;
        let payload = format_alert_payload(&job);
        let body_bytes = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        let ts = chrono::Utc::now().timestamp();
        let mut req = http_agent()
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
