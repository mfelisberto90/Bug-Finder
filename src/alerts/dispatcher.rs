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

fn alert_semaphore() -> Arc<Semaphore> {
    WEBHOOK_SEM
        .get_or_init(|| Arc::new(Semaphore::new(2)))
        .clone()
}

#[derive(Debug, Clone)]
pub struct AlertDispatchJob {
    pub organization_id: i64,
    pub rule_id: i64,
    pub rule_name: String,
    pub channel_type: String, // "webhook" | "slack" | "discord" | "telegram" | "email"
    pub target_url: String,
    pub webhook_secret: String,
    pub email_to: String,
    pub title: String,
    pub message: String,
    pub level: String,
    pub project_slug: String,
    pub short_id: Option<String>,
}

fn redact_secret(msg: &str, secret: &str) -> String {
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        return msg.to_string();
    }
    let encoded = trimmed.replace(':', "%3A");
    msg.replace(trimmed, "[REDACTED]")
        .replace(&encoded, "[REDACTED]")
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
        "discord" => {
            let color: u32 = match job.level.to_ascii_lowercase().as_str() {
                "fatal" | "critical" => 0xDC2626,
                "error" => 0xEF4444,
                "warning" | "warn" => 0xF59E0B,
                "info" => 0x3B82F6,
                _ => 0x64748B,
            };
            let title: String = job.title.chars().take(250).collect();
            let desc: String = job.message.chars().take(1500).collect();
            let mut fields = vec![
                json!({ "name": "Project", "value": &job.project_slug, "inline": true }),
                json!({ "name": "Level", "value": job.level.to_ascii_uppercase(), "inline": true }),
                json!({ "name": "Rule", "value": &job.rule_name, "inline": true }),
            ];
            if let Some(sid) = &job.short_id {
                fields.push(json!({ "name": "Issue", "value": sid, "inline": true }));
            }
            json!({
                "content": format!("[{}] {}: {}", job.level.to_ascii_uppercase(), job.project_slug, title),
                "embeds": [{
                    "title": title,
                    "description": desc,
                    "color": color,
                    "fields": fields,
                    "footer": { "text": "Bug-Finder Alerting" }
                }]
            })
        }
        "telegram" => {
            let chat_id = job
                .target_url
                .strip_prefix("telegram:")
                .map(str::trim)
                .unwrap_or("");
            let title: String = job.title.chars().take(240).collect();
            let desc: String = job.message.chars().take(1800).collect();
            let issue_line = job
                .short_id
                .as_deref()
                .map(|s| format!("\nIssue: {s}"))
                .unwrap_or_default();
            let text = format!(
                "[{}] {} — {}\nRule: {}{}\n\n{}",
                job.level.to_ascii_uppercase(),
                job.project_slug,
                title,
                job.rule_name,
                issue_line,
                desc
            );
            let mut body = json!({
                "text": text,
                "disable_web_page_preview": true
            });
            if !chat_id.is_empty() {
                if let Some(obj) = body.as_object_mut() {
                    obj.insert("chat_id".to_string(), json!(chat_id));
                }
            }
            body
        }
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

fn send_http_payload(agent: &ureq::Agent, url: &str, job: &AlertDispatchJob) -> Result<(), String> {
    let payload = format_alert_payload(job);
    let body_bytes = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
    let ts = chrono::Utc::now().timestamp();
    let mut req = agent
        .post(url)
        .set("Content-Type", "application/json")
        .set("User-Agent", "BugFinder-Alerts/1.0");
    if job.channel_type != "telegram" && !job.webhook_secret.is_empty() {
        let sig = sign_webhook_body(&job.webhook_secret, ts, &body_bytes);
        req = req.set("X-BugFinder-Signature", &sig);
    }
    let resp = req
        .send_bytes(&body_bytes)
        .map_err(|e| redact_secret(&format!("Webhook HTTP error: {e}"), &job.webhook_secret))?;
    if resp.status() >= 200 && resp.status() < 300 {
        Ok(())
    } else {
        Err(redact_secret(
            &format!("Webhook returned HTTP {}", resp.status()),
            &job.webhook_secret,
        ))
    }
}

pub async fn dispatch_alert(config: Arc<AppConfig>, job: AlertDispatchJob) -> Result<(), String> {
    if job.channel_type == "email" {
        let Some(smtp_cfg) = config.smtp.clone() else {
            return Err("SMTP is not configured".into());
        };
        let permit = alert_semaphore()
            .acquire_owned()
            .await
            .map_err(|e| format!("alert semaphore: {e}"))?;
        let to = job.email_to.clone();
        let subj = format!("[Bug-Finder][{}] {}", job.project_slug, job.title);
        let body = format!(
            "{}\n\nProject: {}\nLevel: {}\nShort ID: {}",
            job.message,
            job.project_slug,
            job.level,
            job.short_id.as_deref().unwrap_or("-")
        );
        return tokio::task::spawn_blocking(move || {
            let _guard = permit;
            send_smtp_alert(&smtp_cfg, &to, &subj, &body)
        })
        .await
        .map_err(|e| format!("SMTP join error: {e}"))?;
    }

    let effective_url = if job.channel_type == "telegram" {
        if job.target_url.starts_with("telegram:") {
            let tok = job.webhook_secret.trim();
            if tok.is_empty() {
                return Err("Telegram bot token missing".into());
            }
            format!("https://api.telegram.org/bot{tok}/sendMessage")
        } else {
            job.target_url.clone()
        }
    } else {
        job.target_url.clone()
    };

    let permit = alert_semaphore()
        .acquire_owned()
        .await
        .map_err(|e| format!("alert semaphore: {e}"))?;

    let allow_http_dev = config.dev_allow_http_webhooks;
    tokio::task::spawn_blocking(move || {
        let _guard = permit;
        let target = validate_webhook_url(&effective_url, allow_http_dev).map_err(|e| {
            redact_secret(&format!("SSRF blocked webhook: {e}"), &job.webhook_secret)
        })?;

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

        send_http_payload(&agent, &target.url, &job)
    })
    .await
    .map_err(|e| format!("Webhook join error: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn sample_job(channel_type: &str, level: &str) -> AlertDispatchJob {
        AlertDispatchJob {
            organization_id: 1,
            rule_id: 42,
            rule_name: "Critical Errors".into(),
            channel_type: channel_type.into(),
            target_url: if channel_type == "telegram" {
                "telegram:-1001234567890".into()
            } else {
                "https://hooks.example.test/webhook".into()
            },
            webhook_secret: "123456:AAH_SUPER_SECRET_BOT_TOKEN".into(),
            email_to: String::new(),
            title: "TypeError: Cannot read properties of undefined".into(),
            message: "Unhandled rejection in /api/checkout".into(),
            level: level.into(),
            project_slug: "checkout-web".into(),
            short_id: Some("CHK-109".into()),
        }
    }

    #[test]
    fn webhook_hmac_signature_format() {
        let sig = sign_webhook_body("my-secret", 1700000000, br#"{"ok":true}"#);
        assert!(sig.starts_with("t=1700000000,v1="));
        assert_eq!(sig.len(), "t=1700000000,v1=".len() + 64);
    }

    #[test]
    fn discord_rich_embed_payload_format() {
        let p = format_alert_payload(&sample_job("discord", "error"));
        assert!(p["content"]
            .as_str()
            .unwrap()
            .contains("[ERROR] checkout-web"));
        let embed = &p["embeds"][0];
        assert_eq!(embed["color"].as_u64(), Some(0xEF4444));
        assert_eq!(
            embed["footer"]["text"].as_str(),
            Some("Bug-Finder Alerting")
        );
        let fields = embed["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[3]["name"], "Issue");
        assert_eq!(fields[3]["value"], "CHK-109");

        let warn_p = format_alert_payload(&sample_job("discord", "warning"));
        assert_eq!(warn_p["embeds"][0]["color"].as_u64(), Some(0xF59E0B));
    }

    #[test]
    fn telegram_payload_and_secret_redaction() {
        let job = sample_job("telegram", "fatal");
        let p = format_alert_payload(&job);
        assert_eq!(p["chat_id"].as_str(), Some("-1001234567890"));
        assert_eq!(p["disable_web_page_preview"].as_bool(), Some(true));
        let txt = p["text"].as_str().unwrap();
        assert!(txt.contains("[FATAL] checkout-web"));
        assert!(txt.contains("Issue: CHK-109"));

        let leaked = "https://api.telegram.org/bot123456:AAH_SUPER_SECRET_BOT_TOKEN/sendMessage: connection reset";
        let scrubbed = redact_secret(leaked, &job.webhook_secret);
        assert!(!scrubbed.contains("AAH_SUPER_SECRET_BOT_TOKEN"));
        assert!(scrubbed.contains("bot[REDACTED]/sendMessage"));
    }

    fn read_http_request(sock: &mut std::net::TcpStream) -> String {
        let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));
        let mut raw = Vec::with_capacity(2048);
        let mut tmp = [0u8; 1024];
        let mut hdr_end = None;
        let mut content_len = 0usize;
        loop {
            match sock.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    raw.extend_from_slice(&tmp[..n]);
                    if hdr_end.is_none() {
                        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            hdr_end = Some(pos + 4);
                            let hdr_str = String::from_utf8_lossy(&raw[..pos]);
                            for line in hdr_str.lines() {
                                if let Some((k, v)) = line.split_once(':') {
                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                        content_len = v.trim().parse().unwrap_or(0);
                                    }
                                }
                            }
                        }
                    }
                    if let Some(end) = hdr_end {
                        if raw.len() >= end + content_len {
                            break;
                        }
                    }
                }
            }
        }
        String::from_utf8_lossy(&raw).to_string()
    }

    #[test]
    fn wire_delivery_discord_embed_and_telegram_redaction() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut captured = Vec::new();
            for i in 0..2 {
                let (mut sock, _) = listener.accept().unwrap();
                captured.push(read_http_request(&mut sock));
                let resp = if i == 0 {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                } else {
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 3\r\nConnection: close\r\n\r\nerr"
                };
                sock.write_all(resp.as_bytes()).unwrap();
            }
            captured
        });

        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(2))
            .timeout(Duration::from_secs(2))
            .redirects(0)
            .build();

        let discord_job = sample_job("discord", "error");
        let url_ok = format!("http://{addr}/discord");
        send_http_payload(&agent, &url_ok, &discord_job).expect("discord wire ok");

        let mut tg_job = sample_job("telegram", "fatal");
        tg_job.target_url = "telegram:-100999888".to_string();
        let url_tg_err = format!("http://{addr}/bot{}/sendMessage", tg_job.webhook_secret);
        let err = send_http_payload(&agent, &url_tg_err, &tg_job).unwrap_err();
        assert!(!err.contains(&tg_job.webhook_secret));

        let captured = handle.join().unwrap();
        let hdrs_and_body_0 = &captured[0];
        assert!(hdrs_and_body_0
            .to_ascii_lowercase()
            .contains("x-bugfinder-signature:"));
        assert!(hdrs_and_body_0.contains("\"embeds\""));

        let hdrs_and_body_1 = &captured[1];
        assert!(!hdrs_and_body_1
            .to_ascii_lowercase()
            .contains("x-bugfinder-signature:"));
        assert!(hdrs_and_body_1.contains("-100999888"));
        assert!(hdrs_and_body_1.contains("disable_web_page_preview"));
    }
}
