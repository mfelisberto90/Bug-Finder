use crate::config::SmtpConfig;
use base64::{engine::general_purpose::STANDARD, Engine};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::ServerName;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

const MAX_SMTP_RESPONSE_LINES: usize = 64;
const MAX_SMTP_RESPONSE_BYTES: usize = 16 * 1024;

fn sanitize_header_val(s: &str) -> String {
    s.chars().filter(|&c| c != '\r' && c != '\n' && c != '\0').collect()
}

fn extract_smtp_addr(raw: &str) -> String {
    let safe = sanitize_header_val(raw);
    if let (Some(start), Some(end)) = (safe.find('<'), safe.rfind('>')) {
        if start < end {
            return safe[start + 1..end].trim().to_string();
        }
    }
    safe.trim().to_string()
}

fn read_smtp_response<R: Read>(reader: &mut BufReader<R>) -> Result<(u16, String), String> {
    let mut full = String::new();
    let mut code = 0u16;
    for _ in 0..MAX_SMTP_RESPONSE_LINES {
        let mut line = String::new();
        let n = reader
            .take(MAX_SMTP_RESPONSE_BYTES as u64)
            .read_line(&mut line)
            .map_err(|e| format!("SMTP read error: {e}"))?;
        if n == 0 {
            return Err("Unexpected EOF from SMTP server".into());
        }
        if full.len().saturating_add(line.len()) > MAX_SMTP_RESPONSE_BYTES {
            return Err("SMTP response exceeded 16 KiB limit".into());
        }
        full.push_str(&line);
        let bytes = line.as_bytes();
        if bytes.len() >= 3 && bytes[0..3].iter().all(|b| b.is_ascii_digit()) {
            code = line[0..3].parse().unwrap_or(0);
            if bytes.get(3) == Some(&b' ') || bytes.len() == 3 {
                return Ok((code, full));
            }
        } else {
            return Ok((code, full));
        }
    }
    Err("SMTP response exceeded max line limit".into())
}

fn expect_code(res: (u16, String), expected_prefix: u16) -> Result<(), String> {
    if res.0 / 100 == expected_prefix {
        Ok(())
    } else {
        Err(format!("SMTP unexpected code {}: {}", res.0, res.1.trim()))
    }
}

fn make_tls_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn smtp_transaction<S: Read + Write>(
    stream: S,
    cfg: &SmtpConfig,
    to: &str,
    subject: &str,
    body_text: &str,
    already_greeted: bool,
) -> Result<(), String> {
    let mut reader = BufReader::new(stream);
    if !already_greeted {
        expect_code(read_smtp_response(&mut reader)?, 2)?;
    }

    reader
        .get_mut()
        .write_all(b"EHLO bugfinder.local\r\n")
        .map_err(|e| format!("SMTP write EHLO: {e}"))?;
    reader.get_mut().flush().ok();
    let ehlo_res = read_smtp_response(&mut reader)?;
    expect_code(ehlo_res.clone(), 2)?;

    if let (Some(user), Some(pass)) = (&cfg.user, &cfg.password) {
        let ehlo_upper = ehlo_res.1.to_ascii_uppercase();
        if !ehlo_upper.contains("PLAIN") && ehlo_upper.contains("LOGIN") {
            reader
                .get_mut()
                .write_all(b"AUTH LOGIN\r\n")
                .map_err(|e| format!("SMTP write AUTH LOGIN: {e}"))?;
            reader.get_mut().flush().ok();
            expect_code(read_smtp_response(&mut reader)?, 3)?;

            let u_b64 = format!("{}\r\n", STANDARD.encode(user.as_bytes()));
            reader
                .get_mut()
                .write_all(u_b64.as_bytes())
                .map_err(|e| format!("SMTP write user: {e}"))?;
            reader.get_mut().flush().ok();
            expect_code(read_smtp_response(&mut reader)?, 3)?;

            let p_b64 = format!("{}\r\n", STANDARD.encode(pass.as_bytes()));
            reader
                .get_mut()
                .write_all(p_b64.as_bytes())
                .map_err(|e| format!("SMTP write pass: {e}"))?;
            reader.get_mut().flush().ok();
            expect_code(read_smtp_response(&mut reader)?, 2)?;
        } else {
            let auth_raw = format!("\0{user}\0{pass}");
            let encoded = STANDARD.encode(auth_raw.as_bytes());
            let cmd = format!("AUTH PLAIN {encoded}\r\n");
            reader
                .get_mut()
                .write_all(cmd.as_bytes())
                .map_err(|e| format!("SMTP write AUTH: {e}"))?;
            reader.get_mut().flush().ok();
            expect_code(read_smtp_response(&mut reader)?, 2)?;
        }
    }

    let safe_from = sanitize_header_val(&cfg.from);
    let safe_from_addr = extract_smtp_addr(&safe_from);
    let safe_to = extract_smtp_addr(to);
    let safe_subj = sanitize_header_val(subject);

    let mail_from = format!("MAIL FROM:<{safe_from_addr}>\r\n");
    reader
        .get_mut()
        .write_all(mail_from.as_bytes())
        .map_err(|e| format!("SMTP MAIL FROM: {e}"))?;
    reader.get_mut().flush().ok();
    expect_code(read_smtp_response(&mut reader)?, 2)?;

    let rcpt = format!("RCPT TO:<{safe_to}>\r\n");
    reader
        .get_mut()
        .write_all(rcpt.as_bytes())
        .map_err(|e| format!("SMTP RCPT TO: {e}"))?;
    reader.get_mut().flush().ok();
    expect_code(read_smtp_response(&mut reader)?, 2)?;

    reader
        .get_mut()
        .write_all(b"DATA\r\n")
        .map_err(|e| format!("SMTP DATA: {e}"))?;
    reader.get_mut().flush().ok();
    expect_code(read_smtp_response(&mut reader)?, 3)?;

    let mut msg = format!(
        "From: {safe_from}\r\nTo: <{safe_to}>\r\nSubject: {safe_subj}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
    );
    // Dot-stuff lines beginning with '.' per RFC 5321
    for line in body_text.lines() {
        if line.starts_with('.') {
            msg.push('.');
        }
        msg.push_str(line);
        msg.push_str("\r\n");
    }
    msg.push_str(".\r\n");

    reader
        .get_mut()
        .write_all(msg.as_bytes())
        .map_err(|e| format!("SMTP body write: {e}"))?;
    reader.get_mut().flush().ok();
    expect_code(read_smtp_response(&mut reader)?, 2)?;

    let _ = reader.get_mut().write_all(b"QUIT\r\n");
    let _ = reader.get_mut().flush();
    Ok(())
}

/// Zero-crate native TLS SMTP sender (`STARTTLS` on 587 or Implicit TLS on 465).
pub fn send_smtp_alert(cfg: &SmtpConfig, to: &str, subject: &str, body_text: &str) -> Result<(), String> {
    let addrs = (cfg.host.as_str(), cfg.port)
        .to_socket_addrs()
        .map_err(|e| format!("SMTP DNS resolve failed: {e}"))?;
    let mut tcp_opt: Option<TcpStream> = None;
    let mut last_err = String::new();
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(s) => {
                tcp_opt = Some(s);
                break;
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    let tcp = tcp_opt.ok_or_else(|| format!("SMTP connect timeout/failed: {last_err}"))?;
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(10)));

    let tls_cfg = make_tls_config();
    let server_name = ServerName::try_from(cfg.host.clone())
        .map_err(|_| "Invalid SMTP server name for TLS".to_string())?;

    if cfg.implicit_tls {
        let conn = ClientConnection::new(tls_cfg, server_name)
            .map_err(|e| format!("TLS init failed: {e}"))?;
        let tls_stream = StreamOwned::new(conn, tcp);
        return smtp_transaction(tls_stream, cfg, to, subject, body_text, false);
    }

    // STARTTLS upgrade flow
    let mut reader = BufReader::new(tcp);
    expect_code(read_smtp_response(&mut reader)?, 2)?;
    reader
        .get_mut()
        .write_all(b"EHLO bugfinder.local\r\n")
        .map_err(|e| format!("SMTP EHLO: {e}"))?;
    reader.get_mut().flush().ok();
    expect_code(read_smtp_response(&mut reader)?, 2)?;

    reader
        .get_mut()
        .write_all(b"STARTTLS\r\n")
        .map_err(|e| format!("SMTP STARTTLS: {e}"))?;
    reader.get_mut().flush().ok();
    expect_code(read_smtp_response(&mut reader)?, 2)?;

    let plain_tcp = reader.into_inner();
    let conn = ClientConnection::new(tls_cfg, server_name)
        .map_err(|e| format!("STARTTLS handshake init: {e}"))?;
    let tls_stream = StreamOwned::new(conn, plain_tcp);
    smtp_transaction(tls_stream, cfg, to, subject, body_text, true)
}
