use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsrfError(pub String);

impl std::fmt::Display for SsrfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 0                             // 0.0.0.0/8 ("this host on this network")
        || ip.is_loopback()               // 127.0.0.0/8
        || ip.is_private()                // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || ip.is_link_local()             // 169.254.0.0/16 (cloud metadata)
        || ip.is_unspecified()            // 0.0.0.0/8
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || (o[0] == 100 && (o[1] & 0b1100_0000) == 64) // 100.64.0.0/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)     // 192.0.0.0/24
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15 benchmarking
        || o[0] >= 240
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_blocked_v4(mapped);
    }
    let seg = ip.segments();
    let is_nat64 = seg[0] == 0x0064 && seg[1] == 0xff9b;
    let is_ipv4_compat = seg[0..6] == [0; 6] && (seg[6] != 0 || seg[7] > 1);
    let is_6to4_blocked = if seg[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            (seg[1] & 0xff) as u8,
            (seg[2] >> 8) as u8,
            (seg[2] & 0xff) as u8,
        );
        is_blocked_v4(embedded)
    } else {
        false
    };
    let is_teredo = seg[0] == 0x2001 && seg[1] == 0x0000;
    ip.is_loopback()                  // ::1
        || ip.is_unspecified()        // ::
        || ip.is_multicast()
        || is_nat64
        || is_ipv4_compat
        || is_6to4_blocked
        || is_teredo
        || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA
        || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (seg[0] & 0xffc0) == 0xfec0 // fec0::/10 deprecated site-local
        || (seg[0..6] == [0, 0, 0, 0, 0xffff, 0]) // ::ffff:0:0:0/96 SIIT IPv4-translated
        || (seg[0] == 0x2001 && seg[1] == 0x0db8)
}

#[derive(Debug, Clone)]
pub struct ValidatedTarget {
    pub url: String,
    pub host: String,
    pub port: u16,
    pub resolved_addrs: Vec<SocketAddr>,
}

/// Validates webhook URL syntax and resolves DNS pre-connect, rejecting all private,
/// loopback, link-local, metadata, and internal hostnames against SSRF.
pub fn validate_webhook_url(raw: &str, allow_http_dev: bool) -> Result<ValidatedTarget, SsrfError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(SsrfError("Invalid webhook URL characters".into()));
    }
    let (scheme, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        if !allow_http_dev {
            return Err(SsrfError(
                "Webhook URL must use https:// in production".into(),
            ));
        }
        ("http", r)
    } else {
        return Err(SsrfError("Webhook URL must start with https://".into()));
    };

    let authority = rest.split(&['/', '?', '#'][..]).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || authority.contains('\\') {
        return Err(SsrfError("Invalid webhook authority".into()));
    }

    let (host, port) = if authority.starts_with('[') {
        let end_bracket = authority
            .find(']')
            .ok_or_else(|| SsrfError("Malformed IPv6 host".into()))?;
        let h = &authority[1..end_bracket];
        let after = &authority[end_bracket + 1..];
        let p = if let Some(port_s) = after.strip_prefix(':') {
            port_s
                .parse::<u16>()
                .map_err(|_| SsrfError("Invalid webhook port".into()))?
        } else if scheme == "https" {
            443
        } else {
            80
        };
        (h.to_ascii_lowercase(), p)
    } else if let Some((h, port_s)) = authority.rsplit_once(':') {
        let p = port_s
            .parse::<u16>()
            .map_err(|_| SsrfError("Invalid webhook port".into()))?;
        (h.to_ascii_lowercase(), p)
    } else {
        let p = if scheme == "https" { 443 } else { 80 };
        (authority.to_ascii_lowercase(), p)
    };

    let host_trimmed = host.trim_end_matches('.');
    if host_trimmed.is_empty()
        || host_trimmed == "localhost"
        || host_trimmed.ends_with(".localhost")
        || host_trimmed.ends_with(".local")
        || host_trimmed.ends_with(".internal")
        || host_trimmed == "metadata.google.internal"
    {
        return Err(SsrfError("Blocked internal webhook hostname".into()));
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_blocked_ip(ip) {
            return Err(SsrfError("Blocked private/loopback webhook IP".into()));
        }
        return Ok(ValidatedTarget {
            url: trimmed.to_string(),
            host,
            port,
            resolved_addrs: vec![SocketAddr::new(ip, port)],
        });
    }

    let addrs: Vec<SocketAddr> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| SsrfError(format!("Webhook DNS lookup failed: {e}")))?
        .collect();

    if addrs.is_empty() {
        return Err(SsrfError("Webhook DNS returned zero addresses".into()));
    }
    for addr in &addrs {
        if is_blocked_ip(addr.ip()) {
            return Err(SsrfError(
                "Webhook DNS resolved to blocked private IP".into(),
            ));
        }
    }

    Ok(ValidatedTarget {
        url: trimmed.to_string(),
        host,
        port,
        resolved_addrs: addrs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssrf_blocks_metadata_loopback_and_private_ranges() {
        assert!(validate_webhook_url("http://169.254.169.254/latest/meta-data", true).is_err());
        assert!(validate_webhook_url("https://127.0.0.1:8080/hook", false).is_err());
        assert!(validate_webhook_url("https://0.1.2.3/hook", false).is_err());
        assert!(validate_webhook_url("https://10.0.0.5/hook", false).is_err());
        assert!(validate_webhook_url("https://[::ffff:127.0.0.1]/hook", false).is_err());
        assert!(validate_webhook_url("https://[::127.0.0.1]/hook", false).is_err());
        assert!(validate_webhook_url("https://[64:ff9b::127.0.0.1]/hook", false).is_err());
        assert!(validate_webhook_url("https://[2002:7f00:0001::1]/hook", false).is_err());
        assert!(validate_webhook_url(
            "https://[2001:0000:4136:e378:8000:63bf:3fff:fdd2]/hook",
            false
        )
        .is_err());
        assert!(validate_webhook_url("https://127.0.0.1?foo=bar", false).is_err());
        assert!(validate_webhook_url("https://127.0.0.1#frag", false).is_err());
        assert!(validate_webhook_url("https://user:pass@93.184.216.34/hook", false).is_err());
        assert!(validate_webhook_url("https://93.184.216.34\\@127.0.0.1/hook", false).is_err());
        assert!(validate_webhook_url("https://93.184.216.34/hook\n", false).is_ok()); // trimmed
        assert!(validate_webhook_url("https://93.184.216.34/ho ok", false).is_err());
        assert!(validate_webhook_url("https://internal.service.local/hook", false).is_err());
        assert!(validate_webhook_url("https://localhost./hook", false).is_err());
        assert!(validate_webhook_url("https://[fec0::1]/hook", false).is_err());
        assert!(validate_webhook_url("http://hooks.example.com/hook", false).is_err());
        let ok = validate_webhook_url("https://93.184.216.34/webhook?a=1", false).unwrap();
        assert_eq!(ok.port, 443);
    }
}
