use std::env;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    Serve {
        desktop_app: bool,
    },
    Migrate,
    Backup {
        out_path: PathBuf,
    },
    Doctor {
        url: Option<String>,
        json: bool,
    },
    Healthcheck {
        url: String,
    },
    Tail {
        base_url: String,
        token: String,
        org: String,
        project: Option<i64>,
        level: Option<String>,
        query: Option<String>,
    },
    Mcp {
        org: String,
        token: Option<String>,
    },
    TestEvent {
        dsn: String,
    },
    TestLog {
        dsn: String,
    },
    Init {
        dir: PathBuf,
        dsn: String,
        stack: String,
        sdk: String,
        dry_run: bool,
        force: bool,
        no_test: bool,
    },
    Wrap {
        dsn: String,
        service: Option<String>,
        env_name: String,
        capture_stdout: bool,
        heartbeat_url: Option<String>,
        cmd: Vec<String>,
    },
    Pipe {
        dsn: String,
        service: Option<String>,
        env_name: String,
    },
    SourcemapsUpload {
        base_url: String,
        org: String,
        project: String,
        release: String,
        token: String,
        dir: PathBuf,
        delete_after_upload: bool,
    },
    Check {
        url: Option<String>,
        dsn: Option<String>,
        app_url: Option<String>,
        org: Option<String>,
        project: Option<String>,
        token: Option<String>,
        json: bool,
    },
    AiPrompt {
        dsn: String,
        app_url: Option<String>,
        org: Option<String>,
        project: Option<String>,
        stack: String,
        dir: PathBuf,
    },
    Lint {
        dir: PathBuf,
    },
    Keygen,
    Version,
    Help,
}

#[derive(Debug, Clone)]
pub struct CidrBlock {
    pub network: IpAddr,
    pub prefix: u8,
}

impl CidrBlock {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let s = raw.trim();
        if s == "*" {
            return Err("Wildcard '*' in BUGFINDER_TRUSTED_PROXIES is forbidden".into());
        }
        if let Some((ip_part, mask_part)) = s.split_once('/') {
            let ip: IpAddr = ip_part
                .parse()
                .map_err(|e| format!("Invalid CIDR IP '{s}': {e}"))?;
            let prefix: u8 = mask_part
                .parse()
                .map_err(|e| format!("Invalid CIDR mask '{s}': {e}"))?;
            let max_bits = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max_bits {
                return Err(format!("CIDR prefix out of range in '{s}'"));
            }
            Ok(Self {
                network: ip,
                prefix,
            })
        } else {
            let ip: IpAddr = s
                .parse()
                .map_err(|e| format!("Invalid proxy IP '{s}': {e}"))?;
            let prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Ok(Self {
                network: ip,
                prefix,
            })
        }
    }

    pub fn expand_keyword_or_cidr(raw: &str) -> Result<Vec<Self>, String> {
        let s = raw.trim();
        if s.eq_ignore_ascii_case("loopback") {
            return ["127.0.0.0/8", "::1/128"]
                .iter()
                .map(|c| Self::parse(c))
                .collect();
        }
        if s.eq_ignore_ascii_case("private") {
            return [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "100.64.0.0/10",
                "169.254.0.0/16",
                "fc00::/7",
                "fe80::/10",
            ]
            .iter()
            .map(|c| Self::parse(c))
            .collect();
        }
        if s.eq_ignore_ascii_case("cloudflare") {
            return [
                "173.245.48.0/20",
                "103.21.244.0/22",
                "103.22.200.0/22",
                "103.31.4.0/22",
                "141.101.64.0/18",
                "108.162.192.0/18",
                "190.93.240.0/20",
                "188.114.96.0/20",
                "197.234.240.0/22",
                "198.41.128.0/17",
                "162.158.0.0/15",
                "104.16.0.0/13",
                "104.24.0.0/14",
                "172.64.0.0/13",
                "131.0.72.0/22",
                "2400:cb00::/32",
                "2606:4700::/32",
                "2803:f800::/32",
                "2405:b500::/32",
                "2405:8100::/32",
                "2a06:98c0::/29",
                "2c0f:f248::/32",
            ]
            .iter()
            .map(|c| Self::parse(c))
            .collect();
        }
        Ok(vec![Self::parse(s)?])
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                (u32::from(net) & mask) == (u32::from(addr) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                (u128::from(net) & mask) == (u128::from(addr) & mask)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub implicit_tls: bool,
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub display_name: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub bind_addr: String,
    pub data_dir: PathBuf,
    pub database_url: Option<String>,
    pub app_key: [u8; 32],
    pub max_unzipped_bytes: usize,
    pub max_db_mb: u64,
    pub retention_days: u32,
    pub trusted_proxies: Vec<CidrBlock>,
    pub trust_cf_header: bool,
    pub allowed_hosts: Vec<String>,
    pub public_url: Option<String>,
    pub session_ttl_sec: i64,
    pub session_idle_sec: i64,
    pub metrics_token: Option<String>,
    pub force_secure_cookies: bool,
    pub is_dev: bool,
    pub desktop_app_mode: bool,
    pub dev_allow_http_webhooks: bool,
    pub anti_ptrace: bool,
    pub skip_migrations: bool,
    pub smtp: Option<SmtpConfig>,
    pub oidc: Option<OidcConfig>,
}

impl AppConfig {
    pub fn from_env_and_overrides(
        bind_override: Option<String>,
        data_override: Option<PathBuf>,
        db_override: Option<String>,
        desktop_app_mode: bool,
    ) -> Result<Self, String> {
        let data_dir = data_override
            .or_else(|| env::var("BUGFINDER_DATA_DIR").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("./data"));

        fs::create_dir_all(&data_dir).map_err(|e| format!("Failed creating data_dir: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700));
        }

        let bind_addr = bind_override
            .or_else(|| env::var("BUGFINDER_BIND").ok())
            .unwrap_or_else(|| {
                if desktop_app_mode {
                    "127.0.0.1:0".to_string()
                } else {
                    "127.0.0.1:8080".to_string()
                }
            });

        let database_url = db_override.or_else(|| {
            env::var("DATABASE_URL")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        });

        let is_loopback_bind = bind_addr.starts_with("127.0.0.1:")
            || bind_addr.starts_with("localhost:")
            || bind_addr.starts_with("[::1]:");

        let max_unzipped_bytes = env::var("BUGFINDER_MAX_UNZIPPED_BYTES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&v| (4096..=32 * 1024 * 1024).contains(&v))
            .unwrap_or(2 * 1024 * 1024);

        let max_db_mb = env::var("BUGFINDER_MAX_DB_MB")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&v| v >= 16)
            .unwrap_or(512);

        let retention_days = env::var("BUGFINDER_RETENTION_DAYS")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|&v| (1..=3650).contains(&v))
            .unwrap_or(30);

        let mut trusted_proxies = Vec::new();
        let mut trust_cf_header = env::var("BUGFINDER_TRUST_CF_HEADER")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if let Ok(raw) = env::var("BUGFINDER_TRUSTED_PROXIES") {
            for part in raw.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
                if part.eq_ignore_ascii_case("cloudflare") {
                    trust_cf_header = true;
                }
                trusted_proxies.extend(CidrBlock::expand_keyword_or_cidr(part)?);
            }
        }

        let mut allowed_hosts = Vec::new();
        if let Ok(raw) = env::var("BUGFINDER_ALLOWED_HOSTS") {
            for part in raw.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
                if part == "*" {
                    return Err("Wildcard '*' in BUGFINDER_ALLOWED_HOSTS is forbidden".into());
                }
                let host = if part.starts_with('[') {
                    part.split(']')
                        .next()
                        .map(|s| format!("{}]", s.to_ascii_lowercase()))
                        .unwrap_or_default()
                } else {
                    part.split(':').next().unwrap_or("").to_ascii_lowercase()
                };
                if !host.is_empty() && !allowed_hosts.contains(&host) {
                    allowed_hosts.push(host);
                }
            }
        }

        let public_url = env::var("BUGFINDER_PUBLIC_URL")
            .ok()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| s.starts_with("https://") || s.starts_with("http://"));

        let session_ttl_hours = env::var("BUGFINDER_SESSION_TTL_HOURS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|&v| (1..=720).contains(&v))
            .unwrap_or(168);
        let session_ttl_sec = session_ttl_hours * 3600;

        let session_idle_hours = env::var("BUGFINDER_SESSION_IDLE_HOURS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|&v| (1..=720).contains(&v))
            .unwrap_or(24);
        let session_idle_sec = session_idle_hours * 3600;

        let metrics_token = env::var("BUGFINDER_METRICS_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let force_secure_cookies = env::var("BUGFINDER_FORCE_SECURE_COOKIES")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let has_prod_signals = force_secure_cookies
            || !trusted_proxies.is_empty()
            || !allowed_hosts.is_empty()
            || database_url.is_some()
            || public_url
                .as_deref()
                .map(|u| u.starts_with("https://"))
                .unwrap_or(false);
        let is_dev = match env::var("BUGFINDER_ENV") {
            Ok(v) => matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "dev" | "development" | "local"
            ),
            Err(_) => !has_prod_signals && (desktop_app_mode || is_loopback_bind),
        };

        let app_key = load_or_create_app_key(&data_dir, is_dev)?;

        let dev_allow_http_webhooks = env::var("BUGFINDER_DEV_ALLOW_HTTP_WEBHOOKS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let anti_ptrace = env::var("BUGFINDER_ANTI_PTRACE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let skip_migrations = env::var("BUGFINDER_SKIP_MIGRATIONS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let oidc_issuer = env::var("BUGFINDER_OIDC_ISSUER")
            .ok()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty());
        let oidc_client_id = env::var("BUGFINDER_OIDC_CLIENT_ID")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let oidc_client_secret = env::var("BUGFINDER_OIDC_CLIENT_SECRET")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let oidc_display_name = env::var("BUGFINDER_OIDC_DISPLAY_NAME")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "SSO / OIDC".to_string());

        let oidc = match (oidc_issuer, oidc_client_id, oidc_client_secret, &public_url) {
            (Some(issuer), Some(client_id), Some(client_secret), Some(pub_url)) => {
                if !is_dev && (!issuer.starts_with("https://") || !pub_url.starts_with("https://"))
                {
                    return Err("BUGFINDER_OIDC_ISSUER and BUGFINDER_PUBLIC_URL must use https:// outside dev mode".into());
                }
                if !(issuer.starts_with("https://") || issuer.starts_with("http://")) {
                    return Err("Invalid BUGFINDER_OIDC_ISSUER URL scheme".into());
                }
                Some(OidcConfig {
                    issuer,
                    client_id,
                    client_secret,
                    display_name: oidc_display_name,
                    redirect_uri: format!(
                        "{}/api/auth/oidc/callback",
                        pub_url.trim_end_matches('/')
                    ),
                })
            }
            _ => None,
        };

        let smtp = env::var("BUGFINDER_SMTP_HOST")
            .ok()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .map(|host| {
                let port = env::var("BUGFINDER_SMTP_PORT")
                    .ok()
                    .and_then(|p| p.parse::<u16>().ok())
                    .unwrap_or(587);
                let implicit_tls = env::var("BUGFINDER_SMTP_TLS_MODE")
                    .map(|m| m.eq_ignore_ascii_case("implicit") || port == 465)
                    .unwrap_or(port == 465);
                SmtpConfig {
                    host,
                    port,
                    user: env::var("BUGFINDER_SMTP_USER")
                        .ok()
                        .filter(|s| !s.is_empty()),
                    password: env::var("BUGFINDER_SMTP_PASS")
                        .ok()
                        .filter(|s| !s.is_empty()),
                    from: env::var("BUGFINDER_SMTP_FROM")
                        .unwrap_or_else(|_| "alerts@bugfinder.local".to_string()),
                    implicit_tls,
                }
            });

        Ok(Self {
            bind_addr,
            data_dir,
            database_url,
            app_key,
            max_unzipped_bytes,
            max_db_mb,
            retention_days,
            trusted_proxies,
            trust_cf_header,
            allowed_hosts,
            public_url,
            session_ttl_sec,
            session_idle_sec,
            metrics_token,
            force_secure_cookies,
            is_dev,
            desktop_app_mode,
            dev_allow_http_webhooks,
            anti_ptrace,
            skip_migrations,
            smtp,
            oidc,
        })
    }

    pub fn sqlite_path(&self) -> PathBuf {
        if let Some(url) = &self.database_url {
            if let Some(stripped) = url.strip_prefix("sqlite://") {
                return PathBuf::from(stripped);
            }
        }
        self.data_dir.join("bugfinder.db")
    }

    pub fn sourcemaps_dir(&self) -> PathBuf {
        self.data_dir.join("sourcemaps")
    }

    pub fn is_postgres(&self) -> bool {
        self.database_url
            .as_deref()
            .map(|u| u.starts_with("postgres://") || u.starts_with("postgresql://"))
            .unwrap_or(false)
    }

    pub fn is_trusted_proxy(&self, peer: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|c| c.contains(peer))
    }
}

fn load_or_create_app_key(data_dir: &Path, is_dev: bool) -> Result<[u8; 32], String> {
    if let Ok(raw) = env::var("BUGFINDER_APP_KEY") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            if !is_dev && trimmed.len() < 32 {
                return Err(
                    "BUGFINDER_APP_KEY must be at least 32 characters (64 hex chars recommended) in production"
                        .into(),
                );
            }
            return decode_key_bytes(trimmed);
        }
    }

    let key_file = data_dir.join(".app_key");
    if key_file.is_file() {
        let content = fs::read_to_string(&key_file)
            .map_err(|e| format!("Failed reading {}: {e}", key_file.display()))?;
        return decode_key_bytes(content.trim());
    }

    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let hex_key = hex::encode(bytes);

    let tmp_path = data_dir.join(".app_key.tmp");
    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp_path)
        .map_err(|e| format!("Failed creating .app_key.tmp: {e}"))?;
    f.write_all(hex_key.as_bytes())
        .map_err(|e| format!("Failed writing .app_key.tmp: {e}"))?;
    f.sync_all()
        .map_err(|e| format!("Failed syncing .app_key.tmp: {e}"))?;
    fs::rename(&tmp_path, &key_file).map_err(|e| format!("Failed renaming .app_key: {e}"))?;

    Ok(bytes)
}

fn decode_key_bytes(raw: &str) -> Result<[u8; 32], String> {
    if raw.len() == 64 {
        if let Ok(bytes) = hex::decode(raw) {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return Ok(arr);
            }
        }
    }
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    let digest = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&digest);
    Ok(arr)
}

pub struct ParsedArgs {
    pub command: CliCommand,
    pub bind_override: Option<String>,
    pub data_override: Option<PathBuf>,
    pub db_override: Option<String>,
}

pub fn parse_cli_args(args: &[String]) -> Result<ParsedArgs, String> {
    let mut bind_override = None;
    let mut data_override = None;
    let mut db_override = None;
    let mut desktop_app = false;
    let mut i = 1;

    if matches!(
        args.get(1).map(|s| s.as_str()),
        Some("--help" | "-h" | "help")
    ) {
        return Ok(ParsedArgs {
            command: CliCommand::Help,
            bind_override: None,
            data_override: None,
            db_override: None,
        });
    }

    if args.get(1).map(|s| s.as_str()) == Some("--version")
        || args.get(1).map(|s| s.as_str()) == Some("-V")
    {
        return Ok(ParsedArgs {
            command: CliCommand::Version,
            bind_override: None,
            data_override: None,
            db_override: None,
        });
    }

    if let Some(sub) = args.get(1).map(|s| s.as_str()) {
        match sub {
            "migrate" => {
                let mut j = 2;
                while j < args.len() {
                    match args[j].as_str() {
                        "--data" => {
                            j += 1;
                            data_override =
                                Some(PathBuf::from(args.get(j).ok_or("--data requires a value")?));
                        }
                        "--db" => {
                            j += 1;
                            db_override =
                                Some(args.get(j).cloned().ok_or("--db requires a value")?);
                        }
                        other => return Err(format!("Unknown migrate option: {other}")),
                    }
                    j += 1;
                }
                return Ok(ParsedArgs {
                    command: CliCommand::Migrate,
                    bind_override: None,
                    data_override,
                    db_override,
                });
            }
            "backup" => {
                let mut out_path: Option<PathBuf> = None;
                let mut j = 2;
                while j < args.len() {
                    match args[j].as_str() {
                        "--out" => {
                            j += 1;
                            out_path =
                                Some(PathBuf::from(args.get(j).ok_or("--out requires a path")?));
                        }
                        "--data" => {
                            j += 1;
                            data_override =
                                Some(PathBuf::from(args.get(j).ok_or("--data requires a value")?));
                        }
                        "--db" => {
                            j += 1;
                            db_override =
                                Some(args.get(j).cloned().ok_or("--db requires a value")?);
                        }
                        other => return Err(format!("Unknown backup option: {other}")),
                    }
                    j += 1;
                }
                let out_path = out_path.ok_or("backup requires --out <path>")?;
                return Ok(ParsedArgs {
                    command: CliCommand::Backup { out_path },
                    bind_override: None,
                    data_override,
                    db_override,
                });
            }
            "doctor" => {
                let mut url = None;
                let mut json = false;
                let mut j = 2;
                while j < args.len() {
                    match args[j].as_str() {
                        "--url" => {
                            j += 1;
                            url = Some(args.get(j).cloned().ok_or("--url requires a value")?);
                        }
                        "--data" => {
                            j += 1;
                            data_override =
                                Some(PathBuf::from(args.get(j).ok_or("--data requires a value")?));
                        }
                        "--db" => {
                            j += 1;
                            db_override =
                                Some(args.get(j).cloned().ok_or("--db requires a value")?);
                        }
                        "--json" => json = true,
                        other => return Err(format!("Unknown doctor option: {other}")),
                    }
                    j += 1;
                }
                return Ok(ParsedArgs {
                    command: CliCommand::Doctor { url, json },
                    bind_override: None,
                    data_override,
                    db_override,
                });
            }
            "healthcheck" => {
                let mut url = "http://127.0.0.1:8080/api/health".to_string();
                let mut j = 2;
                while j < args.len() {
                    if args[j] == "--url" {
                        j += 1;
                        url = args.get(j).cloned().ok_or("--url requires a value")?;
                    }
                    j += 1;
                }
                return Ok(ParsedArgs {
                    command: CliCommand::Healthcheck { url },
                    bind_override: None,
                    data_override: None,
                    db_override: None,
                });
            }
            "tail" => {
                let mut base_url = "http://127.0.0.1:8080".to_string();
                let mut token = env::var("BUGFINDER_API_TOKEN").unwrap_or_default();
                let mut org = "default".to_string();
                let mut project = None;
                let mut level = None;
                let mut query = None;
                let mut j = 2;
                while j < args.len() {
                    match args[j].as_str() {
                        "--url" => {
                            j += 1;
                            base_url = args.get(j).cloned().ok_or("--url requires value")?;
                        }
                        "--token" => {
                            j += 1;
                            token = args.get(j).cloned().ok_or("--token requires value")?;
                        }
                        "--org" => {
                            j += 1;
                            org = args.get(j).cloned().ok_or("--org requires value")?;
                        }
                        "--project" => {
                            j += 1;
                            let val = args.get(j).ok_or("--project requires value")?;
                            project = Some(val.parse::<i64>().map_err(|_| "invalid --project id")?);
                        }
                        "--level" => {
                            j += 1;
                            level = Some(args.get(j).cloned().ok_or("--level requires value")?);
                        }
                        "--query" => {
                            j += 1;
                            query = Some(args.get(j).cloned().ok_or("--query requires value")?);
                        }
                        other => return Err(format!("Unknown tail option: {other}")),
                    }
                    j += 1;
                }
                if token.is_empty() {
                    return Err("tail requires --token or BUGFINDER_API_TOKEN".into());
                }
                return Ok(ParsedArgs {
                    command: CliCommand::Tail {
                        base_url,
                        token,
                        org,
                        project,
                        level,
                        query,
                    },
                    bind_override: None,
                    data_override: None,
                    db_override: None,
                });
            }
            "mcp" => {
                let mut org = "default".to_string();
                let mut token = env::var("BUGFINDER_API_TOKEN").ok();
                let mut j = 2;
                while j < args.len() {
                    match args[j].as_str() {
                        "--org" => {
                            j += 1;
                            org = args.get(j).cloned().ok_or("--org requires value")?;
                        }
                        "--token" => {
                            j += 1;
                            token = Some(args.get(j).cloned().ok_or("--token requires value")?);
                        }
                        "--data" => {
                            j += 1;
                            data_override =
                                Some(PathBuf::from(args.get(j).ok_or("--data requires value")?));
                        }
                        "--db" => {
                            j += 1;
                            db_override = Some(args.get(j).cloned().ok_or("--db requires value")?);
                        }
                        other => return Err(format!("Unknown mcp option: {other}")),
                    }
                    j += 1;
                }
                return Ok(ParsedArgs {
                    command: CliCommand::Mcp { org, token },
                    bind_override: None,
                    data_override,
                    db_override,
                });
            }
            "test-event" | "test-log" => {
                let mut dsn = String::new();
                let mut j = 2;
                while j < args.len() {
                    if args[j] == "--dsn" {
                        j += 1;
                        dsn = args.get(j).cloned().ok_or("--dsn requires value")?;
                    }
                    j += 1;
                }
                if dsn.is_empty() {
                    return Err(format!("{sub} requires --dsn <url>"));
                }
                let command = if sub == "test-event" {
                    CliCommand::TestEvent { dsn }
                } else {
                    CliCommand::TestLog { dsn }
                };
                return Ok(ParsedArgs {
                    command,
                    bind_override: None,
                    data_override: None,
                    db_override: None,
                });
            }
            "init" => {
                let mut dir = PathBuf::from(".");
                let mut dsn = env::var("BUGFINDER_DSN").unwrap_or_default();
                let mut stack = "auto".to_string();
                let mut sdk = "zero-dep".to_string();
                let mut dry_run = false;
                let mut force = false;
                let mut no_test = false;
                let mut j = 2;
                while j < args.len() {
                    match args[j].as_str() {
                        "--dir" => {
                            j += 1;
                            dir = PathBuf::from(args.get(j).ok_or("--dir requires value")?);
                        }
                        "--dsn" => {
                            j += 1;
                            dsn = args.get(j).cloned().ok_or("--dsn requires value")?;
                        }
                        "--stack" => {
                            j += 1;
                            stack = args.get(j).cloned().ok_or("--stack requires value")?;
                        }
                        "--sdk" => {
                            j += 1;
                            sdk = args.get(j).cloned().ok_or("--sdk requires value")?;
                        }
                        "--dry-run" => dry_run = true,
                        "--force" => force = true,
                        "--no-test" => no_test = true,
                        other => return Err(format!("Unknown init option: {other}")),
                    }
                    j += 1;
                }
                if dsn.trim().is_empty() {
                    return Err("init requires --dsn <url> (or BUGFINDER_DSN env var)".into());
                }
                return Ok(ParsedArgs {
                    command: CliCommand::Init {
                        dir,
                        dsn,
                        stack,
                        sdk,
                        dry_run,
                        force,
                        no_test,
                    },
                    bind_override: None,
                    data_override: None,
                    db_override: None,
                });
            }
            "wrap" => {
                let mut dsn = env::var("BUGFINDER_DSN").unwrap_or_default();
                let mut service = None;
                let mut env_name = "production".to_string();
                let mut capture_stdout = false;
                let mut heartbeat_url = None;
                let mut cmd = Vec::new();
                let mut j = 2;
                while j < args.len() {
                    match args[j].as_str() {
                        "--" => {
                            cmd.extend(args[j + 1..].iter().cloned());
                            break;
                        }
                        "--dsn" => {
                            j += 1;
                            dsn = args.get(j).cloned().ok_or("--dsn requires value")?;
                        }
                        "--service" => {
                            j += 1;
                            service = Some(args.get(j).cloned().ok_or("--service requires value")?);
                        }
                        "--env" => {
                            j += 1;
                            env_name = args.get(j).cloned().ok_or("--env requires value")?;
                        }
                        "--capture-stdout" => capture_stdout = true,
                        "--heartbeat-url" => {
                            j += 1;
                            heartbeat_url = Some(
                                args.get(j)
                                    .cloned()
                                    .ok_or("--heartbeat-url requires value")?,
                            );
                        }
                        other if !other.starts_with('-') => {
                            cmd.extend(args[j..].iter().cloned());
                            break;
                        }
                        other => return Err(format!("Unknown wrap option: {other}")),
                    }
                    j += 1;
                }
                if dsn.trim().is_empty() {
                    return Err("wrap requires --dsn <url> (or BUGFINDER_DSN env var)".into());
                }
                if cmd.is_empty() {
                    return Err("wrap requires a command after '--'".into());
                }
                return Ok(ParsedArgs {
                    command: CliCommand::Wrap {
                        dsn,
                        service,
                        env_name,
                        capture_stdout,
                        heartbeat_url,
                        cmd,
                    },
                    bind_override: None,
                    data_override: None,
                    db_override: None,
                });
            }
            "pipe" => {
                let mut dsn = env::var("BUGFINDER_DSN").unwrap_or_default();
                let mut service = None;
                let mut env_name = "production".to_string();
                let mut j = 2;
                while j < args.len() {
                    match args[j].as_str() {
                        "--dsn" => {
                            j += 1;
                            dsn = args.get(j).cloned().ok_or("--dsn requires value")?;
                        }
                        "--service" => {
                            j += 1;
                            service = Some(args.get(j).cloned().ok_or("--service requires value")?);
                        }
                        "--env" => {
                            j += 1;
                            env_name = args.get(j).cloned().ok_or("--env requires value")?;
                        }
                        other => return Err(format!("Unknown pipe option: {other}")),
                    }
                    j += 1;
                }
                if dsn.trim().is_empty() {
                    return Err("pipe requires --dsn <url> (or BUGFINDER_DSN env var)".into());
                }
                return Ok(ParsedArgs {
                    command: CliCommand::Pipe {
                        dsn,
                        service,
                        env_name,
                    },
                    bind_override: None,
                    data_override: None,
                    db_override: None,
                });
            }
            "sourcemaps" => {
                if args.get(2).map(|s| s.as_str()) != Some("upload") {
                    return Err("Expected 'bugfinder sourcemaps upload ...'".into());
                }
                let mut base_url = env::var("BUGFINDER_URL").unwrap_or_default();
                let mut org = env::var("BUGFINDER_ORG").unwrap_or_default();
                let mut project = env::var("BUGFINDER_PROJECT").unwrap_or_default();
                let mut release = String::new();
                let mut token = env::var("BUGFINDER_TOKEN").unwrap_or_default();
                let mut dir = PathBuf::from(".");
                let mut delete_after_upload = false;
                let mut j = 3;
                while j < args.len() {
                    match args[j].as_str() {
                        "--url" => {
                            j += 1;
                            base_url = args.get(j).cloned().ok_or("--url requires a value")?;
                        }
                        "--org" => {
                            j += 1;
                            org = args.get(j).cloned().ok_or("--org requires a value")?;
                        }
                        "--project" => {
                            j += 1;
                            project = args.get(j).cloned().ok_or("--project requires a value")?;
                        }
                        "--release" => {
                            j += 1;
                            release = args.get(j).cloned().ok_or("--release requires a value")?;
                        }
                        "--token" => {
                            j += 1;
                            token = args.get(j).cloned().ok_or("--token requires a value")?;
                        }
                        "--dir" => {
                            j += 1;
                            dir = PathBuf::from(args.get(j).ok_or("--dir requires a path")?);
                        }
                        "--delete-after-upload" => delete_after_upload = true,
                        other => return Err(format!("Unknown sourcemaps upload option: {other}")),
                    }
                    j += 1;
                }
                if base_url.trim().is_empty()
                    || org.trim().is_empty()
                    || project.trim().is_empty()
                    || release.trim().is_empty()
                    || token.trim().is_empty()
                {
                    return Err(
                        "sourcemaps upload requires --url, --org, --project, --release, and --token (or BUGFINDER_TOKEN)"
                            .into(),
                    );
                }
                return Ok(ParsedArgs {
                    command: CliCommand::SourcemapsUpload {
                        base_url,
                        org,
                        project,
                        release,
                        token,
                        dir,
                        delete_after_upload,
                    },
                    bind_override: None,
                    data_override: None,
                    db_override: None,
                });
            }
            "check" => {
                let mut url = None;
                let mut dsn = None;
                let mut app_url = None;
                let mut org = env::var("BUGFINDER_ORG").ok();
                let mut project = env::var("BUGFINDER_PROJECT").ok();
                let mut token = env::var("BUGFINDER_TOKEN")
                    .or_else(|_| env::var("BUGFINDER_API_TOKEN"))
                    .ok();
                let mut json = false;
                let mut j = 2;
                while j < args.len() {
                    match args[j].as_str() {
                        "--url" => {
                            j += 1;
                            url = Some(args.get(j).cloned().ok_or("--url requires a value")?);
                        }
                        "--dsn" => {
                            j += 1;
                            dsn = Some(args.get(j).cloned().ok_or("--dsn requires a value")?);
                        }
                        "--app-url" => {
                            j += 1;
                            app_url =
                                Some(args.get(j).cloned().ok_or("--app-url requires a value")?);
                        }
                        "--org" => {
                            j += 1;
                            org = Some(args.get(j).cloned().ok_or("--org requires a value")?);
                        }
                        "--project" => {
                            j += 1;
                            project =
                                Some(args.get(j).cloned().ok_or("--project requires a value")?);
                        }
                        "--token" => {
                            j += 1;
                            token = Some(args.get(j).cloned().ok_or("--token requires a value")?);
                        }
                        "--json" => json = true,
                        other => return Err(format!("Unknown check option: {other}")),
                    }
                    j += 1;
                }
                return Ok(ParsedArgs {
                    command: CliCommand::Check {
                        url,
                        dsn,
                        app_url,
                        org,
                        project,
                        token,
                        json,
                    },
                    bind_override: None,
                    data_override: None,
                    db_override: None,
                });
            }
            "ai-prompt" => {
                let mut dsn = env::var("BUGFINDER_DSN").unwrap_or_default();
                let mut app_url = env::var("BUGFINDER_APP_URL").ok();
                let mut org = env::var("BUGFINDER_ORG").ok();
                let mut project = env::var("BUGFINDER_PROJECT").ok();
                let mut stack = "auto".to_string();
                let mut dir = PathBuf::from(".");
                let mut j = 2;
                while j < args.len() {
                    match args[j].as_str() {
                        "--dsn" => {
                            j += 1;
                            dsn = args.get(j).cloned().ok_or("--dsn requires value")?;
                        }
                        "--app-url" => {
                            j += 1;
                            app_url = Some(args.get(j).cloned().ok_or("--app-url requires value")?);
                        }
                        "--org" => {
                            j += 1;
                            org = Some(args.get(j).cloned().ok_or("--org requires value")?);
                        }
                        "--project" => {
                            j += 1;
                            project = Some(args.get(j).cloned().ok_or("--project requires value")?);
                        }
                        "--stack" => {
                            j += 1;
                            stack = args.get(j).cloned().ok_or("--stack requires value")?;
                        }
                        "--dir" => {
                            j += 1;
                            dir = PathBuf::from(args.get(j).ok_or("--dir requires path")?);
                        }
                        other => return Err(format!("Unknown ai-prompt option: {other}")),
                    }
                    j += 1;
                }
                if dsn.trim().is_empty() {
                    return Err("ai-prompt requires --dsn <url> (or BUGFINDER_DSN env var)".into());
                }
                return Ok(ParsedArgs {
                    command: CliCommand::AiPrompt {
                        dsn,
                        app_url,
                        org,
                        project,
                        stack,
                        dir,
                    },
                    bind_override: None,
                    data_override: None,
                    db_override: None,
                });
            }
            "lint" => {
                let mut dir = PathBuf::from(".");
                let mut j = 2;
                while j < args.len() {
                    match args[j].as_str() {
                        "--dir" => {
                            j += 1;
                            dir = PathBuf::from(args.get(j).ok_or("--dir requires path")?);
                        }
                        other => return Err(format!("Unknown lint option: {other}")),
                    }
                    j += 1;
                }
                return Ok(ParsedArgs {
                    command: CliCommand::Lint { dir },
                    bind_override: None,
                    data_override: None,
                    db_override: None,
                });
            }
            "keygen" => {
                return Ok(ParsedArgs {
                    command: CliCommand::Keygen,
                    bind_override: None,
                    data_override: None,
                    db_override: None,
                });
            }
            _ => {}
        }
    }

    while i < args.len() {
        match args[i].as_str() {
            "--headless" => desktop_app = false,
            "--app" => desktop_app = true,
            "--bind" => {
                i += 1;
                bind_override = Some(args.get(i).cloned().ok_or("--bind requires address")?);
            }
            "--data" => {
                i += 1;
                data_override = Some(PathBuf::from(args.get(i).ok_or("--data requires path")?));
            }
            "--db" => {
                i += 1;
                db_override = Some(args.get(i).cloned().ok_or("--db requires url/path")?);
            }
            "--version" | "-V" => {
                return Ok(ParsedArgs {
                    command: CliCommand::Version,
                    bind_override: None,
                    data_override: None,
                    db_override: None,
                });
            }
            "--help" | "-h" => {
                return Ok(ParsedArgs {
                    command: CliCommand::Help,
                    bind_override: None,
                    data_override: None,
                    db_override: None,
                });
            }
            other => return Err(format!("Unknown flag: {other}")),
        }
        i += 1;
    }

    Ok(ParsedArgs {
        command: CliCommand::Serve { desktop_app },
        bind_override,
        data_override,
        db_override,
    })
}
