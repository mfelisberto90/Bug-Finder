use std::env;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    Serve { desktop_app: bool },
    Healthcheck { url: String },
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
    TestEvent { dsn: String },
    TestLog { dsn: String },
    Version,
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
            let ip: IpAddr = ip_part.parse().map_err(|e| format!("Invalid CIDR IP '{s}': {e}"))?;
            let prefix: u8 = mask_part.parse().map_err(|e| format!("Invalid CIDR mask '{s}': {e}"))?;
            let max_bits = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max_bits {
                return Err(format!("CIDR prefix out of range in '{s}'"));
            }
            Ok(Self { network: ip, prefix })
        } else {
            let ip: IpAddr = s.parse().map_err(|e| format!("Invalid proxy IP '{s}': {e}"))?;
            let prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Ok(Self { network: ip, prefix })
        }
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
pub struct AppConfig {
    pub bind_addr: String,
    pub data_dir: PathBuf,
    pub database_url: Option<String>,
    pub app_key: [u8; 32],
    pub max_unzipped_bytes: usize,
    pub max_db_mb: u64,
    pub retention_days: u32,
    pub trusted_proxies: Vec<CidrBlock>,
    pub metrics_token: Option<String>,
    pub force_secure_cookies: bool,
    pub is_dev: bool,
    pub desktop_app_mode: bool,
    pub dev_allow_http_webhooks: bool,
    pub smtp: Option<SmtpConfig>,
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

        let is_dev = env::var("BUGFINDER_ENV")
            .map(|v| v.eq_ignore_ascii_case("dev") || v.eq_ignore_ascii_case("development"))
            .unwrap_or(true);

        let app_key = load_or_create_app_key(&data_dir)?;

        let max_unzipped_bytes = env::var("BUGFINDER_MAX_UNZIPPED_BYTES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&v| v >= 4096 && v <= 32 * 1024 * 1024)
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
        if let Ok(raw) = env::var("BUGFINDER_TRUSTED_PROXIES") {
            for part in raw.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
                trusted_proxies.push(CidrBlock::parse(part)?);
            }
        }

        let metrics_token = env::var("BUGFINDER_METRICS_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let force_secure_cookies = env::var("BUGFINDER_FORCE_SECURE_COOKIES")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let dev_allow_http_webhooks = env::var("BUGFINDER_DEV_ALLOW_HTTP_WEBHOOKS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

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
                    user: env::var("BUGFINDER_SMTP_USER").ok().filter(|s| !s.is_empty()),
                    password: env::var("BUGFINDER_SMTP_PASS").ok().filter(|s| !s.is_empty()),
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
            metrics_token,
            force_secure_cookies,
            is_dev,
            desktop_app_mode,
            dev_allow_http_webhooks,
            smtp,
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

fn load_or_create_app_key(data_dir: &Path) -> Result<[u8; 32], String> {
    if let Ok(raw) = env::var("BUGFINDER_APP_KEY") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return decode_key_bytes(trimmed);
        }
    }

    let key_file = data_dir.join(".app_key");
    if key_file.is_file() {
        let content = fs::read_to_string(&key_file)
            .map_err(|e| format!("Failed reading {}: {e}", key_file.display()))?;
        return decode_key_bytes(content.trim());
    }

    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let hex_key = hex::encode(bytes);

    let tmp_path = data_dir.join(".app_key.tmp");
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|e| format!("Failed creating .app_key.tmp: {e}"))?;
    f.write_all(hex_key.as_bytes())
        .map_err(|e| format!("Failed writing .app_key.tmp: {e}"))?;
    f.sync_all().map_err(|e| format!("Failed syncing .app_key.tmp: {e}"))?;
    fs::rename(&tmp_path, &key_file)
        .map_err(|e| format!("Failed renaming .app_key: {e}"))?;

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

    if args.get(1).map(|s| s.as_str()) == Some("--version") || args.get(1).map(|s| s.as_str()) == Some("-V") {
        return Ok(ParsedArgs {
            command: CliCommand::Version,
            bind_override: None,
            data_override: None,
            db_override: None,
        });
    }

    if let Some(sub) = args.get(1).map(|s| s.as_str()) {
        match sub {
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
                        "--url" => { j += 1; base_url = args.get(j).cloned().ok_or("--url requires value")?; }
                        "--token" => { j += 1; token = args.get(j).cloned().ok_or("--token requires value")?; }
                        "--org" => { j += 1; org = args.get(j).cloned().ok_or("--org requires value")?; }
                        "--project" => {
                            j += 1;
                            let val = args.get(j).ok_or("--project requires value")?;
                            project = Some(val.parse::<i64>().map_err(|_| "invalid --project id")?);
                        }
                        "--level" => { j += 1; level = Some(args.get(j).cloned().ok_or("--level requires value")?); }
                        "--query" => { j += 1; query = Some(args.get(j).cloned().ok_or("--query requires value")?); }
                        other => return Err(format!("Unknown tail option: {other}")),
                    }
                    j += 1;
                }
                if token.is_empty() {
                    return Err("tail requires --token or BUGFINDER_API_TOKEN".into());
                }
                return Ok(ParsedArgs {
                    command: CliCommand::Tail { base_url, token, org, project, level, query },
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
                        "--org" => { j += 1; org = args.get(j).cloned().ok_or("--org requires value")?; }
                        "--token" => { j += 1; token = Some(args.get(j).cloned().ok_or("--token requires value")?); }
                        "--data" => { j += 1; data_override = Some(PathBuf::from(args.get(j).ok_or("--data requires value")?)); }
                        "--db" => { j += 1; db_override = Some(args.get(j).cloned().ok_or("--db requires value")?); }
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
