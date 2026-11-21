use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Apply Linux glibc arena & mmap thresholds to hold idle VmRSS under 15 MB.
pub fn init_low_ram_allocator() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::mallopt(libc::M_ARENA_MAX, 2);
        libc::mallopt(libc::M_MMAP_THRESHOLD, 64 * 1024);
    }
}

/// Return transient heap arenas (scrypt, large source map parses, purge bursts) to OS.
pub fn trim_heap() {
    #[cfg(target_os = "linux")]
    unsafe {
        let _ = libc::malloc_trim(0);
    }
}

/// Read current Linux VmRSS in bytes from `/proc/self/status`.
pub fn current_vm_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
                return Some(kb * 1024);
            }
        }
    }
    None
}

pub fn build_compact_tokio_runtime() -> Result<tokio::runtime::Runtime, std::io::Error> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .thread_stack_size(512 * 1024)
        .enable_all()
        .build()
}

pub fn run_healthcheck(url: &str) -> i32 {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(2))
        .timeout(Duration::from_secs(2))
        .build();

    match agent.get(url).call() {
        Ok(resp) if resp.status() == 200 => 0,
        Ok(resp) => {
            eprintln!("healthcheck failed: HTTP {}", resp.status());
            1
        }
        Err(err) => {
            eprintln!("healthcheck error: {err}");
            1
        }
    }
}

pub fn probe_existing_instance(port_hint: u16) -> bool {
    if port_hint == 0 {
        return false;
    }
    let url = format!("http://127.0.0.1:{port_hint}/api/health");
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_millis(150))
        .timeout(Duration::from_millis(150))
        .build();
    matches!(agent.get(&url).call(), Ok(r) if r.status() == 200)
}

pub fn spawn_desktop_window(url: &str, data_dir: &Path) -> Option<Child> {
    let profile_dir = data_dir.join("window-profile");
    let _ = std::fs::create_dir_all(&profile_dir);
    let candidates = [
        "google-chrome",
        "chromium",
        "chromium-browser",
        "brave-browser",
        "microsoft-edge",
    ];
    for bin in candidates {
        let mut cmd = Command::new(bin);
        cmd.arg(format!("--app={url}"))
            .arg(format!("--user-data-dir={}", profile_dir.display()))
            .arg("--window-size=1440,900")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Ok(child) = cmd.spawn() {
            return Some(child);
        }
    }
    None
}

/// Wait on the spawned browser process. Only trigger shutdown if the browser stayed alive >= 2500ms
/// so thin wrapper shims that delegate to an existing browser process do not kill the local server.
pub async fn wait_for_desktop_browser(mut child: Child) {
    let started = Instant::now();
    let stayed_alive = tokio::task::spawn_blocking(move || {
        let _ = child.wait();
        started.elapsed() >= Duration::from_millis(2500)
    })
    .await
    .unwrap_or(false);

    if !stayed_alive {
        // Keep running until Ctrl-C / SIGTERM if the browser delegated to a pre-existing window
        std::future::pending::<()>().await;
    }
}
