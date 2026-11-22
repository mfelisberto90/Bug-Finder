#![recursion_limit = "256"]

pub mod alerts;
pub mod config;
pub mod domain;
pub mod http;
pub mod mcp;
pub mod runtime;
pub mod security;
pub mod selfcheck;
pub mod storage;

use crate::config::AppConfig;
use crate::domain::models::LiveStreamEvent;
use crate::domain::sourcemap::SourceMapCache;
use crate::security::anti_rea::ShieldEngine;
use crate::security::headers::ScannerGuard;
use crate::security::metrics::AppMetrics;
use crate::security::ratelimit::{EventDedupeCache, HmacRateLimiter, InvalidDsnCache};
use crate::selfcheck::SelfMonitor;
use crate::storage::batch_writer::BatchWriter;
use crate::storage::postgres::PostgresStorage;
use crate::storage::sqlite::SqliteStorage;
use crate::storage::StorageBackend;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

pub struct AppState {
    pub config: Arc<AppConfig>,
    pub storage: Arc<dyn StorageBackend>,
    pub batch_writer: BatchWriter,
    pub rate_limiter: HmacRateLimiter,
    pub event_dedupe: EventDedupeCache,
    pub invalid_dsn_cache: InvalidDsnCache,
    pub scanner_guard: ScannerGuard,
    pub sourcemap_cache: SourceMapCache,
    pub metrics: Arc<AppMetrics>,
    pub self_monitor: Arc<SelfMonitor>,
    pub shield_engine: ShieldEngine,
    pub live_tx: broadcast::Sender<LiveStreamEvent>,
}

pub async fn build_storage(config: &AppConfig) -> Result<Arc<dyn StorageBackend>, String> {
    if config.is_postgres() {
        let url = config.database_url.as_deref().unwrap_or("");
        let pg = PostgresStorage::connect_with_key(url, true, config.app_key).await?;
        Ok(pg)
    } else {
        let sqlite = SqliteStorage::open_with_key(&config.sqlite_path(), config.app_key)?;
        Ok(sqlite)
    }
}

pub fn build_app_state(
    config: Arc<AppConfig>,
    storage: Arc<dyn StorageBackend>,
) -> Arc<AppState> {
    let metrics = Arc::new(AppMetrics::default());
    let self_monitor = Arc::new(SelfMonitor::new(config.data_dir.clone()));
    let shield_engine = ShieldEngine::new();
    let batch_writer = BatchWriter::spawn(
        storage.clone(),
        config.clone(),
        metrics.clone(),
        self_monitor.clone(),
    );
    let rate_limiter = HmacRateLimiter::new(config.app_key, 16_384);
    let event_dedupe = EventDedupeCache::new(32_768, Duration::from_secs(600));
    let invalid_dsn_cache = InvalidDsnCache::new(8_192, Duration::from_secs(30));
    let scanner_guard = ScannerGuard::new();
    let sourcemap_cache = SourceMapCache::new(2 * 1024 * 1024, 8);
    let (live_tx, _) = broadcast::channel::<LiveStreamEvent>(512);

    Arc::new(AppState {
        config,
        storage,
        batch_writer,
        rate_limiter,
        event_dedupe,
        invalid_dsn_cache,
        scanner_guard,
        sourcemap_cache,
        metrics,
        self_monitor,
        shield_engine,
        live_tx,
    })
}
