use crate::runtime::current_vm_rss_bytes;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct AppMetrics {
    pub ingest_events_total: AtomicU64,
    pub ingest_logs_total: AtomicU64,
    pub ingest_transactions_total: AtomicU64,
    pub dropped_rate_limit_total: AtomicU64,
    pub dropped_inbound_filter_total: AtomicU64,
    pub dropped_zip_bomb_total: AtomicU64,
    pub dropped_dedupe_total: AtomicU64,
    pub queue_depth: AtomicU64,
    pub batch_flushes_total: AtomicU64,
    pub alerts_sent_total: AtomicU64,
    pub self_errors_total: AtomicU64,
}

impl AppMetrics {
    pub fn render_prometheus(&self, db_bytes: u64) -> String {
        let rss = current_vm_rss_bytes().unwrap_or(0);
        format!(
            "# HELP bugfinder_ingest_events_total Total error/issue events accepted\n\
             # TYPE bugfinder_ingest_events_total counter\n\
             bugfinder_ingest_events_total {}\n\
             # HELP bugfinder_ingest_logs_total Total structured logs accepted\n\
             # TYPE bugfinder_ingest_logs_total counter\n\
             bugfinder_ingest_logs_total {}\n\
             # HELP bugfinder_ingest_transactions_total Total performance transactions accepted\n\
             # TYPE bugfinder_ingest_transactions_total counter\n\
             bugfinder_ingest_transactions_total {}\n\
             # HELP bugfinder_dropped_total Events dropped by category\n\
             # TYPE bugfinder_dropped_total counter\n\
             bugfinder_dropped_total{{reason=\"rate_limit\"}} {}\n\
             bugfinder_dropped_total{{reason=\"inbound_filter\"}} {}\n\
             bugfinder_dropped_total{{reason=\"zip_bomb\"}} {}\n\
             bugfinder_dropped_total{{reason=\"dedupe\"}} {}\n\
             # HELP bugfinder_queue_depth Current pending micro-batch queue depth\n\
             # TYPE bugfinder_queue_depth gauge\n\
             bugfinder_queue_depth {}\n\
             # HELP bugfinder_batch_flushes_total Total batch writer transaction flushes\n\
             # TYPE bugfinder_batch_flushes_total counter\n\
             bugfinder_batch_flushes_total {}\n\
             # HELP bugfinder_alerts_sent_total Total alert notifications dispatched\n\
             # TYPE bugfinder_alerts_sent_total counter\n\
             bugfinder_alerts_sent_total {}\n\
             # HELP bugfinder_self_errors_total Total internal errors recorded by self-monitor\n\
             # TYPE bugfinder_self_errors_total counter\n\
             bugfinder_self_errors_total {}\n\
             # HELP bugfinder_rss_bytes Current process VmRSS in bytes\n\
             # TYPE bugfinder_rss_bytes gauge\n\
             bugfinder_rss_bytes {}\n\
             # HELP bugfinder_db_size_bytes Current SQLite database size in bytes\n\
             # TYPE bugfinder_db_size_bytes gauge\n\
             bugfinder_db_size_bytes {}\n",
            self.ingest_events_total.load(Ordering::Relaxed),
            self.ingest_logs_total.load(Ordering::Relaxed),
            self.ingest_transactions_total.load(Ordering::Relaxed),
            self.dropped_rate_limit_total.load(Ordering::Relaxed),
            self.dropped_inbound_filter_total.load(Ordering::Relaxed),
            self.dropped_zip_bomb_total.load(Ordering::Relaxed),
            self.dropped_dedupe_total.load(Ordering::Relaxed),
            self.queue_depth.load(Ordering::Relaxed),
            self.batch_flushes_total.load(Ordering::Relaxed),
            self.alerts_sent_total.load(Ordering::Relaxed),
            self.self_errors_total.load(Ordering::Relaxed),
            rss,
            db_bytes,
        )
    }
}
