use crate::alerts::dispatcher::{dispatch_alert, AlertDispatchJob};
use crate::config::AppConfig;
use crate::security::metrics::AppMetrics;
use crate::selfcheck::SelfMonitor;
use crate::storage::{IngestWriteItem, StorageBackend};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

const MAX_QUEUED_BYTES: usize = 16 * 1024 * 1024;
const ALERT_QUEUE_CAPACITY: usize = 256;

fn estimate_item_bytes(item: &IngestWriteItem) -> usize {
    match item {
        IngestWriteItem::Event { payload_json, .. } => payload_json.len().saturating_add(512),
        IngestWriteItem::Logs { logs, .. } => logs
            .iter()
            .map(|l| l.body.len().saturating_add(256))
            .sum::<usize>()
            .max(256),
        IngestWriteItem::Transaction { tx, .. } => tx.name.len().saturating_add(512),
        IngestWriteItem::Session { .. } | IngestWriteItem::CheckIn { .. } => 256,
    }
}

enum WriterMsg {
    Item(Box<IngestWriteItem>, usize),
    Flush(oneshot::Sender<()>),
    Shutdown(oneshot::Sender<()>),
}

/// Adaptive coalescing micro-batch writer:
/// - On idle traffic, flushes immediately (`0 ms` artificial wait) so issues & alerts appear in `< 1 ms`.
/// - During burst storms (`< 5 ms` since last flush), coalesces up to 128 items within `5 ms` per WAL/PG transaction.
/// - Enforces a `16 MiB` total queued byte budget so high-volume payloads cannot OOM-kill low-RAM containers.
pub struct BatchWriter {
    tx: mpsc::Sender<WriterMsg>,
    queued_bytes: Arc<AtomicUsize>,
    metrics: Arc<AppMetrics>,
    self_monitor: Arc<SelfMonitor>,
}

impl BatchWriter {
    pub fn spawn(
        storage: Arc<dyn StorageBackend>,
        config: Arc<AppConfig>,
        metrics: Arc<AppMetrics>,
        self_monitor: Arc<SelfMonitor>,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<WriterMsg>(4096);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let queued_bg = queued_bytes.clone();
        let metrics_bg = metrics.clone();
        let monitor_bg = self_monitor.clone();

        tokio::spawn(async move {
            let mut buffer: Vec<IngestWriteItem> = Vec::with_capacity(128);
            let mut buf_bytes: usize = 0;
            let mut last_flush_at: Option<tokio::time::Instant> = None;
            let mut coalesce_armed = false;
            let coalesce_sleep = tokio::time::sleep(Duration::from_millis(5));
            tokio::pin!(coalesce_sleep);

            loop {
                tokio::select! {
                    biased;
                    maybe_msg = rx.recv() => {
                        match maybe_msg {
                            Some(WriterMsg::Item(item, sz)) => {
                                buffer.push(*item);
                                buf_bytes = buf_bytes.saturating_add(sz);
                                let mut pending_acks = Vec::new();
                                let mut should_shutdown = false;
                                while buffer.len() < 128 {
                                    match rx.try_recv() {
                                        Ok(WriterMsg::Item(it, s)) => {
                                            buffer.push(*it);
                                            buf_bytes = buf_bytes.saturating_add(s);
                                        }
                                        Ok(WriterMsg::Flush(a)) => pending_acks.push(a),
                                        Ok(WriterMsg::Shutdown(a)) => {
                                            pending_acks.push(a);
                                            should_shutdown = true;
                                            break;
                                        }
                                        Err(_) => break,
                                    }
                                }
                                let recently_flushed = last_flush_at
                                    .is_some_and(|t| t.elapsed() < Duration::from_millis(5));
                                if buffer.len() >= 128
                                    || !pending_acks.is_empty()
                                    || should_shutdown
                                    || !recently_flushed
                                {
                                    let flushed_sz = std::mem::take(&mut buf_bytes);
                                    flush_vec(&storage, &config, &metrics_bg, &monitor_bg, &queued_bg, flushed_sz, &mut buffer).await;
                                    last_flush_at = Some(tokio::time::Instant::now());
                                    coalesce_armed = false;
                                    for a in pending_acks {
                                        let _ = a.send(());
                                    }
                                    if should_shutdown {
                                        break;
                                    }
                                } else if !coalesce_armed {
                                    coalesce_sleep.as_mut().reset(
                                        tokio::time::Instant::now() + Duration::from_millis(5),
                                    );
                                    coalesce_armed = true;
                                }
                            }
                            Some(WriterMsg::Flush(ack)) => {
                                let mut acks = vec![ack];
                                let mut should_shutdown = false;
                                while let Ok(msg) = rx.try_recv() {
                                    match msg {
                                        WriterMsg::Item(it, s) => {
                                            buffer.push(*it);
                                            buf_bytes = buf_bytes.saturating_add(s);
                                        }
                                        WriterMsg::Flush(a) => acks.push(a),
                                        WriterMsg::Shutdown(a) => {
                                            acks.push(a);
                                            should_shutdown = true;
                                        }
                                    }
                                }
                                if !buffer.is_empty() {
                                    let flushed_sz = std::mem::take(&mut buf_bytes);
                                    flush_vec(&storage, &config, &metrics_bg, &monitor_bg, &queued_bg, flushed_sz, &mut buffer).await;
                                    last_flush_at = Some(tokio::time::Instant::now());
                                }
                                coalesce_armed = false;
                                for a in acks {
                                    let _ = a.send(());
                                }
                                if should_shutdown {
                                    break;
                                }
                            }
                            Some(WriterMsg::Shutdown(ack)) => {
                                let mut acks = vec![ack];
                                while let Ok(msg) = rx.try_recv() {
                                    match msg {
                                        WriterMsg::Item(it, s) => {
                                            buffer.push(*it);
                                            buf_bytes = buf_bytes.saturating_add(s);
                                        }
                                        WriterMsg::Flush(a) | WriterMsg::Shutdown(a) => acks.push(a),
                                    }
                                }
                                if !buffer.is_empty() {
                                    let flushed_sz = std::mem::take(&mut buf_bytes);
                                    flush_vec(&storage, &config, &metrics_bg, &monitor_bg, &queued_bg, flushed_sz, &mut buffer).await;
                                }
                                for a in acks {
                                    let _ = a.send(());
                                }
                                break;
                            }
                            None => {
                                if !buffer.is_empty() {
                                    let flushed_sz = std::mem::take(&mut buf_bytes);
                                    flush_vec(&storage, &config, &metrics_bg, &monitor_bg, &queued_bg, flushed_sz, &mut buffer).await;
                                }
                                break;
                            }
                        }
                    }
                    _ = &mut coalesce_sleep, if coalesce_armed => {
                        coalesce_armed = false;
                        if !buffer.is_empty() {
                            let flushed_sz = std::mem::take(&mut buf_bytes);
                            flush_vec(&storage, &config, &metrics_bg, &monitor_bg, &queued_bg, flushed_sz, &mut buffer).await;
                            last_flush_at = Some(tokio::time::Instant::now());
                        }
                    }
                }
            }
        });

        Self {
            tx,
            queued_bytes,
            metrics,
            self_monitor,
        }
    }

    pub fn try_enqueue(&self, item: IngestWriteItem) -> Result<(), &'static str> {
        let est = estimate_item_bytes(&item);
        let prev = self.queued_bytes.fetch_add(est, Ordering::Relaxed);
        if prev.saturating_add(est) > MAX_QUEUED_BYTES {
            self.queued_bytes.fetch_sub(est, Ordering::Relaxed);
            self.metrics
                .self_errors_total
                .fetch_add(1, Ordering::Relaxed);
            self.self_monitor.record(
                "batch_writer",
                "warn",
                "queue",
                "Micro-batch ingest byte budget saturated (16 MiB)",
                None,
            );
            return Err("queue_full");
        }
        match self.tx.try_send(WriterMsg::Item(Box::new(item), est)) {
            Ok(()) => {
                self.metrics.queue_depth.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.queued_bytes.fetch_sub(est, Ordering::Relaxed);
                self.metrics
                    .self_errors_total
                    .fetch_add(1, Ordering::Relaxed);
                self.self_monitor.record(
                    "batch_writer",
                    "error",
                    "queue",
                    "Micro-batch ingest queue is full (4096)",
                    None,
                );
                Err("queue_full")
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.queued_bytes.fetch_sub(est, Ordering::Relaxed);
                self.metrics
                    .self_errors_total
                    .fetch_add(1, Ordering::Relaxed);
                self.self_monitor.record(
                    "batch_writer",
                    "error",
                    "queue",
                    "Micro-batch ingest queue channel closed",
                    None,
                );
                Err("queue_closed")
            }
        }
    }

    pub async fn flush_now(&self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.tx.send(WriterMsg::Flush(ack_tx)).await.is_ok() {
            let _ = ack_rx.await;
        }
    }

    pub async fn shutdown(&self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.tx.send(WriterMsg::Shutdown(ack_tx)).await.is_ok() {
            let _ = ack_rx.await;
        }
    }
}

fn sub_atomic_usize(atom: &AtomicUsize, delta: usize) {
    loop {
        let prev = atom.load(Ordering::Relaxed);
        if atom
            .compare_exchange_weak(
                prev,
                prev.saturating_sub(delta),
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            break;
        }
    }
}

async fn flush_vec(
    storage: &Arc<dyn StorageBackend>,
    config: &Arc<AppConfig>,
    metrics: &Arc<AppMetrics>,
    self_monitor: &Arc<SelfMonitor>,
    queued_bytes: &Arc<AtomicUsize>,
    flushed_bytes: usize,
    buffer: &mut Vec<IngestWriteItem>,
) {
    let drained: Vec<IngestWriteItem> = std::mem::take(buffer);
    let count = drained.len() as u64;
    sub_atomic_usize(queued_bytes, flushed_bytes);
    loop {
        let prev = metrics.queue_depth.load(Ordering::Relaxed);
        if metrics
            .queue_depth
            .compare_exchange_weak(
                prev,
                prev.saturating_sub(count),
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            break;
        }
    }
    metrics.batch_flushes_total.fetch_add(1, Ordering::Relaxed);

    // Retry transient lock/pool blips once before falling back to per-item isolation so
    // a single poisoned item never destroys the remaining up to 127 valid items in the batch.
    let mut attempt_items = Some(drained);
    let mut last_err = String::new();
    for delay_ms in [0u64, 25, 100] {
        if delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        let batch = attempt_items.take().unwrap_or_default();
        if batch.is_empty() {
            return;
        }
        let backup = if delay_ms < 100 || batch.len() > 1 {
            Some(batch.clone())
        } else {
            None
        };
        match storage.flush_ingest_batch(batch).await {
            Ok(alerts) => {
                spawn_alert_jobs(config, metrics, self_monitor, alerts);
                return;
            }
            Err(err) => {
                last_err = err;
                attempt_items = backup;
            }
        }
    }

    if let Some(items) = attempt_items {
        if items.len() > 1 {
            let mut failed_count = 0usize;
            for item in items {
                match storage.flush_ingest_batch(vec![item]).await {
                    Ok(alerts) => spawn_alert_jobs(config, metrics, self_monitor, alerts),
                    Err(e) => {
                        failed_count += 1;
                        last_err = e;
                    }
                }
            }
            if failed_count == 0 {
                return;
            }
        }
    }

    metrics.self_errors_total.fetch_add(1, Ordering::Relaxed);
    self_monitor.record(
        "batch_writer",
        "error",
        "storage",
        "Batch ingest flush failed",
        Some(&last_err),
    );
    eprintln!("[bugfinder][batch_writer] flush failed: {last_err}");
}

struct QueuedAlert {
    config: Arc<AppConfig>,
    metrics: Arc<AppMetrics>,
    self_monitor: Arc<SelfMonitor>,
    job: AlertDispatchJob,
}

static ALERT_DISPATCH_TX: OnceLock<mpsc::Sender<QueuedAlert>> = OnceLock::new();

fn alert_queue_tx() -> &'static mpsc::Sender<QueuedAlert> {
    ALERT_DISPATCH_TX.get_or_init(|| {
        let (tx, mut rx) = mpsc::channel::<QueuedAlert>(ALERT_QUEUE_CAPACITY);
        tokio::spawn(async move {
            while let Some(item) = rx.recv().await {
                tokio::spawn(async move {
                    let org_id = item.job.organization_id;
                    match dispatch_alert(item.config, item.job).await {
                        Ok(()) => {
                            item.metrics
                                .alerts_sent_total
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Err(err) => {
                            item.metrics
                                .self_errors_total
                                .fetch_add(1, Ordering::Relaxed);
                            item.self_monitor.record_for_org(
                                org_id,
                                "alerts",
                                "warn",
                                "dispatcher",
                                "Alert delivery failed",
                                Some(&err),
                            );
                        }
                    }
                });
            }
        });
        tx
    })
}

pub fn spawn_alert_jobs(
    config: &Arc<AppConfig>,
    metrics: &Arc<AppMetrics>,
    self_monitor: &Arc<SelfMonitor>,
    alerts: Vec<AlertDispatchJob>,
) {
    let tx = alert_queue_tx();
    for job in alerts {
        let org_id = job.organization_id;
        if tx
            .try_send(QueuedAlert {
                config: config.clone(),
                metrics: metrics.clone(),
                self_monitor: self_monitor.clone(),
                job,
            })
            .is_err()
        {
            metrics.self_errors_total.fetch_add(1, Ordering::Relaxed);
            self_monitor.record_for_org(
                org_id,
                "alerts",
                "warn",
                "dispatcher",
                "Alert dispatch queue saturated (256); dropped alert",
                None,
            );
        }
    }
}
