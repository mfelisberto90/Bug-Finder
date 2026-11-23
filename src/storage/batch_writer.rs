use crate::alerts::dispatcher::{dispatch_alert, AlertDispatchJob};
use crate::config::AppConfig;
use crate::security::metrics::AppMetrics;
use crate::selfcheck::SelfMonitor;
use crate::storage::{IngestWriteItem, StorageBackend};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

enum WriterMsg {
    Item(Box<IngestWriteItem>),
    Flush(oneshot::Sender<()>),
    Shutdown(oneshot::Sender<()>),
}

/// Micro-batching ingestion writer: decouples HTTP response latency (<0.3ms)
/// from SQLite WAL / Postgres transaction overhead and survives error storms cleanly.
pub struct BatchWriter {
    tx: mpsc::Sender<WriterMsg>,
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
        let metrics_bg = metrics.clone();
        let monitor_bg = self_monitor.clone();

        tokio::spawn(async move {
            let mut buffer: Vec<IngestWriteItem> = Vec::with_capacity(128);
            let mut ticker = tokio::time::interval(Duration::from_millis(50));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    biased;
                    maybe_msg = rx.recv() => {
                        match maybe_msg {
                            Some(WriterMsg::Item(item)) => {
                                buffer.push(*item);
                                if buffer.len() >= 128 {
                                    flush_vec(&storage, &config, &metrics_bg, &monitor_bg, &mut buffer).await;
                                }
                            }
                            Some(WriterMsg::Flush(ack)) => {
                                let mut acks = vec![ack];
                                let mut should_shutdown = false;
                                while let Ok(msg) = rx.try_recv() {
                                    match msg {
                                        WriterMsg::Item(it) => buffer.push(*it),
                                        WriterMsg::Flush(a) => acks.push(a),
                                        WriterMsg::Shutdown(a) => {
                                            acks.push(a);
                                            should_shutdown = true;
                                        }
                                    }
                                }
                                if !buffer.is_empty() {
                                    flush_vec(&storage, &config, &metrics_bg, &monitor_bg, &mut buffer).await;
                                }
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
                                        WriterMsg::Item(it) => buffer.push(*it),
                                        WriterMsg::Flush(a) | WriterMsg::Shutdown(a) => acks.push(a),
                                    }
                                }
                                if !buffer.is_empty() {
                                    flush_vec(&storage, &config, &metrics_bg, &monitor_bg, &mut buffer).await;
                                }
                                for a in acks {
                                    let _ = a.send(());
                                }
                                break;
                            }
                            None => {
                                if !buffer.is_empty() {
                                    flush_vec(&storage, &config, &metrics_bg, &monitor_bg, &mut buffer).await;
                                }
                                break;
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        if !buffer.is_empty() {
                            flush_vec(&storage, &config, &metrics_bg, &monitor_bg, &mut buffer).await;
                        }
                    }
                }
            }
        });

        Self {
            tx,
            metrics,
            self_monitor,
        }
    }

    pub fn try_enqueue(&self, item: IngestWriteItem) -> Result<(), &'static str> {
        match self.tx.try_send(WriterMsg::Item(Box::new(item))) {
            Ok(()) => {
                self.metrics.queue_depth.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
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

async fn flush_vec(
    storage: &Arc<dyn StorageBackend>,
    config: &Arc<AppConfig>,
    metrics: &Arc<AppMetrics>,
    self_monitor: &Arc<SelfMonitor>,
    buffer: &mut Vec<IngestWriteItem>,
) {
    let drained: Vec<IngestWriteItem> = std::mem::take(buffer);
    let count = drained.len() as u64;
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

    match storage.flush_ingest_batch(drained).await {
        Ok(alerts) => {
            spawn_alert_jobs(config, metrics, self_monitor, alerts);
        }
        Err(err) => {
            metrics.self_errors_total.fetch_add(1, Ordering::Relaxed);
            self_monitor.record(
                "batch_writer",
                "error",
                "storage",
                "Batch ingest flush failed",
                Some(&err),
            );
            eprintln!("[bugfinder][batch_writer] flush failed: {err}");
        }
    }
}

pub fn spawn_alert_jobs(
    config: &Arc<AppConfig>,
    metrics: &Arc<AppMetrics>,
    self_monitor: &Arc<SelfMonitor>,
    alerts: Vec<AlertDispatchJob>,
) {
    for job in alerts {
        let cfg = config.clone();
        let m = metrics.clone();
        let mon = self_monitor.clone();
        tokio::spawn(async move {
            let org_id = job.organization_id;
            match dispatch_alert(cfg, job).await {
                Ok(()) => {
                    m.alerts_sent_total.fetch_add(1, Ordering::Relaxed);
                }
                Err(err) => {
                    m.self_errors_total.fetch_add(1, Ordering::Relaxed);
                    mon.record_for_org(
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
}
