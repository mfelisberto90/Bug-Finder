use crate::alerts::dispatcher::{dispatch_alert, AlertDispatchJob};
use crate::config::AppConfig;
use crate::security::metrics::AppMetrics;
use crate::storage::{IngestWriteItem, StorageBackend};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

enum WriterMsg {
    Item(IngestWriteItem),
    Flush(oneshot::Sender<()>),
    Shutdown(oneshot::Sender<()>),
}

/// Micro-batching ingestion writer: decouples HTTP response latency (<0.3ms)
/// from SQLite WAL / Postgres transaction overhead and survives error storms cleanly.
pub struct BatchWriter {
    tx: mpsc::Sender<WriterMsg>,
    metrics: Arc<AppMetrics>,
}

impl BatchWriter {
    pub fn spawn(
        storage: Arc<dyn StorageBackend>,
        config: Arc<AppConfig>,
        metrics: Arc<AppMetrics>,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<WriterMsg>(4096);
        let metrics_bg = metrics.clone();

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
                                buffer.push(item);
                                if buffer.len() >= 128 {
                                    flush_vec(&storage, &config, &metrics_bg, &mut buffer).await;
                                }
                            }
                            Some(WriterMsg::Flush(ack)) => {
                                while let Ok(msg) = rx.try_recv() {
                                    if let WriterMsg::Item(it) = msg {
                                        buffer.push(it);
                                    }
                                }
                                if !buffer.is_empty() {
                                    flush_vec(&storage, &config, &metrics_bg, &mut buffer).await;
                                }
                                let _ = ack.send(());
                            }
                            Some(WriterMsg::Shutdown(ack)) => {
                                while let Ok(msg) = rx.try_recv() {
                                    if let WriterMsg::Item(it) = msg {
                                        buffer.push(it);
                                    }
                                }
                                if !buffer.is_empty() {
                                    flush_vec(&storage, &config, &metrics_bg, &mut buffer).await;
                                }
                                let _ = ack.send(());
                                break;
                            }
                            None => {
                                if !buffer.is_empty() {
                                    flush_vec(&storage, &config, &metrics_bg, &mut buffer).await;
                                }
                                break;
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        if !buffer.is_empty() {
                            flush_vec(&storage, &config, &metrics_bg, &mut buffer).await;
                        }
                    }
                }
            }
        });

        Self { tx, metrics }
    }

    pub fn try_enqueue(&self, item: IngestWriteItem) -> Result<(), &'static str> {
        match self.tx.try_send(WriterMsg::Item(item)) {
            Ok(()) => {
                self.metrics.queue_depth.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => Err("queue_full"),
            Err(mpsc::error::TrySendError::Closed(_)) => Err("queue_closed"),
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
    buffer: &mut Vec<IngestWriteItem>,
) {
    let drained: Vec<IngestWriteItem> = std::mem::take(buffer);
    let count = drained.len() as u64;
    let prev = metrics.queue_depth.load(Ordering::Relaxed);
    metrics
        .queue_depth
        .store(prev.saturating_sub(count), Ordering::Relaxed);
    metrics.batch_flushes_total.fetch_add(1, Ordering::Relaxed);

    match storage.flush_ingest_batch(drained).await {
        Ok(alerts) => {
            spawn_alert_jobs(config, metrics, alerts);
        }
        Err(err) => {
            eprintln!("[bugfinder][batch_writer] flush failed: {err}");
        }
    }
}

pub fn spawn_alert_jobs(
    config: &Arc<AppConfig>,
    metrics: &Arc<AppMetrics>,
    alerts: Vec<AlertDispatchJob>,
) {
    for job in alerts {
        let cfg = config.clone();
        let m = metrics.clone();
        tokio::spawn(async move {
            if dispatch_alert(cfg, job).await.is_ok() {
                m.alerts_sent_total.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
}
