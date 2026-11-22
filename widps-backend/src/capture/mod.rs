// Capture: monitor-mode pcap source, channel hopping and 802.11 frame parsing.
pub mod channel_hopper;
pub mod frame;
pub mod ie_parser;
pub mod packet_stats;
pub mod radiotap;
#[allow(dead_code)] // offline pcap helpers for replay tests; not wired yet
pub mod replay;

use crate::api::legacy::{CaptureMode, RuntimeState};
use pcap::{Active, Capture};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

/// BPF filter keeping only 802.11 management frames.
const MANAGEMENT_ONLY_FILTER: &str = "type mgt";
/// Frames buffered between the capture thread and the processing thread (~1-2 MB of management frames).
pub const FRAME_QUEUE_CAPACITY: usize = 4096;
const REOPEN_INTERVAL: Duration = Duration::from_secs(2);

/// One frame copied out of libpcap's buffer, with the channel and the kernel capture time.
pub struct CapturedFrame {
    pub data: Vec<u8>,
    pub channel: u8,
    pub ts: f64,
}

pub fn open_monitor(iface: &str) -> Option<Capture<Active>> {
    match Capture::from_device(iface) {
        Ok(builder) => match builder.immediate_mode(true).open() {
            Ok(mut cap) => {
                // Drop data and control frames in the kernel. The parser also
                // rejects them, so a failed filter only costs CPU.
                if let Err(e) = cap.filter(MANAGEMENT_ONLY_FILTER, true) {
                    eprintln!("[capture] Could not apply BPF filter '{}': {} (continuing unfiltered)", MANAGEMENT_ONLY_FILTER, e);
                }
                Some(cap)
            }
            Err(e) => {
                eprintln!("[capture] Failed to open capture on '{}': {}", iface, e);
                None
            }
        },
        Err(e) => {
            eprintln!("[capture] Interface '{}' not found: {}", iface, e);
            None
        }
    }
}

/// Hands each frame to `tx` without ever blocking; a full queue drops the frame and counts it.
pub fn offer(tx: &SyncSender<CapturedFrame>, frame: CapturedFrame, runtime: &RuntimeState) -> bool {
    match tx.try_send(frame) {
        Ok(()) => {
            runtime.note_enqueued();
            true
        }
        Err(TrySendError::Full(_)) => {
            runtime.note_dropped();
            true
        }
        Err(TrySendError::Disconnected(_)) => false,
    }
}

/// Capture thread: reads frames and queues them. If the adapter fails, reopens it every 2 s.
pub fn run(iface: &str, mut cap: Capture<Active>, tx: SyncSender<CapturedFrame>, channel: Arc<AtomicU8>, runtime: Arc<RuntimeState>) {
    loop {
        match cap.next_packet() {
            Ok(p) => {
                runtime.note_captured();
                let ts = p.header.ts.tv_sec as f64 + p.header.ts.tv_usec as f64 / 1e6;
                let frame = CapturedFrame { data: p.data.to_vec(), channel: channel.load(Ordering::Acquire), ts };
                if !offer(&tx, frame, &runtime) {
                    return;
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("[capture] capture on {} failed: {}; reopening every {:?}", iface, e, REOPEN_INTERVAL);
                runtime.set_capture_mode(CaptureMode::Error);
                drop(cap);
                cap = loop {
                    std::thread::sleep(REOPEN_INTERVAL);
                    if let Some(c) = open_monitor(iface) {
                        break c;
                    }
                };
                eprintln!("[capture] {} reopened", iface);
                runtime.set_capture_mode(CaptureMode::Live);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::sync_channel;

    #[test]
    fn full_queue_drops_and_counts_without_blocking() {
        let rt = RuntimeState::new("wlan1mon");
        let (tx, rx) = sync_channel::<CapturedFrame>(8);
        let start = std::time::Instant::now();
        for i in 0..1000 {
            assert!(offer(&tx, CapturedFrame { data: vec![0; 64], channel: 6, ts: i as f64 }, &rt));
        }
        assert!(start.elapsed() < Duration::from_secs(1), "offer must never block");
        let s = rt.pipeline_stats();
        assert_eq!((s.enqueued, s.dropped), (8, 992));
        assert_eq!(rx.try_iter().count(), 8);
        drop(rx);
        assert!(!offer(&tx, CapturedFrame { data: vec![], channel: 1, ts: 0.0 }, &rt), "a closed queue stops the capture loop");
    }
}
