use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const HISTORY_SIZE: usize = 60;

#[derive(Debug, Clone, Serialize)]
pub struct TrafficPoint {
    pub timestamp: String,
    pub beacon: u32,
    pub probe_req: u32,
    pub probe_resp: u32,
    pub deauth: u32,
    pub disassoc: u32,
    pub auth: u32,
    pub other: u32,
    pub total_pps: u32,
}

pub type SharedTrafficHistory = Arc<Mutex<VecDeque<TrafficPoint>>>;

pub struct PacketCounters {
    pub beacon: Arc<AtomicU32>,
    pub probe_req: Arc<AtomicU32>,
    pub probe_resp: Arc<AtomicU32>,
    pub deauth: Arc<AtomicU32>,
    pub disassoc: Arc<AtomicU32>,
    pub auth: Arc<AtomicU32>,
    pub other: Arc<AtomicU32>,
}

impl PacketCounters {
    pub fn new() -> Self {
        Self {
            beacon: Arc::new(AtomicU32::new(0)),
            probe_req: Arc::new(AtomicU32::new(0)),
            probe_resp: Arc::new(AtomicU32::new(0)),
            deauth: Arc::new(AtomicU32::new(0)),
            disassoc: Arc::new(AtomicU32::new(0)),
            auth: Arc::new(AtomicU32::new(0)),
            other: Arc::new(AtomicU32::new(0)),
        }
    }
}

pub fn spawn_reporter(
    counters: &PacketCounters,
    pps_out: Arc<AtomicU32>,
) -> SharedTrafficHistory {
    let history: SharedTrafficHistory = Arc::new(Mutex::new(VecDeque::with_capacity(HISTORY_SIZE + 1)));

    let beacon = Arc::clone(&counters.beacon);
    let probe_req = Arc::clone(&counters.probe_req);
    let probe_resp = Arc::clone(&counters.probe_resp);
    let deauth = Arc::clone(&counters.deauth);
    let disassoc = Arc::clone(&counters.disassoc);
    let auth = Arc::clone(&counters.auth);
    let other = Arc::clone(&counters.other);
    let hist = Arc::clone(&history);

    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));

        let b = beacon.swap(0, Ordering::Relaxed);
        let pr = probe_req.swap(0, Ordering::Relaxed);
        let ps = probe_resp.swap(0, Ordering::Relaxed);
        let de = deauth.swap(0, Ordering::Relaxed);
        let di = disassoc.swap(0, Ordering::Relaxed);
        let au = auth.swap(0, Ordering::Relaxed);
        let ot = other.swap(0, Ordering::Relaxed);

        let total = b + pr + ps + de + di + au + ot;
        pps_out.store(total, Ordering::Release);

        let point = TrafficPoint {
            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
            beacon: b,
            probe_req: pr,
            probe_resp: ps,
            deauth: de,
            disassoc: di,
            auth: au,
            other: ot,
            total_pps: total,
        };

        let mut h = hist.lock().unwrap();
        h.push_back(point);
        if h.len() > HISTORY_SIZE {
            h.pop_front();
        }
    });

    history
}
