use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

const MAX_EVENTS: usize = 200;

#[derive(Debug, Clone)]
pub struct SseEvent {
    pub event_type: String,
    pub data: String,
    pub id: u64,
}

pub struct SseBroadcaster {
    events: VecDeque<SseEvent>,
    next_id: u64,
    subscribers: Vec<std::sync::mpsc::Sender<String>>,
}

pub type SharedBroadcaster = Arc<Mutex<SseBroadcaster>>;

impl SseBroadcaster {
    pub fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(MAX_EVENTS + 1),
            next_id: 1,
            subscribers: Vec::new(),
        }
    }

    pub fn push(&mut self, event_type: &str, data: &str) {
        let event = SseEvent {
            event_type: event_type.to_string(),
            data: data.to_string(),
            id: self.next_id,
        };
        self.next_id += 1;

        let sse_msg = format!(
            "id: {}\nevent: {}\ndata: {}\n\n",
            event.id, event.event_type, event.data
        );

        self.subscribers.retain(|tx| tx.send(sse_msg.clone()).is_ok());

        self.events.push_back(event);
        if self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
    }

    pub fn subscribe(&mut self) -> std::sync::mpsc::Receiver<String> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.subscribers.push(tx);
        rx
    }

    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    pub fn events_since(&self, last_id: u64) -> Vec<SseEvent> {
        self.events.iter()
            .filter(|e| e.id > last_id)
            .cloned()
            .collect()
    }

    pub fn latest_events(&self, count: usize) -> Vec<SseEvent> {
        self.events.iter().rev().take(count).cloned().collect()
    }

    pub fn catch_up_since(&self, last_id: u64) -> String {
        let missed = self.events_since(last_id);
        let mut out = String::new();
        for event in &missed {
            out.push_str(&format!(
                "id: {}\nevent: {}\ndata: {}\n\n",
                event.id, event.event_type, event.data
            ));
        }
        out
    }
}
