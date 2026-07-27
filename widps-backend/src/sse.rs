use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

const MAX_EVENTS: usize = 100;

#[derive(Debug, Clone)]
pub struct SseEvent {
    pub event_type: String,
    pub data: String,
    pub id: u64,
}

pub struct SseBroadcaster {
    events: VecDeque<SseEvent>,
    next_id: u64,
}

pub type SharedBroadcaster = Arc<Mutex<SseBroadcaster>>;

impl SseBroadcaster {
    pub fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(MAX_EVENTS + 1),
            next_id: 1,
        }
    }

    pub fn push(&mut self, event_type: &str, data: &str) {
        let event = SseEvent {
            event_type: event_type.to_string(),
            data: data.to_string(),
            id: self.next_id,
        };
        self.next_id += 1;
        self.events.push_back(event);
        if self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
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
}
