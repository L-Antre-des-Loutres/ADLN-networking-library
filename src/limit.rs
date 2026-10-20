use std::time::Instant;

use crate::TrafficLimits;

pub(crate) struct Bucket {
    available: f64,
    rate: f64,
    last: Instant,
}

impl Bucket {
    pub fn new(rate: u32, now: Instant) -> Self {
        Self {
            available: f64::from(rate),
            rate: f64::from(rate),
            last: now,
        }
    }
    pub fn take(&mut self, amount: usize, now: Instant) -> bool {
        self.available = (self.available
            + now.saturating_duration_since(self.last).as_secs_f64() * self.rate)
            .min(self.rate);
        self.last = now;
        if self.available < amount as f64 {
            return false;
        }
        self.available -= amount as f64;
        true
    }
}

pub(crate) struct Budget {
    packets: Bucket,
    bytes: Bucket,
}

impl Budget {
    pub fn new(limits: &TrafficLimits, now: Instant) -> Self {
        Self {
            packets: Bucket::new(limits.packets_per_second, now),
            bytes: Bucket::new(limits.bytes_per_second, now),
        }
    }
    pub fn take(&mut self, length: usize, now: Instant) -> bool {
        self.packets.take(1, now) && self.bytes.take(length, now)
    }
}
