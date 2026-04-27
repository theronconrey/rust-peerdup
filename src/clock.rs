use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct VectorClock(pub BTreeMap<String, u64>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockOrdering {
    Equal,
    SelfDominates,
    OtherDominates,
    Concurrent,
}

impl VectorClock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment(&mut self, peer: &str) {
        let counter = self.0.entry(peer.to_string()).or_insert(0);
        *counter += 1;
    }

    pub fn merge(&mut self, other: &VectorClock) {
        for (peer, &v) in &other.0 {
            let our = self.0.entry(peer.clone()).or_insert(0);
            if v > *our {
                *our = v;
            }
        }
    }

    pub fn compare(&self, other: &VectorClock) -> ClockOrdering {
        let mut self_ahead = false;
        let mut other_ahead = false;
        let keys: BTreeSet<&String> = self.0.keys().chain(other.0.keys()).collect();
        for key in keys {
            let s = self.0.get(key).copied().unwrap_or(0);
            let o = other.0.get(key).copied().unwrap_or(0);
            if s > o {
                self_ahead = true;
            }
            if o > s {
                other_ahead = true;
            }
        }
        match (self_ahead, other_ahead) {
            (false, false) => ClockOrdering::Equal,
            (true, false) => ClockOrdering::SelfDominates,
            (false, true) => ClockOrdering::OtherDominates,
            (true, true) => ClockOrdering::Concurrent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal() {
        let a = VectorClock::new();
        let b = VectorClock::new();
        assert_eq!(a.compare(&b), ClockOrdering::Equal);
    }

    #[test]
    fn dominates_after_increment() {
        let mut a = VectorClock::new();
        let b = VectorClock::new();
        a.increment("p1");
        assert_eq!(a.compare(&b), ClockOrdering::SelfDominates);
        assert_eq!(b.compare(&a), ClockOrdering::OtherDominates);
    }

    #[test]
    fn concurrent_when_each_ahead_on_different_peer() {
        let mut a = VectorClock::new();
        let mut b = VectorClock::new();
        a.increment("p1");
        b.increment("p2");
        assert_eq!(a.compare(&b), ClockOrdering::Concurrent);
        assert_eq!(b.compare(&a), ClockOrdering::Concurrent);
    }

    #[test]
    fn merge_takes_per_peer_max() {
        let mut a = VectorClock::new();
        a.increment("p1");
        a.increment("p1");
        a.increment("p2");
        let mut b = VectorClock::new();
        b.increment("p1");
        b.increment("p3");
        b.merge(&a);
        assert_eq!(b.0.get("p1"), Some(&2));
        assert_eq!(b.0.get("p2"), Some(&1));
        assert_eq!(b.0.get("p3"), Some(&1));
    }
}
