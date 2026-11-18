//! State of `ulpf.runtime.analytics.DriftMonitor.observe_items`: per (input,
//! source, family) windows of structure signatures, baselines, and the overlap
//! test, with the same arithmetic and orders as Python (signatures in first-seen
//! order, `count / n` probabilities, the overlap summed in the baseline's order).
//! What a fired drift reports (the event, the Log DNA comparison) is built in
//! Python from `Fired`.

use rustc_hash::FxHashMap as HashMap;
use std::time::Instant;

type Key = (String, String, String);

#[derive(Default)]
struct Window {
    n: u64,
    sigs: Vec<(String, u64)>,
    index: HashMap<String, usize>,
    lines: Vec<String>,
}

pub struct Base {
    pub dist: Vec<(String, f64)>,
    pub lines: Vec<String>,
}

pub struct Fired {
    pub family: String,
    pub base_dist: Vec<(String, f64)>,
    pub base_lines: Vec<String>,
    pub dist: Vec<(String, f64)>,
    pub lines: Vec<String>,
    pub sim: f64,
}

pub struct State {
    sample_lines: u64,
    min_interval: f64,
    threshold: f64,
    win: HashMap<Key, Window>,
    base: HashMap<Key, Base>,
    last_check: HashMap<Key, Instant>,
}

/// One observed event: raw_format, structure signature, raw_event.
pub struct Item<'a> {
    pub fmt: Option<&'a str>,
    pub sig: &'a str,
    pub raw: &'a str,
}

impl State {
    pub fn new(sample_lines: u64, min_interval: f64, threshold: f64) -> Self {
        State { sample_lines, min_interval, threshold, win: HashMap::default(), base: HashMap::default(),
                last_check: HashMap::default() }
    }

    /// Observe one event; Some when a drift fires on it.
    pub fn observe(&mut self, input: &str, source: &str, it: &Item) -> Option<Fired> {
        let fmt = match it.fmt {
            Some(f) if !f.is_empty() => f,
            _ => "unknown",
        };
        if fmt == "ulpf_derived" {
            return None;
        }
        let family = if fmt == "auto_detected" || fmt == "raw_fallback" { "unparsed" } else { fmt };
        let key: Key = (input.to_string(), source.to_string(), family.to_string());
        let w = self.win.entry(key.clone()).or_default();
        match w.index.get(it.sig) {
            Some(&i) => w.sigs[i].1 += 1,
            None => {
                w.index.insert(it.sig.to_string(), w.sigs.len());
                w.sigs.push((it.sig.to_string(), 1));
            }
        }
        w.n += 1;
        if w.lines.len() < 200 {
            w.lines.push(it.raw.to_string());
        }
        if w.n < self.sample_lines {
            return None;
        }
        let w = std::mem::take(w);
        let n = w.n as f64;
        let dist: Vec<(String, f64)> = w.sigs.into_iter().map(|(s, c)| (s, c as f64 / n)).collect();
        let Some(base) = self.base.get(&key) else {
            self.base.insert(key, Base { dist, lines: w.lines });
            return None;
        };
        let now = Instant::now();
        if let Some(last) = self.last_check.get(&key) {
            if now.duration_since(*last).as_secs_f64() < self.min_interval {
                return None;
            }
        }
        self.last_check.insert(key.clone(), now);
        // _overlap(base, dist): sum(min(p, dist.get(s, 0.0)) for s, p in base.items())
        let lookup: HashMap<&str, f64> = dist.iter().map(|(s, p)| (s.as_str(), *p)).collect();
        let mut sim = 0.0f64;
        for (s, p) in &base.dist {
            let q = *lookup.get(s.as_str()).unwrap_or(&0.0);
            sim += if q < *p { q } else { *p }; // min(p, q) returns p unless q < p
        }
        if sim >= self.threshold {
            return None;
        }
        let old = self.base.insert(key, Base { dist: dist.clone(), lines: w.lines.clone() }).unwrap();
        Some(Fired { family: family.to_string(), base_dist: old.dist, base_lines: old.lines, dist, lines: w.lines, sim })
    }
}
