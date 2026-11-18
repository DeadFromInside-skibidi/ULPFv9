//! Per-event state of `ulpf.intelligence.anomaly.AnomalyDetector.analyse_event`
//! (severity and byte-volume z-scores, first-seen addresses), bit for bit.
//!
//! Python arithmetic is reproduced exactly: ints stay exact until they meet a
//! float, int/float comparisons do not round, and `x ** 2` calls the same C
//! `pow` CPython's float power does. What Python formats (descriptions,
//! rounding) and the `is_global` check of a first-seen address stay in Python:
//! this module reports raw findings and Python builds the anomaly dicts.

use crate::pysem::cmp_int_float;
use crate::val::Val;
use rustc_hash::FxHashSet as HashSet;
use std::cmp::Ordering;
use std::collections::VecDeque;

extern "C" {
    fn pow(x: f64, y: f64) -> f64;
}

/// A Python int or float.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Num {
    I(i128),
    F(f64),
}

impl Num {
    pub fn f(self) -> f64 {
        match self {
            Num::I(i) => i as f64, // PyLong_AsDouble: round half to even
            Num::F(f) => f,
        }
    }

    fn add(self, o: Num) -> Num {
        match (self, o) {
            (Num::I(a), Num::I(b)) => Num::I(a + b),
            _ => Num::F(self.f() + o.f()),
        }
    }

    /// `v * v` converted to float (the exact square for ints, as Python computes it).
    fn square_f(self) -> f64 {
        match self {
            Num::I(i) => {
                let m = i.unsigned_abs();
                match m.checked_mul(m) {
                    Some(p) => p as f64,
                    None => (m as f64) * (m as f64), // beyond 2**128: unreachable for 64-bit inputs
                }
            }
            Num::F(f) => f * f,
        }
    }

    fn cmp_f(self, f: f64) -> Option<Ordering> {
        match self {
            Num::I(i) => cmp_int_float(i, f),
            Num::F(x) => x.partial_cmp(&f),
        }
    }

    pub fn from_val(v: &Val) -> Option<Num> {
        match v {
            Val::Bool(b) => Some(Num::I(*b as i128)),
            Val::Int(i) => Some(Num::I(*i as i128)),
            Val::Float(f) => Some(Num::F(*f)),
            _ => None,
        }
    }
}

struct Rolling {
    window: usize,
    values: VecDeque<Num>,
    sum: f64,
    sum_sq: f64,
}

impl Rolling {
    fn new(window: usize) -> Self {
        Rolling { window, values: VecDeque::with_capacity(window), sum: 0.0, sum_sq: 0.0 }
    }

    fn add(&mut self, v: Num) {
        if self.values.len() == self.window {
            let old = self.values.pop_front().unwrap();
            self.sum -= old.f();
            self.sum_sq -= old.square_f();
        }
        self.values.push_back(v);
        self.sum += v.f();
        self.sum_sq += v.square_f();
    }

    fn mean(&self) -> f64 {
        let n = self.values.len();
        if n > 0 {
            self.sum / n as f64
        } else {
            0.0
        }
    }

    fn std(&self) -> f64 {
        let n = self.values.len();
        if n < 2 {
            return 0.0;
        }
        let m = self.mean();
        // max(x, 0.0) returns x unless 0.0 > x
        let x = (self.sum_sq / n as f64) - unsafe { pow(m, std::hint::black_box(2.0)) };
        let var = if 0.0 > x { 0.0 } else { x };
        var.sqrt()
    }

    fn z(&self, v: Num) -> f64 {
        let sd = self.std();
        let mean = self.mean();
        if sd == 0.0 {
            return match v.cmp_f(mean) {
                Some(Ordering::Equal) => 0.0,
                Some(Ordering::Greater) => 3.0,
                _ => -3.0,
            };
        }
        (v.f() - mean) / sd
    }
}

/// A hashable Python value used as a dict key (`1`, `1.0` and `True` are one key).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Key {
    S(String),
    I(i128),
    F(u64),
}

fn key(v: &Val) -> Result<Key, String> {
    Ok(match v {
        Val::Str(s) => Key::S(s.to_string()),
        Val::Bool(b) => Key::I(*b as i128),
        Val::Int(i) => Key::I(*i as i128),
        Val::Float(f) => {
            if f.fract() == 0.0 && f.abs() < 1.7e38 {
                Key::I(*f as i128)
            } else {
                Key::F(f.to_bits())
            }
        }
        Val::Null => Key::S("\0None".into()),
        Val::List(_) => return Err("unhashable type: 'list'".into()),
        Val::Map(_) => return Err("unhashable type: 'dict'".into()),
    })
}

pub struct Config {
    pub window: usize,
    pub z_threshold: f64,
    pub max_known_ips: usize,
    pub warmup: i64,
    pub max_novelty: Option<f64>,
}

/// One event's inputs (`event.get(...)` values; None when the key is absent).
pub struct Obs<'a> {
    pub severity: Option<&'a Val>,
    pub ips: [Option<&'a Val>; 2],
    pub bytes: [Option<&'a Val>; 2],
}

pub enum Finding {
    /// (kind, value, mean, std, z): severity_spike / bytes_spike
    Spike(&'static str, Num, f64, f64, f64),
    /// first-seen address after the warm-up while novelty is low (Python checks is_global)
    NewIp(Val, &'static str),
}

pub struct State {
    c: Config,
    severity: Rolling,
    bytes: Rolling,
    known: HashSet<Key>,
    order: VecDeque<Key>,
    obs: VecDeque<u8>,
    obs_new: i64,
    pub total: i64,
}

impl State {
    pub fn new(c: Config) -> Self {
        State { severity: Rolling::new(c.window), bytes: Rolling::new(c.window), known: HashSet::default(),
                order: VecDeque::new(), obs: VecDeque::with_capacity(1000), obs_new: 0, total: 0, c }
    }

    pub fn analyse(&mut self, o: &Obs, out: &mut Vec<Finding>) -> Result<(), String> {
        self.total += 1;
        // event.get("severity", 0): a missing key is 0; None or text raise in Python
        let sev = match o.severity {
            None => Num::I(0),
            Some(v) => Num::from_val(v).ok_or("unsupported operand type for severity")?,
        };
        self.severity.add(sev);
        if self.severity.values.len() > 10 {
            let z = self.severity.z(sev);
            if z.abs() > self.c.z_threshold {
                out.push(Finding::Spike("severity_spike", sev, self.severity.mean(), self.severity.std(), z));
            }
        }
        for (ip, endpoint) in o.ips.iter().zip(["source", "destination"]) {
            let Some(ip) = ip.filter(|v| v.truthy()) else { continue };
            let k = key(ip)?;
            let is_new = !self.known.contains(&k);
            if self.obs.len() == 1000 {
                self.obs_new -= self.obs.pop_front().unwrap() as i64;
            }
            self.obs.push_back(is_new as u8);
            self.obs_new += is_new as i64;
            if is_new {
                self.known.insert(k.clone());
                self.order.push_back(k);
                if self.known.len() > self.c.max_known_ips {
                    if let Some(old) = self.order.pop_front() {
                        self.known.remove(&old);
                    }
                }
                if self.total > self.c.warmup && self.novelty_ok() {
                    out.push(Finding::NewIp(ip.clone(), endpoint));
                }
            }
        }
        let mut total = Num::I(0);
        for b in o.bytes.iter().flatten() {
            if b.truthy() {
                if let Some(n) = Num::from_val(b) {
                    total = total.add(n);
                }
            }
        }
        if total.cmp_f(0.0) == Some(Ordering::Greater) {
            self.bytes.add(total);
            if self.bytes.values.len() > 10 {
                let z = self.bytes.z(total);
                if z.abs() > self.c.z_threshold {
                    out.push(Finding::Spike("bytes_spike", total, self.bytes.mean(), self.bytes.std(), z));
                }
            }
        }
        Ok(())
    }

    fn novelty_ok(&self) -> bool {
        match self.c.max_novelty {
            None => true,
            Some(m) => self.obs.len() == 1000 && (self.obs_new as f64 / self.obs.len() as f64) < m,
        }
    }
}
