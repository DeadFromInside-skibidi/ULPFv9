//! Stage timings of the hot path, for optimisation work (no profiler needed):
//!
//!     python -c "..."   # see docs/DEVELOPMENT_GUIDE.md: writes target/bench_input.json
//!     cargo test --release --lib bench::stages -- --ignored --nocapture
//!
//! The input file holds the normaliser tables (`ulpf.engine.native_lane._tables()`)
//! and a corpus of lines.

#![cfg(test)]

use crate::detect::{Detector, Fmt};
use crate::engine::{BatchArgs, Columns, Core};
use crate::norm::{new_event, Ctx, Tables};
use crate::parsers::Parsers;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use serde_json::Value as J;
use std::time::Instant;

fn tables(v: &J) -> Tables {
    let smap = |k: &str| -> HashMap<String, String> {
        v[k].as_object().unwrap().iter().map(|(a, b)| (a.clone(), b.as_str().unwrap().to_string())).collect()
    };
    let paths = |k: &str| -> HashMap<String, Vec<String>> {
        v[k].as_object().unwrap().iter()
            .map(|(a, b)| (a.clone(), b.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()))
            .collect()
    };
    let imap = |k: &str| -> HashMap<String, i64> {
        v[k].as_object().unwrap().iter().map(|(a, b)| (a.clone(), b.as_i64().unwrap())).collect()
    };
    let strs = |k: &str| -> Vec<String> { v[k].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect() };
    Tables {
        aliases: paths("aliases"), schema_paths: paths("schema_paths"), action_map: smap("action_map"),
        direction_map: smap("direction_map"),
        protocol_map: v["protocol_map"].as_object().unwrap().iter()
            .map(|(a, b)| (a.parse().unwrap(), b.as_str().unwrap().to_string())).collect(),
        protocol_names: imap("protocol_names"),
        syslog_sev: v["syslog_sev"].as_object().unwrap().iter().map(|(a, b)| (a.parse().unwrap(), b.as_i64().unwrap())).collect(),
        cef_sev: imap("cef_sev"), text_sev: imap("text_sev"), categories: strs("categories"),
        category_aliases: smap("category_aliases"), nullish: strs("nullish").into_iter().collect::<HashSet<_>>(),
        int_fields: strs("int_fields").into_iter().collect::<HashSet<_>>(),
        schema_version: v["schema_version"].as_str().unwrap().to_string(),
    }
}

#[test]
#[ignore]
fn stages() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/target/bench_input.json");
    let input: J = serde_json::from_str(&std::fs::read_to_string(path).expect("run the dump script first")).unwrap();
    let core = Core { t: tables(&input["tables"]), det: Detector::new(), p: Parsers::new() };
    let lines: Vec<String> = input["lines"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
    let a = BatchArgs { node: "n", input_name: "i", source: "s", source_ip: "10.9.8.7", now: "2026-01-01T00:00:00.000+00:00" };
    let rounds = 5;
    let n = (lines.len() * rounds) as f64;
    let mut report = |name: &str, f: &mut dyn FnMut()| {
        let t = Instant::now();
        f();
        println!("{name:>18}: {:7.0} ns/event", t.elapsed().as_nanos() as f64 / n);
    };
    let digest = [0u8; 32];
    report("detect", &mut || for _ in 0..rounds { for l in &lines { let mut j = None; std::hint::black_box(core.det.detect(l, &mut j)); } });
    report("new_event", &mut || for _ in 0..rounds { for _ in &lines { std::hint::black_box(new_event("x", "now", "1.1.0")); } });
    report("event_id", &mut || for r in 0..rounds { for (i, _) in lines.iter().enumerate() { std::hint::black_box(crate::engine::event_id("n", (r * 100000 + i) as i64)); } });
    // parse + build per format (Build::build included)
    let c = Ctx { t: &core.t, event_id: "e", now: "now", raw_hash: "h" };
    report("parse+build", &mut || for _ in 0..rounds {
        for l in &lines {
            let mut j = None;
            let (fmt, _) = core.det.detect(l, &mut j);
            let r = match fmt {
                Fmt::Syslog => core.p.syslog(l, &c), Fmt::Cef => core.p.cef(l, &c), Fmt::Leef => core.p.leef(l, &c),
                Fmt::Kv => core.p.kv(l, &c), Fmt::Json => core.p.json(l, j.unwrap(), &c), Fmt::Other => continue,
            };
            std::hint::black_box(r.ok());
        }
    });
    let mut events = Vec::new();
    report("one (all)", &mut || { events.clear(); for r in 0..rounds { for (i, l) in lines.iter().enumerate() {
        let e = core.one(l.as_bytes(), &digest, (r * 100000 + i) as i64, &a);
        if r == 0 { events.push(e); } else { std::hint::black_box(e); } } } });
    #[cfg(feature = "stage-timing")]
    for (i, name) in crate::norm::timing::NAMES.iter().enumerate() {
        let ns = crate::norm::timing::T[i].load(std::sync::atomic::Ordering::Relaxed) as f64;
        println!("{:>18}: {:7.0} ns/event  (Build::build, over parse+build and one)", name, ns / (2.0 * n));
    }
    let natives: Vec<_> = events.iter().flatten().cloned().collect();
    println!("{:>18}: {} of {}", "native", natives.len(), lines.len());
    let m = natives.len() as f64 / lines.len() as f64;
    let mut evs = natives.clone();
    let t = Instant::now();
    for _ in 0..rounds { for e in evs.iter_mut() { crate::engine::enrich(e, &HashMap::default(), &HashMap::default(), &[], None); } }
    println!("{:>18}: {:7.0} ns/event", "enrich", t.elapsed().as_nanos() as f64 / (n * m));
    let t = Instant::now();
    for _ in 0..rounds { let mut cols = Columns::new(natives.len()); for e in &natives { cols.append(e, None).unwrap(); } std::hint::black_box(cols.finish()); }
    println!("{:>18}: {:7.0} ns/event", "row (no mac)", t.elapsed().as_nanos() as f64 / (n * m));
    let t = Instant::now();
    for _ in 0..rounds { let mut cols = Columns::new(natives.len()); for e in &natives { cols.append(e, Some(&[7u8; 32])).unwrap(); } std::hint::black_box(cols.finish()); }
    println!("{:>18}: {:7.0} ns/event", "row + mac", t.elapsed().as_nanos() as f64 / (n * m));
    let t = Instant::now();
    for _ in 0..rounds { let mut s = String::with_capacity(4096); for e in &natives { s.clear(); crate::val::write_json_map(e, &mut s, &["raw_event", "parsed_fields"]); } std::hint::black_box(s); }
    println!("{:>18}: {:7.0} ns/event", "normalised_json", t.elapsed().as_nanos() as f64 / (n * m));
    {
        let mut per: Vec<(String, u128, usize)> = Vec::new();
        for (k, _) in &natives[0].0 {
            per.push((k.to_string(), 0, 0));
        }
        let mut s = String::with_capacity(8192);
        for e in &natives {
            for (k, v) in &e.0 {
                if let Some(slot) = per.iter_mut().find(|x| x.0 == **k) {
                    let t = Instant::now();
                    for _ in 0..rounds { s.clear(); crate::val::write_json(v, &mut s); }
                    slot.1 += t.elapsed().as_nanos();
                    slot.2 += s.len();
                }
            }
        }
        for (k, ns, b) in per {
            println!("    {:>20}: {:6.0} ns/event {:6.0} bytes", k, ns as f64 / (n * m), b as f64 / natives.len() as f64);
        }
    }
    let t = Instant::now();
    for _ in 0..rounds { let mut s = String::with_capacity(4096); for e in &natives { s.clear(); if let Some(crate::val::Val::Map(p)) = e.get("parsed_fields") { crate::val::write_json_map(p, &mut s, &[]); } } std::hint::black_box(s); }
    println!("{:>18}: {:7.0} ns/event", "parsed_fields json", t.elapsed().as_nanos() as f64 / (n * m));
    let t = Instant::now();
    for _ in 0..rounds { let mut s = String::with_capacity(1 << 20); for e in &natives { if let Some(crate::val::Val::Str(r)) = e.get("raw_event") { s.push_str(r); } if s.len() > 1 << 19 { s.clear(); } } std::hint::black_box(s); }
    println!("{:>18}: {:7.0} ns/event", "raw copy", t.elapsed().as_nanos() as f64 / (n * m));
    let t = Instant::now();
    for _ in 0..rounds { let mut s = String::with_capacity(4096); for e in &natives { s.clear(); crate::engine::write_projection(e, &mut s); } std::hint::black_box(s); }
    println!("{:>18}: {:7.0} ns/event", "projection", t.elapsed().as_nanos() as f64 / (n * m));
    let t = Instant::now();
    for _ in 0..rounds { for e in &natives { std::hint::black_box(e.clone()); } }
    println!("{:>18}: {:7.0} ns/event", "clone (allocs)", t.elapsed().as_nanos() as f64 / (n * m));
    let t = Instant::now();
    for _ in 0..rounds { for e in &natives { drop(std::hint::black_box(e.clone())); } }
    println!("{:>18}: {:7.0} ns/event", "clone+drop", t.elapsed().as_nanos() as f64 / (n * m));
}
