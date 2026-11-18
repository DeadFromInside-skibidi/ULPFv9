//! Analytics on native events: Sigma rule matching (`ulpf.intelligence.sigma`
//! `SigmaEngine.match`) and output routing (`ulpf.runtime.router.Router`).
//!
//! Both are built from descriptions the Python modules emit (`SigmaEngine.ir()`,
//! `Router.ir()`), so the rule compiler, field resolution tables and route
//! parsing stay in Python. Evaluation returns `Err(Undecided)` for an event
//! whose result depends on semantics not reproduced here (non-ASCII text under
//! case folding, IPv6 parsing, `$` before a newline); the worker then evaluates
//! that one event in Python.
//!
//! Like Python's `EventView`, one evaluation context per event caches what the
//! rules share: each field's resolved value, its `str()` and lower-case forms,
//! and the keyword text. Substring needles are precompiled (`memmem::Finder`,
//! SIMD).

use crate::parsers::to_val;
use crate::pysem::{cmp_int_float, py_eq, py_float, Net, Undecided, U};
use crate::val::{write_json, write_json_str, Map, Val};
use memchr::memmem::Finder;
use rustc_hash::FxHashMap as HashMap;
use serde_json::Value as J;
use std::borrow::Cow;
use std::cell::OnceCell;
use std::cmp::Ordering;

type PResult<T> = Result<T, String>;

fn s<'a>(v: &'a J, k: &str) -> PResult<&'a str> {
    v.get(k).and_then(|x| x.as_str()).ok_or_else(|| format!("ir: missing string {k}"))
}

fn arr<'a>(v: &'a J, k: &str) -> PResult<&'a Vec<J>> {
    v.get(k).and_then(|x| x.as_array()).ok_or_else(|| format!("ir: missing list {k}"))
}

fn strset(v: &J) -> PResult<Option<Vec<String>>> {
    match v {
        J::Null => Ok(None),
        J::Array(a) => a.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| "ir: set of strings".to_string()))
            .collect::<PResult<Vec<_>>>().map(Some),
        _ => Err("ir: set of strings".into()),
    }
}

// ---------------------------------------------------------------------------
// Field resolution (`EventView._resolve`)
// ---------------------------------------------------------------------------

/// How one field name resolves; `id` indexes the per-event cache (one id per name).
pub struct FieldRef {
    id: usize,
    name: String,
    parts: Vec<String>,
    low: String,
    dotted: bool,
    target: Option<Vec<String>>,
}

/// Interns field references by name while a rule set is built.
#[derive(Default)]
struct Fields {
    ids: HashMap<String, usize>,
}

impl Fields {
    fn get(&mut self, v: &J) -> PResult<FieldRef> {
        let name = s(v, "name")?.to_string();
        let n = self.ids.len();
        let id = *self.ids.entry(name.clone()).or_insert(n);
        let target = match v.get("target") {
            Some(J::Array(a)) => Some(a.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect()),
            _ => None,
        };
        Ok(FieldRef { id, parts: name.split('.').map(String::from).collect(), low: s(v, "low")?.to_string(), name,
                      dotted: v.get("dotted").and_then(|x| x.as_bool()).unwrap_or(false), target })
    }
}

fn walk<'a, S: AsRef<str>>(ev: &'a Map, parts: &[S]) -> Option<&'a Val> {
    let mut cur: Option<&Val> = None;
    let mut m = ev;
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            match cur {
                Some(Val::Map(x)) => m = x,
                _ => return None,
            }
        }
        cur = m.get(p.as_ref());
        match cur {
            None | Some(Val::Null) => return None,
            _ => {}
        }
    }
    cur
}

fn nn(v: &Val) -> Option<&Val> {
    if v.is_null() {
        None
    } else {
        Some(v)
    }
}

/// `parsed_fields` looked up the way `EventView._resolve` does (exact name, then the first
/// key equal ignoring case, then the first key whose last dotted segment is the name), built
/// once per event.
struct Parsed<'a> {
    exact: HashMap<&'a str, &'a Val>,
    lower: HashMap<Cow<'a, str>, &'a Val>, // borrowed when the key is already lower case
    leaf: HashMap<Cow<'a, str>, &'a Val>,
    non_ascii: bool, // a key only Python lower-cases: the case-insensitive lookups are undecided
}

fn index_parsed(ev: &Map) -> Option<Parsed<'_>> {
    let parsed = match ev.get("parsed_fields") {
        Some(Val::Map(m)) => m,
        _ => return None,
    };
    let mut p = Parsed { exact: HashMap::default(), lower: HashMap::default(), leaf: HashMap::default(),
                         non_ascii: false };
    for (k, v) in &parsed.0 {
        let k: &str = k.as_ref();
        p.exact.entry(k).or_insert(v);
        if !k.is_ascii() {
            p.non_ascii = true;
            continue;
        }
        let low: Cow<'_, str> = if k.bytes().any(|c| c.is_ascii_uppercase()) {
            Cow::Owned(k.to_ascii_lowercase())
        } else {
            Cow::Borrowed(k)
        };
        if let Some(i) = low.rfind('.') {
            let leaf = match &low {
                Cow::Borrowed(b) => Cow::Borrowed(&b[i + 1..]),
                Cow::Owned(o) => Cow::Owned(o[i + 1..].to_string()),
            };
            p.leaf.entry(leaf).or_insert(v);
        }
        p.lower.entry(low).or_insert(v);
    }
    Some(p)
}

/// The value `EventView.get(name)` returns; None stands for Python None.
fn resolve<'a>(ev: &'a Map, f: &FieldRef, parsed: &Option<Parsed<'a>>) -> U<Option<&'a Val>> {
    if f.dotted {
        if let Some(v) = walk(ev, &f.parts) {
            return Ok(Some(v));
        }
    }
    if let Some(v) = ev.get(&f.name) {
        if !matches!(v, Val::Map(_)) {
            return Ok(nn(v));
        }
    }
    if let Some(t) = &f.target {
        if let Some(v) = walk(ev, t) {
            return Ok(Some(v));
        }
    }
    let Some(p) = parsed else { return Ok(None) };
    if let Some(v) = p.exact.get(f.name.as_str()) {
        return Ok(nn(v));
    }
    if p.non_ascii {
        return Err(Undecided); // str.lower() of non-ASCII keys
    }
    if f.low.bytes().any(|c| c.is_ascii_uppercase()) || !f.low.is_ascii() {
        return Ok(None);                  // `low` is Python's lower(): only an ASCII lower-case name can equal a key
    }
    if let Some(v) = p.lower.get(f.low.as_str()) {
        return Ok(nn(v));                 // str(k).lower() == low
    }
    // flattened documents: the first key whose last dotted segment is the name
    Ok(p.leaf.get(f.low.as_str()).and_then(|v| nn(v)))
}

// ---------------------------------------------------------------------------
// Probes: a value with its str() and lower-case forms, computed on first use
// ---------------------------------------------------------------------------

struct Probe<'a> {
    v: Option<&'a Val>,
    text: OnceCell<Option<Cow<'a, str>>>,
    lower: OnceCell<U<Option<String>>>, // Some(s): lower-cased copy; None: the text has no upper case
}

impl<'a> Probe<'a> {
    fn new(v: Option<&'a Val>) -> Self {
        Probe { v, text: OnceCell::new(), lower: OnceCell::new() }
    }

    fn with_text(t: String) -> Self {
        let p = Probe::new(None);
        let _ = p.text.set(Some(Cow::Owned(t)));
        p
    }

    fn container(&self) -> bool {
        matches!(self.v, Some(Val::List(_)) | Some(Val::Map(_)))
    }

    /// `str(v)` for scalars (None for None and containers).
    fn text(&self) -> Option<&str> {
        self.text.get_or_init(|| match self.v {
            None | Some(Val::List(_)) | Some(Val::Map(_)) => None,
            Some(Val::Str(s)) => Some(Cow::Borrowed(s.as_str())),
            Some(x) => x.py_str().map(Cow::Owned),
        }).as_deref()
    }

    /// `str(v).lower()`: Err for non-ASCII text (Unicode case mapping is Python's).
    fn lower(&self) -> U<Option<&str>> {
        let low = self.lower.get_or_init(|| match self.text() {
            None => Ok(None),
            Some(t) if !t.is_ascii() => Err(Undecided),
            Some(t) if t.bytes().any(|c| c.is_ascii_uppercase()) => Ok(Some(t.to_ascii_lowercase())),
            Some(_) => Ok(None),
        });
        match low {
            Err(e) => Err(*e),
            Ok(Some(s)) => Ok(Some(s.as_str())),
            Ok(None) => Ok(self.text()),
        }
    }
}

/// Per-event cache shared by all rules.
struct Ctx<'a> {
    ev: &'a Map,
    values: Vec<OnceCell<U<Option<&'a Val>>>>,
    probes: Vec<OnceCell<Probe<'a>>>,
    text: OnceCell<U<Probe<'a>>>,
    parsed: OnceCell<Option<Parsed<'a>>>,
}

impl<'a> Ctx<'a> {
    fn new(ev: &'a Map, n: usize) -> Self {
        Ctx { ev, values: (0..n).map(|_| OnceCell::new()).collect(), probes: (0..n).map(|_| OnceCell::new()).collect(),
              text: OnceCell::new(), parsed: OnceCell::new() }
    }

    fn value(&self, f: &FieldRef) -> U<Option<&'a Val>> {
        *self.values[f.id].get_or_init(|| resolve(self.ev, f, self.parsed.get_or_init(|| index_parsed(self.ev))))
    }

    fn probe(&self, f: &FieldRef) -> U<&Probe<'a>> {
        let v = self.value(f)?;
        Ok(self.probes[f.id].get_or_init(|| Probe::new(v)))
    }

    /// `EventView.text()`: f"{raw_event or ''}\n{message or ''}"
    fn text(&self) -> U<&Probe<'a>> {
        match self.text.get_or_init(|| {
            let part = |k: &str| -> U<String> {
                match self.ev.get(k) {
                    Some(v) if v.truthy() => v.py_str().ok_or(Undecided),
                    _ => Ok(String::new()),
                }
            };
            Ok(Probe::with_text(format!("{}\n{}", part("raw_event")?, part("message")?)))
        }) {
            Ok(p) => Ok(p),
            Err(e) => Err(*e),
        }
    }
}

// ---------------------------------------------------------------------------
// Value matchers (`_value_matcher`)
// ---------------------------------------------------------------------------

enum Tok {
    Lit(Vec<u8>),
    Star,
    One,
}

enum Mode {
    Eq,
    Contains(Finder<'static>),
    Starts,
    Ends,
}

enum VM {
    Exists(bool),
    Num(Ordering, bool, f64), // op as (ordering, or-equal), reference
    Null,
    Cidr(Net),
    Re(regex::Regex, bool),   // pattern has '$'
    Bool(bool),
    NumStr(String),
    Str { mode: Mode, needle: String, cased: bool },
    Glob { tok: Vec<Tok>, cased: bool, one: bool },
    Any(Vec<VM>),
    Py, // only Python reproduces it: the event is undecided
}

fn mode(m: &str, needle: &str) -> PResult<Mode> {
    Ok(match m {
        "eq" => Mode::Eq,
        "contains" => Mode::Contains(Finder::new(needle.as_bytes()).into_owned()),
        "startswith" => Mode::Starts,
        "endswith" => Mode::Ends,
        o => return Err(format!("ir: mode {o}")),
    })
}

fn glob_tokens(v: &J) -> PResult<(Vec<Tok>, bool)> {
    let mut one = false;
    let toks = arr(v, "tok")?.iter().map(|t| {
        let a = t.as_array().ok_or("ir: token")?;
        Ok(match a.first().and_then(|x| x.as_str()) {
            Some("*") => Tok::Star,
            Some("?") => {
                one = true;
                Tok::One
            }
            Some("lit") => Tok::Lit(a.get(1).and_then(|x| x.as_str()).ok_or("ir: literal")?.as_bytes().to_vec()),
            _ => return Err("ir: token".to_string()),
        })
    }).collect::<PResult<Vec<_>>>()?;
    Ok((toks, one))
}

impl VM {
    fn from(v: &J) -> PResult<Self> {
        Ok(match s(v, "t")? {
            "exists" => VM::Exists(v["want"].as_bool().unwrap_or(false)),
            "num" => {
                let r = v["ref"].as_f64().ok_or("ir: num ref")?;
                match s(v, "op")? {
                    "lt" => VM::Num(Ordering::Less, false, r),
                    "lte" => VM::Num(Ordering::Less, true, r),
                    "gt" => VM::Num(Ordering::Greater, false, r),
                    "gte" => VM::Num(Ordering::Greater, true, r),
                    o => return Err(format!("ir: op {o}")),
                }
            }
            "null" => VM::Null,
            "cidr" => VM::Cidr(Net::parse(s(v, "net")?).ok_or("ir: network")?),
            "re" => {
                let pat = s(v, "pat")?;
                let fl = s(v, "flags")?;
                let re = regex::RegexBuilder::new(pat).case_insensitive(fl.contains('i'))
                    .multi_line(fl.contains('m')).dot_matches_new_line(fl.contains('s')).build()
                    .map_err(|e| format!("ir: regex: {e}"))?;
                VM::Re(re, pat.contains('$'))
            }
            "bool" => VM::Bool(v["v"].as_bool().unwrap_or(false)),
            "numstr" => VM::NumStr(s(v, "ref")?.to_string()),
            "str" => {
                let needle = s(v, "needle")?.to_string();
                VM::Str { mode: mode(s(v, "mode")?, &needle)?, needle, cased: v["cased"].as_bool().unwrap_or(false) }
            }
            "glob" => {
                let (tok, one) = glob_tokens(v)?;
                VM::Glob { tok, cased: v["cased"].as_bool().unwrap_or(false), one }
            }
            "any" => VM::Any(arr(v, "of")?.iter().map(VM::from).collect::<PResult<_>>()?),
            "py" => VM::Py,
            o => return Err(format!("ir: value matcher {o}")),
        })
    }

    fn matches(&self, p: &Probe) -> U<bool> {
        let v = p.v;
        Ok(match self {
            VM::Exists(want) => (v.is_some() && !matches!(v, Some(Val::Str(x)) if x.is_empty())) == *want,
            VM::Num(ord, eq, r) => match as_number(v)? {
                None => false,
                Some(n) => n.partial_cmp(r).map(|o| o == *ord || (*eq && o == Ordering::Equal)).unwrap_or(false),
            },
            VM::Null => v.is_none() || matches!(v, Some(Val::Str(x)) if x.is_empty()),
            VM::Cidr(net) => match v {
                None => false,
                Some(_) if p.container() => return Err(Undecided), // repr() of a container
                Some(_) => net.contains(p.text().unwrap_or(""))?,
            },
            VM::Re(re, dollar) => match v {
                None if p.text().is_none() => false,
                Some(_) if p.container() => return Err(Undecided),
                _ => {
                    let t = p.text().unwrap_or("");
                    if !t.is_ascii() || (*dollar && t.contains('\n')) {
                        return Err(Undecided);
                    }
                    re.is_match(t)
                }
            },
            VM::Bool(b) => match v {
                Some(Val::Bool(x)) => x == b,
                Some(Val::Str(x)) => x.eq_ignore_ascii_case(if *b { "true" } else { "false" }),
                _ => false,
            },
            VM::NumStr(r) => match p.text() {
                None => false,
                Some(t) => t == r,
            },
            VM::Str { mode, needle, cased } => {
                let t = if *cased { p.text() } else { p.lower()? };
                match t {
                    None => false,
                    Some(t) => match mode {
                        Mode::Eq => t == needle,
                        Mode::Contains(f) => f.find(t.as_bytes()).is_some(),
                        Mode::Starts => t.starts_with(needle.as_str()),
                        Mode::Ends => t.ends_with(needle.as_str()),
                    },
                }
            }
            VM::Glob { tok, cased, one } => {
                let t = match p.text() {
                    None => return Ok(false),
                    Some(t) => t,
                };
                if *one && !t.is_ascii() {
                    return Err(Undecided); // '?' is one character, not one byte
                }
                let t = if *cased { t } else { p.lower()?.unwrap_or("") };
                glob_match(t.as_bytes(), tok)
            }
            VM::Any(ms) => {
                for m in ms {
                    if m.matches(p)? {
                        return Ok(true);
                    }
                }
                false
            }
            VM::Py => return Err(Undecided),
        })
    }
}

/// `_as_number`
fn as_number(v: Option<&Val>) -> U<Option<f64>> {
    Ok(match v {
        None | Some(Val::Null) => None, // float("None")
        Some(Val::Bool(_)) => None,
        Some(Val::Int(i)) => Some(*i as f64),
        Some(Val::Float(f)) => Some(*f),
        Some(Val::Str(x)) => py_float(x)?,
        Some(Val::List(_)) | Some(Val::Map(_)) => None, // repr() never parses as a float
    })
}

/// Whole-text match of `*` / `?` / literal tokens (`re.fullmatch` of the DOTALL wildcard regex).
fn glob_match(t: &[u8], tok: &[Tok]) -> bool {
    // greedy matcher, backtracking to the last star (linear for one star)
    let (mut ti, mut ki) = (0usize, 0usize);
    let mut lit_off = 0usize; // position inside the current literal token
    let mut star: Option<(usize, usize)> = None; // (token after star, text position)
    loop {
        if ki < tok.len() {
            match &tok[ki] {
                Tok::Star => {
                    star = Some((ki + 1, ti));
                    ki += 1;
                    lit_off = 0;
                    continue;
                }
                Tok::One if ti < t.len() => {
                    ti += 1;
                    ki += 1;
                    continue;
                }
                Tok::Lit(l) if ti < t.len() && t[ti] == l[lit_off] => {
                    ti += 1;
                    lit_off += 1;
                    if lit_off == l.len() {
                        ki += 1;
                        lit_off = 0;
                    }
                    continue;
                }
                _ => {}
            }
        } else if ti == t.len() {
            return true;
        }
        match star {
            Some((k, p)) if p < t.len() => {
                star = Some((k, p + 1));
                ki = k;
                ti = p + 1;
                lit_off = 0;
            }
            _ => return false,
        }
    }
}

// ---------------------------------------------------------------------------
// Selections and conditions
// ---------------------------------------------------------------------------

enum Node {
    Field { f: FieldRef, all: bool, m: Vec<VM> },
    FieldRefEq { f: FieldRef, refs: Vec<FieldRef> },
    False,
    Kw(Vec<VM>),
    And(Vec<Node>),
    Or(Vec<Node>),
    Not(Box<Node>),
    AtLeast(usize, Vec<Node>),
}

impl Node {
    fn from(v: &J, fields: &mut Fields) -> PResult<Self> {
        let mut list = |k: &str, fields: &mut Fields| -> PResult<Vec<Node>> {
            arr(v, k)?.iter().map(|x| Node::from(x, fields)).collect()
        };
        Ok(match s(v, "t")? {
            "field" => Node::Field { f: fields.get(&v["f"])?, all: v["all"].as_bool().unwrap_or(false),
                                     m: arr(v, "m")?.iter().map(VM::from).collect::<PResult<_>>()? },
            "fieldref" => Node::FieldRefEq {
                f: fields.get(&v["f"])?,
                refs: arr(v, "refs")?.iter().map(|x| fields.get(x)).collect::<PResult<_>>()?,
            },
            "false" => Node::False,
            "kw" => Node::Kw(arr(v, "m")?.iter().map(VM::from).collect::<PResult<_>>()?),
            "and" => Node::And(list("of", fields)?),
            "or" => Node::Or(list("of", fields)?),
            "not" => Node::Not(Box::new(Node::from(&v["x"], fields)?)),
            "atleast" => Node::AtLeast(v["k"].as_u64().ok_or("ir: k")? as usize, list("of", fields)?),
            o => return Err(format!("ir: node {o}")),
        })
    }

    fn eval(&self, cx: &Ctx) -> U<bool> {
        Ok(match self {
            Node::Field { f, all, m } => {
                let p = cx.probe(f)?;
                if *all {
                    for x in m {
                        if !x.matches(p)? {
                            return Ok(false);
                        }
                    }
                    true
                } else if let Some(Val::List(items)) = p.v {
                    for it in items {
                        let ip = Probe::new(nn(it));
                        for x in m {
                            if x.matches(&ip)? {
                                return Ok(true);
                            }
                        }
                    }
                    false
                } else {
                    for x in m {
                        if x.matches(p)? {
                            return Ok(true);
                        }
                    }
                    false
                }
            }
            Node::FieldRefEq { f, refs } => {
                let a = cx.value(f)?;
                for r in refs {
                    if let Some(a) = a {
                        if py_eq(a, cx.value(r)?.unwrap_or(&Val::Null)) {
                            return Ok(true);
                        }
                    }
                }
                false
            }
            Node::False => false,
            Node::Kw(ms) => {
                let t = cx.text()?;
                for m in ms {
                    if m.matches(t)? {
                        return Ok(true);
                    }
                }
                false
            }
            Node::And(xs) => {
                for x in xs {
                    if !x.eval(cx)? {
                        return Ok(false);
                    }
                }
                true
            }
            Node::Or(xs) => {
                for x in xs {
                    if x.eval(cx)? {
                        return Ok(true);
                    }
                }
                false
            }
            Node::Not(x) => !x.eval(cx)?,
            Node::AtLeast(k, xs) => {
                let mut n = 0;
                for x in xs {
                    if x.eval(cx)? {
                        n += 1;
                    }
                }
                n >= *k
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

struct Rule {
    id: String,
    guard: Option<usize>, // index into Sigma.guards: the logsource guard, evaluated first
    cond: Node,
    categories: Option<Vec<String>>,
    formats: Option<Vec<String>>,
    group_by: Option<Vec<FieldRef>>, // None: plain rule (entity key)
    agg_field: Option<FieldRef>,
    corr_fields: Vec<FieldRef>,      // values the hit carries for Sigma correlations
}

/// One anchored field: an Aho-Corasick automaton over every rule's needles for it.
struct Scan {
    field: Option<FieldRef>,      // None: the keyword text
    ac: aho_corasick::AhoCorasick,
    rules: Vec<Vec<u32>>,         // pattern id -> rules anchored on it
    all: Vec<u32>,                // every rule with a needle here (fallback when undecidable)
}

pub struct Sigma {
    rules: Vec<Rule>,
    entity: [FieldRef; 2],
    n_fields: usize,
    scans: Vec<Scan>,
    anchored: Vec<bool>,          // rule is evaluated only if one of its needles is present
    // Scans of fields that can only come from parsed_fields (not dotted, no schema target):
    // found through the event's own keys (lower-cased name or last segment) instead of
    // resolving every anchored field on every event. The others are always scanned.
    by_key: HashMap<String, Vec<u32>>,
    always: Vec<u32>,
    guards: Vec<Node>,               // distinct logsource guards
    scan_guards: Vec<Vec<u32>>,      // per scan: guards of its rules (u32::MAX: an unguarded rule)
    pub stats: [std::sync::atomic::AtomicU64; 4], // events, candidate rules, conditions evaluated, field scans
}

fn in_set(v: Option<&Val>, set: &Option<Vec<String>>) -> bool {
    match set {
        None => true,
        Some(xs) => matches!(v, Some(Val::Str(s)) if xs.iter().any(|x| x == s)),
    }
}

impl Sigma {
    /// From `SigmaEngine.ir()`: {"rules": [...], "entity": [source.ip, device.hostname field refs]}.
    pub fn from_json(text: &str) -> PResult<Self> {
        let v: J = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let mut fields = Fields::default();
        let mut guards: Vec<Node> = Vec::new();
        let mut guard_ids: HashMap<String, usize> = HashMap::default();
        let rules = arr(&v, "rules")?.iter().map(|r| {
            let guard = match &r["guard"] {
                J::Null => None,
                g => {
                    let key = g.to_string();
                    Some(match guard_ids.get(&key) {
                        Some(&i) => i,
                        None => {
                            guards.push(Node::from(g, &mut fields)?);
                            guard_ids.insert(key, guards.len() - 1);
                            guards.len() - 1
                        }
                    })
                }
            };
            Ok(Rule {
                id: s(r, "id")?.to_string(),
                guard,
                cond: Node::from(&r["cond"], &mut fields)?,
                categories: strset(&r["categories"])?,
                formats: strset(&r["formats"])?,
                group_by: match &r["group_by"] {
                    J::Null => None,
                    J::Array(a) => Some(a.iter().map(|x| fields.get(x)).collect::<PResult<_>>()?),
                    _ => return Err("ir: group_by".to_string()),
                },
                agg_field: match &r["agg_field"] {
                    J::Null => None,
                    f => Some(fields.get(f)?),
                },
                corr_fields: match r.get("corr_fields") {
                    Some(J::Array(a)) => a.iter().map(|x| fields.get(x)).collect::<PResult<_>>()?,
                    _ => Vec::new(),
                },
            })
        }).collect::<PResult<Vec<_>>>()?;
        // anchors: field (by name; "" = keyword text) -> needle -> rules
        let mut by_field: Vec<(Option<FieldRef>, Vec<String>, Vec<Vec<u32>>)> = Vec::new();
        let mut field_slot: HashMap<String, usize> = HashMap::default();
        let mut anchored = vec![false; rules.len()];
        for (ri, r) in arr(&v, "rules")?.iter().enumerate() {
            let Some(list) = r.get("anchors").and_then(|x| x.as_array()) else { continue };
            anchored[ri] = true;
            for a in list {
                let pair = a.as_array().ok_or("ir: anchor")?;
                let (fj, needle) = (&pair[0], pair[1].as_str().ok_or("ir: anchor needle")?);
                let key = if fj.is_null() { String::new() } else { s(fj, "name")?.to_string() };
                let slot = match field_slot.get(&key) {
                    Some(&i) => i,
                    None => {
                        let f = if fj.is_null() { None } else { Some(fields.get(fj)?) };
                        by_field.push((f, Vec::new(), Vec::new()));
                        field_slot.insert(key, by_field.len() - 1);
                        by_field.len() - 1
                    }
                };
                let e = &mut by_field[slot];
                match e.1.iter().position(|x| x == needle) {
                    Some(p) => {
                        if !e.2[p].contains(&(ri as u32)) {
                            e.2[p].push(ri as u32)
                        }
                    }
                    None => {
                        e.1.push(needle.to_string());
                        e.2.push(vec![ri as u32]);
                    }
                }
            }
        }
        let mut scans = Vec::with_capacity(by_field.len());
        for (field, needles, rules_of) in by_field {
            // needles are lower case; matching ASCII-case-insensitively on the original text
            // (ASCII text only, see `candidates`) finds what a search of its lower-cased copy finds
            let build = |kind| aho_corasick::AhoCorasick::builder().match_kind(aho_corasick::MatchKind::Standard)
                .ascii_case_insensitive(true).kind(kind).build(&needles);
            let ac = build(Some(aho_corasick::AhoCorasickKind::DFA)).or_else(|_| build(None))
                .map_err(|e| format!("ir: anchors: {e}"))?;
            let mut all: Vec<u32> = rules_of.iter().flatten().copied().collect();
            all.sort_unstable();
            all.dedup();
            scans.push(Scan { field, ac, rules: rules_of, all });
        }
        let scan_guards: Vec<Vec<u32>> = scans.iter().map(|sc| {
            let mut g: Vec<u32> = sc.all.iter().map(|&r| rules[r as usize].guard.map_or(u32::MAX, |x| x as u32)).collect();
            g.sort_unstable();
            g.dedup();
            g
        }).collect();
        let mut by_key: HashMap<String, Vec<u32>> = HashMap::default();
        let mut always = Vec::new();
        for (i, sc) in scans.iter().enumerate() {
            match &sc.field {
                Some(f) if !f.dotted && f.target.is_none() && f.low.is_ascii() =>
                    by_key.entry(f.low.clone()).or_default().push(i as u32),
                _ => always.push(i as u32),
            }
        }
        let ent = arr(&v, "entity")?;
        if ent.len() != 2 {
            return Err("ir: entity".into());
        }
        let entity = [fields.get(&ent[0])?, fields.get(&ent[1])?];
        Ok(Sigma { rules, entity, n_fields: fields.ids.len(), scans, anchored, by_key, always, guards, scan_guards,
                   stats: Default::default() })
    }

    /// Rules worth evaluating on this event: unanchored ones, and anchored ones with a needle
    /// in the field it anchors on. Lists and text only Python lower-cases make every rule of
    /// that field a candidate (their evaluation decides, or leaves the event to Python).
    fn guard(&self, g: usize, cx: &Ctx, state: &mut [u8]) -> u8 {
        if state[g] == 0 {
            state[g] = match self.guards[g].eval(cx) {
                Ok(false) => 1,
                Ok(true) => 2,
                Err(_) => 3,
            };
        }
        state[g]
    }

    fn candidates(&self, cx: &Ctx, gstate: &mut [u8]) -> Vec<bool> {
        let mut cand: Vec<bool> = self.anchored.iter().map(|a| !a).collect();
        // the scans worth running: fields present in this event (as a top-level key, or a
        // parsed_fields key by lower-cased name or last segment), plus the always-scanned ones
        let mut todo: Vec<u32> = self.always.clone();
        for (k, _) in &cx.ev.0 {
            let k: &str = k.as_ref();
            let hit = if k.bytes().any(|c| c.is_ascii_uppercase()) {
                self.by_key.get(k.to_ascii_lowercase().as_str())
            } else {
                self.by_key.get(k)
            };
            if let Some(s) = hit {
                todo.extend(s);
            }
        }
        match cx.parsed.get_or_init(|| index_parsed(cx.ev)) {
            Some(p) if p.non_ascii => todo.extend(self.by_key.values().flatten()),  // undecidable: scan all
            Some(p) => {
                for k in p.lower.keys().chain(p.leaf.keys()) {
                    if let Some(s) = self.by_key.get(&**k) {
                        todo.extend(s);
                    }
                }
            }
            None => {}
        }
        todo.sort_unstable();
        todo.dedup();
        for &si in &todo {
            let sc = &self.scans[si as usize];
            // only fields some rule with a passing (or undecided) guard needs
            if !self.scan_guards[si as usize].iter().any(|&g| g == u32::MAX || self.guard(g as usize, cx, gstate) != 1) {
                continue;
            }
            self.stats[3].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let probe = match &sc.field {
                Some(f) => match cx.probe(f) {
                    Ok(p) => p,
                    Err(_) => {
                        sc.all.iter().for_each(|&r| cand[r as usize] = true);
                        continue;
                    }
                },
                None => match cx.text() {
                    Ok(p) => p,
                    Err(_) => {
                        sc.all.iter().for_each(|&r| cand[r as usize] = true);
                        continue;
                    }
                },
            };
            if probe.container() {
                sc.all.iter().for_each(|&r| cand[r as usize] = true);
                continue;
            }
            let text = match probe.text() {
                Some(t) if t.is_ascii() => t,
                Some(_) => {                      // only Python lower-cases non-ASCII text
                    sc.all.iter().for_each(|&r| cand[r as usize] = true);
                    continue;
                }
                None => continue,
            };
            if !sc.ac.is_match(text) {           // the common case: no needle at all (prefilter)
                continue;
            }
            for m in sc.ac.find_overlapping_iter(text) {
                for &r in &sc.rules[m.pattern().as_usize()] {
                    cand[r as usize] = true;
                }
            }
        }
        cand
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// `SigmaEngine.match(event)` as a JSON array of [rule_id, group_key, aggregation value].
    pub fn match_json(&self, ev: &Map, out: &mut String) -> U<usize> {
        let cx = Ctx::new(ev, self.n_fields);
        let start = out.len();
        let r = self.write_hits(&cx, out);
        if r.is_err() {
            out.truncate(start);
        }
        r
    }

    fn write_hits(&self, cx: &Ctx, out: &mut String) -> U<usize> {
        let ev = cx.ev;
        let mut n = 0;
        let mut gstate = vec![0u8; self.guards.len()];
        let cand = self.candidates(cx, &mut gstate);
        use std::sync::atomic::Ordering::Relaxed;
        self.stats[0].fetch_add(1, Relaxed);
        self.stats[1].fetch_add(cand.iter().filter(|c| **c).count() as u64, Relaxed);
        let mut evaluated = 0u64;
        let (category, raw_format) = (ev.get("category"), ev.get("raw_format"));   // once per event
        out.push('[');
        for (ri, r) in self.rules.iter().enumerate() {
            if !cand[ri] {
                continue;
            }
            if !in_set(category, &r.categories) || !in_set(raw_format, &r.formats) {
                continue;
            }
            if let Some(g) = r.guard {
                match self.guard(g, cx, &mut gstate) {
                    1 => continue,
                    3 => return Err(Undecided),
                    _ => {}
                }
            }
            evaluated += 1;
            if !r.cond.eval(cx)? {
                continue;
            }
            self.stats[2].fetch_add(evaluated, Relaxed);
            evaluated = 0;
            let key = self.group_key(r, cx)?;
            let agg = match &r.agg_field {
                Some(f) => cx.value(f)?.cloned().unwrap_or(Val::Null),
                None => Val::Null,
            };
            if n > 0 {
                out.push(',');
            }
            out.push('[');
            write_json_str(&r.id, out);
            out.push(',');
            write_json_str(&key, out);
            out.push(',');
            write_json(&agg, out);
            if !r.corr_fields.is_empty() {
                out.push_str(",[");
                for (i, f) in r.corr_fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    match cx.value(f)? {
                        None => out.push_str("null"),
                        Some(Val::List(_)) | Some(Val::Map(_)) => return Err(Undecided), // Python sends str()
                        Some(v) => write_json(v, out),
                    }
                }
                out.push(']');
            }
            out.push(']');
            n += 1;
        }
        self.stats[2].fetch_add(evaluated, Relaxed);
        out.push(']');
        Ok(n)
    }

    fn group_key(&self, r: &Rule, cx: &Ctx) -> U<String> {
        match &r.group_by {
            None => {
                // str(ev.get("source.ip") or ev.get("device.hostname") or "")
                for f in &self.entity {
                    if let Some(v) = cx.value(f)? {
                        if v.truthy() {
                            return v.py_str().ok_or(Undecided);
                        }
                    }
                }
                Ok(String::new())
            }
            Some(fields) => {
                let mut out = String::new();
                for (i, f) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push('|');
                    }
                    match cx.value(f)? {
                        None => out.push_str("None"),
                        Some(v) => out.push_str(&v.py_str().ok_or(Undecided)?),
                    }
                }
                Ok(out)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Routing (`Router.targets`)
// ---------------------------------------------------------------------------

struct Route {
    to: Vec<usize>,
    fin: bool,
    kind_in: Option<Vec<String>>,
    input_in: Option<Vec<String>>,
    source_in: Option<Vec<String>>,
    raw_format_in: Option<Vec<String>>,
    category_in: Option<Vec<String>>,
    sev_gte: Option<Val>,
    sev_lte: Option<Val>,
    exists: Vec<Vec<String>>,
    equals: Vec<(Vec<String>, Val)>,
}

pub struct Router {
    routes: Vec<Route>,
    default: Option<usize>,
}

fn num_cmp(a: &Val, b: &Val) -> Option<Ordering> {
    match (a, b) {
        (Val::Int(x), Val::Int(y)) => Some(x.cmp(y)),
        (Val::Int(x), Val::Float(y)) => cmp_int_float(*x as i128, *y),
        (Val::Float(x), Val::Int(y)) => cmp_int_float(*y as i128, *x).map(|o| o.reverse()),
        (Val::Float(x), Val::Float(y)) => x.partial_cmp(y),
        _ => None,
    }
}

impl Router {
    /// From `Router.ir()`: {"routes": [...], "default": sink index or null}; sinks are indices.
    pub fn from_json(text: &str) -> PResult<Self> {
        let v: J = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let path = |p: &J| -> PResult<Vec<String>> {
            Ok(p.as_str().ok_or("ir: path")?.split('.').map(String::from).collect())
        };
        let sev = |x: &J| -> PResult<Option<Val>> {
            match x {
                J::Null => Ok(None),
                J::Number(_) => Ok(Some(to_val(x).map_err(|_| "ir: severity bound")?)),
                _ => Err("ir: severity bound is not a number".into()),
            }
        };
        let routes = arr(&v, "routes")?.iter().map(|r| {
            Ok(Route {
                to: arr(r, "to")?.iter().map(|x| x.as_u64().map(|i| i as usize).ok_or("ir: sink")).collect::<Result<_, _>>()?,
                fin: r["final"].as_bool().unwrap_or(false),
                kind_in: strset(&r["kind_in"])?,
                input_in: strset(&r["input_in"])?,
                source_in: strset(&r["source_in"])?,
                raw_format_in: strset(&r["raw_format_in"])?,
                category_in: strset(&r["category_in"])?,
                sev_gte: sev(&r["severity_gte"])?,
                sev_lte: sev(&r["severity_lte"])?,
                exists: arr(r, "field_exists")?.iter().map(path).collect::<PResult<_>>()?,
                equals: arr(r, "field_equals")?.iter().map(|pv| {
                    let a = pv.as_array().ok_or("ir: field_equals")?;
                    Ok((path(&a[0])?, to_val(&a[1]).map_err(|_| "ir: field_equals value needs Python".to_string())?))
                }).collect::<PResult<_>>()?,
            })
        }).collect::<PResult<Vec<_>>>()?;
        Ok(Router { routes, default: v["default"].as_u64().map(|i| i as usize) })
    }

    fn route_matches(r: &Route, ev: &Map) -> bool {
        let set_ok = |v: Option<&Val>, set: &Option<Vec<String>>| match set {
            None => true,
            Some(xs) => matches!(v, Some(Val::Str(s)) if xs.iter().any(|x| x == s)),
        };
        let kind = ev.get("event_kind");
        if r.kind_in.is_some() && !set_ok(Some(kind.unwrap_or(&Val::Str("log".into()))), &r.kind_in) {
            return false;
        }
        let meta = match ev.get("metadata") {
            Some(Val::Map(m)) => Some(m),
            _ => None,
        };
        let mget = |k: &str| meta.and_then(|m| m.get(k));
        if !set_ok(mget("input"), &r.input_in) || !set_ok(mget("ingestion_source"), &r.source_in)
            || !set_ok(ev.get("raw_format"), &r.raw_format_in) || !set_ok(ev.get("category"), &r.category_in) {
            return false;
        }
        // sev = event.get("severity") or 0
        let sev = match ev.get("severity") {
            Some(v) if v.truthy() => v.clone(),
            _ => Val::Int(0),
        };
        if let Some(g) = &r.sev_gte {
            if num_cmp(&sev, g) == Some(Ordering::Less) || num_cmp(&sev, g).is_none() {
                return false;
            }
        }
        if let Some(l) = &r.sev_lte {
            if num_cmp(&sev, l) == Some(Ordering::Greater) || num_cmp(&sev, l).is_none() {
                return false;
            }
        }
        for p in &r.exists {
            match walk(ev, p) {
                None => return false,
                Some(Val::Str(x)) if x.is_empty() => return false,
                Some(Val::List(x)) if x.is_empty() => return false,
                Some(Val::Map(x)) if x.len() == 0 => return false,
                _ => {}
            }
        }
        for (p, want) in &r.equals {
            if !py_eq(walk(ev, p).unwrap_or(&Val::Null), want) {
                return false;
            }
        }
        true
    }

    /// (sink indices, unrouted) for one event.
    pub fn targets(&self, ev: &Map) -> (Vec<usize>, bool) {
        let mut out: Vec<usize> = Vec::new();
        for r in &self.routes {
            if Self::route_matches(r, ev) {
                for t in &r.to {
                    if !out.contains(t) {
                        out.push(*t);
                    }
                }
                if r.fin {
                    break;
                }
            }
        }
        let unrouted = out.is_empty();
        if unrouted {
            if let Some(d) = self.default {
                out.push(d);
            }
        }
        (out, unrouted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(p: &str) -> Vec<Tok> {
        let mut out = vec![];
        let mut lit = vec![];
        for c in p.bytes() {
            if c == b'*' || c == b'?' {
                if !lit.is_empty() {
                    out.push(Tok::Lit(std::mem::take(&mut lit)));
                }
                out.push(if c == b'*' { Tok::Star } else { Tok::One });
            } else {
                lit.push(c);
            }
        }
        if !lit.is_empty() {
            out.push(Tok::Lit(lit));
        }
        out
    }

    #[test]
    fn glob() {
        for (p, t, want) in [("*abc*", "xxabcxx", true), ("abc", "abc", true), ("abc", "abcd", false),
                             ("a*c", "abbbc", true), ("a*c", "abbbd", false), ("a?c", "abc", true),
                             ("a?c", "ac", false), ("*", "", true), ("", "", true), ("", "x", false),
                             ("*a*a*", "aa", true), ("*aab", "aaab", true), ("*ab*cd*", "xabycdz", true),
                             ("*ab*cd*", "xacdab", false), ("a*b*c", "abcabc", true), ("**x", "yx", true),
                             ("*ana", "banana", true), ("*?", "", false), ("?*", "q", true)] {
            assert_eq!(glob_match(t.as_bytes(), &toks(p)), want, "{p} {t}");
        }
    }
}

#[cfg(test)]
mod sigma_bench {
    //! `cargo test --release --lib sigma_bench -- --ignored --nocapture` with
    //! target/sigma_ir_1000.json and target/sigma_events.json written by the benchmark scripts.
    use super::*;
    use std::time::Instant;

    #[test]
    #[ignore]
    fn stages() {
        let ir = std::fs::read_to_string(std::env::var("SIGMA_IR").unwrap_or("target/sigma_ir_1000.json".into())).unwrap();
        let sig = Sigma::from_json(&ir).unwrap();
        let evj: J = serde_json::from_str(&std::fs::read_to_string("target/sigma_events.json").unwrap()).unwrap();
        for corpus in ["mixed", "sysmon"] {
            let evs: Vec<Map> = evj[corpus].as_array().unwrap().iter()
                .filter_map(|e| match crate::parsers::to_val(e) { Ok(Val::Map(m)) => Some(m), _ => None }).collect();
            let n = evs.len() as f64;
            let reps = 20;
            let t = Instant::now();
            for _ in 0..reps { for e in &evs { let cx = Ctx::new(e, sig.n_fields); std::hint::black_box(&cx); } }
            let ctx = t.elapsed().as_secs_f64() / (n * reps as f64) * 1e6;
            let t = Instant::now();
            for _ in 0..reps { for e in &evs { std::hint::black_box(index_parsed(e)); } }
            let idx = t.elapsed().as_secs_f64() / (n * reps as f64) * 1e6;
            let t = Instant::now();
            for _ in 0..reps { for e in &evs { let cx = Ctx::new(e, sig.n_fields); let mut g = vec![0u8; sig.guards.len()];
                                              std::hint::black_box(sig.candidates(&cx, &mut g)); } }
            let cand = t.elapsed().as_secs_f64() / (n * reps as f64) * 1e6;
            let t = Instant::now();
            let mut out = String::new();
            for _ in 0..reps { for e in &evs { out.clear(); let _ = sig.match_json(e, &mut out); } }
            let full = t.elapsed().as_secs_f64() / (n * reps as f64) * 1e6;
            let per = |t: Instant| t.elapsed().as_secs_f64() / (n * reps as f64) * 1e6;
            let t = Instant::now();
            for _ in 0..reps { for _e in &evs {
                let c: Vec<bool> = sig.anchored.iter().map(|a| !a).collect(); std::hint::black_box(c);
                std::hint::black_box(sig.always.clone()); } }
            let p_alloc = per(t);
            let t = Instant::now();
            for _ in 0..reps { for e in &evs { let mut todo: Vec<u32> = Vec::new(); for (k, _) in &e.0 { let k: &str = k.as_ref();
                if let Some(s) = sig.by_key.get(k) { todo.extend(s); } } std::hint::black_box(todo); } }
            let p_top = per(t);
            let t = Instant::now();
            for _ in 0..reps { for e in &evs { let cx = Ctx::new(e, sig.n_fields); let mut todo: Vec<u32> = Vec::new();
                if let Some(p) = cx.parsed.get_or_init(|| index_parsed(cx.ev)) { for k in p.lower.keys().chain(p.leaf.keys()) {
                    if let Some(s) = sig.by_key.get(&**k) { todo.extend(s); } } } std::hint::black_box(todo); } }
            let p_parsed = per(t);
            let t = Instant::now();
            for _ in 0..reps { for e in &evs { let cx = Ctx::new(e, sig.n_fields); for &si in &sig.always {
                if let Some(f) = &sig.scans[si as usize].field { let _ = std::hint::black_box(cx.probe(f).map(|p| p.text().map(|t| t.len()))); }
                else { let _ = std::hint::black_box(cx.text().map(|p| p.text().map(|t| t.len()))); } } } }
            let p_probe = per(t);
            println!("  alloc={p_alloc:.2} top={p_top:.2} parsed(+index)={p_parsed:.2} always_probes(+ctx)={p_probe:.2}");
            let scans = sig.stats[3].swap(0, std::sync::atomic::Ordering::Relaxed) as f64 / (n * reps as f64 * 2.0);
            println!("{corpus}: fields={} ctx_new={ctx:.2}us index={idx:.2}us ctx+candidates={cand:.2}us match={full:.2}us                       scans/event={scans:.1} todo={} always={}", sig.n_fields, sig.always.len(), sig.always.len());
        }
    }
}
