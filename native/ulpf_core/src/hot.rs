//! Hot tier: a memory-mapped ring of records on local (NVMe) disk.
//!
//! One writer per ring (the lakehouse output's sender thread); any number of readers, in this or
//! other processes, read without locks. Positions are logical byte offsets that only grow; the
//! physical offset is `pos % capacity`.
//!
//! Header (4096 bytes): magic, version, capacity, then the atomics `head` (end of the last
//! published record), `tail` (start of the oldest record still intact) and `flushed` (records
//! before it are in the cold tier). Record: `len u32 | kind u32 | seq u64 | key_len u32 |
//! payload_len u32 | key | payload`, padded to 8 bytes; kind 2 marks the padding at the end of
//! the data region when a record does not fit before it.
//!
//! Protocol. Writer: advance `tail` past the records it will overwrite (Release), write the
//! record, publish `head` (Release); `sync` msyncs the records and the header (once per batch,
//! before the caller acknowledges its source). `release` drops flushed pages from memory. Reader: load `head` (Acquire),
//! copy a record, then re-load `tail`: if `tail` moved past the record's start, the copy may be
//! torn and is discarded. Unflushed data is never overwritten: `append` reports the ring full
//! instead (the caller keeps the data in its durable buffer and retries).

use memmap2::MmapMut;
use std::fs::OpenOptions;
use std::sync::atomic::{AtomicU64, Ordering};

const HDR: usize = 4096;
const MAGIC: &[u8; 8] = b"ULPFRING";
const VERSION: u32 = 1;
const OFF_CAP: usize = 16;
const OFF_HEAD: usize = 24;
const OFF_TAIL: usize = 32;
const OFF_FLUSHED: usize = 40;
const OFF_SEQ: usize = 48;
const REC: usize = 24;
const KIND_DATA: u32 = 1;
const KIND_PAD: u32 = 2;
pub const MIN_CAPACITY: u64 = 1 << 16;
pub const MAX_CAPACITY: u64 = 1 << 40;

pub struct Ring {
    map: MmapMut,
    base: *mut u8,                         // map.as_mut_ptr(), taken once at open
    cap: u64,
    writer: std::sync::Mutex<()>,          // one appender at a time; readers never lock
    synced: AtomicU64,                     // records before it are msync'd (this process)
}

// SAFETY: the map is shared memory accessed only through `base` with the protocol in the module
// docs: header fields through atomics, record bytes written by the single writer (the mutex)
// before `head` publishes them, and every reader copy validated against `tail`.
unsafe impl Send for Ring {}
unsafe impl Sync for Ring {}

pub struct Record {
    pub pos: u64,
    pub seq: u64,
    pub key: String,
    pub payload: Vec<u8>,
}

fn align8(n: u64) -> u64 {
    (n + 7) & !7
}

impl Ring {
    /// Open `path`, creating a ring of `capacity` bytes if the file does not exist.
    pub fn open(path: &str, capacity: u64) -> Result<Ring, String> {
        let exists = std::path::Path::new(path).exists();
        let f = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)
            .map_err(|e| format!("{path}: {e}"))?;
        let cap = if exists {
            let len = f.metadata().map_err(|e| e.to_string())?.len();
            if len < HDR as u64 + MIN_CAPACITY {
                return Err(format!("{path}: not a hot-tier ring (size {len})"));
            }
            len - HDR as u64
        } else {
            if !(MIN_CAPACITY..=MAX_CAPACITY).contains(&capacity) {
                return Err(format!("capacity must be {MIN_CAPACITY}..{MAX_CAPACITY} bytes"));
            }
            let cap = capacity & !7;
            f.set_len(HDR as u64 + cap).map_err(|e| e.to_string())?;
            cap
        };
        // SAFETY: the file stays open for the map's lifetime (the map keeps its own handle) and
        // is only resized above, before mapping. Other processes may write it concurrently; all
        // shared fields are accessed through atomics or validated copies (see module docs).
        let mut map = unsafe { MmapMut::map_mut(&f) }.map_err(|e| e.to_string())?;
        if !exists {
            map[..8].copy_from_slice(MAGIC);
            map[8..12].copy_from_slice(&VERSION.to_le_bytes());
            map[OFF_CAP..OFF_CAP + 8].copy_from_slice(&cap.to_le_bytes());
            map.flush_range(0, HDR).map_err(|e| e.to_string())?;
        } else if &map[..8] != MAGIC || u32::from_le_bytes(map[8..12].try_into().unwrap()) != VERSION
            || u64::from_le_bytes(map[OFF_CAP..OFF_CAP + 8].try_into().unwrap()) != cap {
            return Err(format!("{path}: not a version-{VERSION} hot-tier ring"));
        }
        let base = map.as_mut_ptr();
        let r = Ring { map, base, cap, writer: std::sync::Mutex::new(()), synced: AtomicU64::new(0) };
        r.synced.store(r.head(), Ordering::Release);
        Ok(r)
    }

    fn atomic(&self, off: usize) -> &AtomicU64 {
        // SAFETY: `off` is one of the 8-aligned header offsets below HDR; the map is page
        // aligned, so the address is aligned for AtomicU64 and lives as long as `self`.
        unsafe { &*(self.base.add(off) as *const AtomicU64) }
    }

    pub fn capacity(&self) -> u64 {
        self.cap
    }
    pub fn head(&self) -> u64 {
        self.atomic(OFF_HEAD).load(Ordering::Acquire)
    }
    pub fn tail(&self) -> u64 {
        self.atomic(OFF_TAIL).load(Ordering::Acquire)
    }
    pub fn flushed(&self) -> u64 {
        self.atomic(OFF_FLUSHED).load(Ordering::Acquire)
    }

    /// Records before `pos` are in the cold tier (only moves forward, never past `head`).
    pub fn set_flushed(&self, pos: u64) -> Result<(), String> {
        if pos > self.synced.load(Ordering::Acquire) {
            self.sync()?;                      // never drop pages that are not on disk yet
        }
        let pos = pos.min(self.head());
        let old = self.atomic(OFF_FLUSHED).fetch_max(pos, Ordering::AcqRel);
        self.map.flush_range(0, HDR).map_err(|e| e.to_string())?;
        if pos > old {
            self.release(old, pos);
        }
        Ok(())
    }

    /// Drop the resident pages of [from, to) from this process's memory: the bytes are on disk
    /// (msync'd at append) and a later reader faults them back in. Keeps RSS to the unflushed
    /// part of the ring instead of everything written since start.
    fn release(&self, from: u64, to: u64) {
        const PAGE: u64 = 4096;
        let (from, to) = (from.max(to.saturating_sub(self.cap)), to);
        let mut p = from;
        while p < to {
            let phys = p % self.cap;
            let n = (to - p).min(self.cap - phys);
            let (a, b) = ((phys + PAGE - 1) / PAGE * PAGE, (phys + n) / PAGE * PAGE);
            if b > a {
                self.release_phys(HDR + a as usize, (b - a) as usize);
            }
            p += n;
        }
    }

    #[cfg(windows)]
    fn release_phys(&self, off: usize, len: usize) {
        // SAFETY: [off, off+len) lies inside the mapping. VirtualUnlock on pages that are not
        // locked only removes them from the working set (documented); it never frees the view.
        unsafe { windows_sys::Win32::System::Memory::VirtualUnlock(self.base.add(off) as *const _, len) };
    }

    #[cfg(unix)]
    fn release_phys(&self, off: usize, len: usize) {
        // SAFETY: a shared file mapping: MADV_DONTNEED drops the pages, and later reads see the
        // file's contents, which the writer msync'd before publishing them.
        let _ = unsafe { self.map.unchecked_advise_range(memmap2::UncheckedAdvice::DontNeed, off, len) };
    }

    #[cfg(not(any(windows, unix)))]
    fn release_phys(&self, _off: usize, _len: usize) {}

    fn data(&self) -> *mut u8 {
        // SAFETY: HDR < map length (checked at open).
        unsafe { self.base.add(HDR) }
    }

    fn read_u32(&self, phys: u64) -> u32 {
        let mut b = [0u8; 4];
        // SAFETY: phys + 4 <= cap (records are 8-aligned and at least REC bytes), in bounds.
        unsafe { std::ptr::copy_nonoverlapping(self.data().add(phys as usize), b.as_mut_ptr(), 4) };
        u32::from_le_bytes(b)
    }

    /// Length of the record (or padding) at logical `pos`, from what is in the map.
    fn len_at(&self, pos: u64) -> u64 {
        let phys = pos % self.cap;
        if self.cap - phys < REC as u64 {
            return self.cap - phys;      // too short for a header: implicit padding
        }
        let n = self.read_u32(phys) as u64;
        if n < REC as u64 || n > self.cap - phys { self.cap - phys } else { n }
    }

    /// Append one record; Ok(None) when the ring is full of unflushed data.
    pub fn append(&self, key: &str, payload: &[u8]) -> Result<Option<u64>, String> {
        if key.len() > 4096 {
            return Err("partition key longer than 4096 bytes".into());
        }
        let need = align8((REC + key.len() + payload.len()) as u64);
        if need > self.cap / 2 {
            return Err(format!("record of {need} bytes exceeds half the ring ({} bytes)", self.cap));
        }
        let _w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        let head = self.head();
        let phys = head % self.cap;
        let gap = if self.cap - phys < need { self.cap - phys } else { 0 };
        let start = head + gap;
        let end = start + need;
        if end - self.flushed() > self.cap {
            return Ok(None);
        }
        // free the space: move tail past every record the new bytes overlap
        let mut tail = self.tail();
        while end - tail > self.cap {
            tail += self.len_at(tail);
        }
        self.atomic(OFF_TAIL).store(tail, Ordering::Release);
        let seq = self.atomic(OFF_SEQ).fetch_add(1, Ordering::AcqRel);
        if gap >= REC as u64 {
            let mut pad = [0u8; REC];
            pad[..4].copy_from_slice(&(gap as u32).to_le_bytes());
            pad[4..8].copy_from_slice(&KIND_PAD.to_le_bytes());
            self.write(phys, &pad);
        }
        let mut hdr = [0u8; REC];
        hdr[..4].copy_from_slice(&(need as u32).to_le_bytes());
        hdr[4..8].copy_from_slice(&KIND_DATA.to_le_bytes());
        hdr[8..16].copy_from_slice(&seq.to_le_bytes());
        hdr[16..20].copy_from_slice(&(key.len() as u32).to_le_bytes());
        hdr[20..24].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let p = start % self.cap;
        self.write(p, &hdr);
        self.write(p + REC as u64, key.as_bytes());
        self.write(p + (REC + key.len()) as u64, payload);
        self.atomic(OFF_HEAD).store(end, Ordering::Release);
        Ok(Some(start))
    }

    /// Make every appended record durable (msync of the bytes written since the last sync, then
    /// of the header). Callers sync before acknowledging their source (one sync per batch).
    pub fn sync(&self) -> Result<(), String> {
        let _w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        let head = self.head();
        let from = self.synced.load(Ordering::Acquire).max(head.saturating_sub(self.cap));
        let mut p = from;
        while p < head {
            let phys = p % self.cap;
            let n = (head - p).min(self.cap - phys);
            self.map.flush_range(HDR + phys as usize, n as usize).map_err(|e| e.to_string())?;
            p += n;
        }
        self.map.flush_range(0, HDR).map_err(|e| e.to_string())?;
        self.synced.store(head, Ordering::Release);
        Ok(())
    }

    fn write(&self, phys: u64, bytes: &[u8]) {
        debug_assert!(phys as usize + bytes.len() <= self.cap as usize);
        // SAFETY: in bounds (asserted); only the writer (holding `writer`) writes record bytes,
        // and readers validate what they copy (module docs).
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.data().add(phys as usize), bytes.len()) };
    }

    /// Records from logical `pos` up to `head`, at most `max_bytes` of them (at least one).
    /// Returns (records, next position, bytes skipped because they were overwritten).
    pub fn read(&self, mut pos: u64, max_bytes: u64) -> (Vec<Record>, u64, u64) {
        let mut out = Vec::new();
        let mut skipped = 0;
        let mut taken = 0u64;
        let head = self.head();
        while pos < head && (taken < max_bytes || out.is_empty()) {
            let tail = self.tail();
            if pos < tail {
                skipped += tail - pos;
                pos = tail;
                continue;
            }
            let phys = pos % self.cap;
            let n = self.len_at(pos);
            let mut buf = vec![0u8; n as usize];
            // SAFETY: phys + n <= cap by len_at; the copy may race with the writer, which is
            // why it is validated against tail below before use.
            unsafe { std::ptr::copy_nonoverlapping(self.data().add(phys as usize), buf.as_mut_ptr(), n as usize) };
            if self.tail() > pos {
                continue;                // overwritten while copying: re-check from the new tail
            }
            pos += n;
            if n < REC as u64 || u32::from_le_bytes(buf[4..8].try_into().unwrap()) != KIND_DATA {
                continue;                // padding
            }
            let klen = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
            let plen = u32::from_le_bytes(buf[20..24].try_into().unwrap()) as usize;
            if REC + klen + plen > buf.len() {
                continue;
            }
            let Ok(key) = std::str::from_utf8(&buf[REC..REC + klen]) else { continue };
            taken += n;
            out.push(Record { pos: pos - n, seq: u64::from_le_bytes(buf[8..16].try_into().unwrap()), key: key.to_owned(),
                              payload: buf[REC + klen..REC + klen + plen].to_vec() });
        }
        (out, pos, skipped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> String {
        let p = std::env::temp_dir().join(format!("ulpf_ring_{}_{name}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn append_read_wrap_and_backpressure() {
        let path = tmp("a");
        let r = Ring::open(&path, MIN_CAPACITY).unwrap();
        let payload = vec![7u8; 1000];
        let mut n = 0;
        while r.append("t/2026-10-25/10", &payload).unwrap().is_some() {
            n += 1;
        }
        assert_eq!(n, 63);                         // 65536 / 1040
        let (recs, next, skipped) = r.read(0, u64::MAX);
        assert_eq!((recs.len(), skipped), (63, 0));
        assert!(recs.iter().all(|x| x.payload == payload && x.key == "t/2026-10-25/10"));
        r.set_flushed(next).unwrap();
        for _ in 0..100 {                         // wraps; tail follows
            assert!(r.append("k", &payload).unwrap().is_some());
            r.set_flushed(r.head()).unwrap();
        }
        let (recs, _, skipped) = r.read(0, u64::MAX);
        assert!(skipped > 0 && !recs.is_empty() && recs.iter().all(|x| x.key == "k"));
        let seqs: Vec<u64> = recs.iter().map(|x| x.seq).collect();
        assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1));
        drop(r);
        let r2 = Ring::open(&path, 0).unwrap();     // reopen keeps positions
        assert_eq!(r2.read(r2.tail(), u64::MAX).0.last().unwrap().seq, 162);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_bad_files_and_sizes() {
        let path = tmp("b");
        std::fs::write(&path, vec![0u8; HDR + MIN_CAPACITY as usize]).unwrap();
        assert!(Ring::open(&path, 0).is_err());
        let _ = std::fs::remove_file(&path);
        let r = Ring::open(&tmp("c"), MIN_CAPACITY).unwrap();
        assert!(r.append("k", &vec![0u8; 40_000]).is_err());
    }
}
