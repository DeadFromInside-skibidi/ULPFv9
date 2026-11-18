//! Arrow C Data Interface export of the store rows
//! (https://arrow.apache.org/docs/format/CDataInterface.html), offered through the
//! Arrow PyCapsule interface (`__arrow_c_array__`): pyarrow takes the column
//! buffers the core built without copying them, and frees them through the
//! `release` callbacks when the last Arrow array using them goes away. A capsule
//! that is never imported releases them in its destructor.

use crate::engine::Column;
use std::ffi::{c_char, c_void, CString};
use std::ptr;

const FLAG_NULLABLE: i64 = 2;

#[repr(C)]
pub struct ArrowSchema {
    format: *const c_char,
    name: *const c_char,
    metadata: *const c_char,
    flags: i64,
    n_children: i64,
    children: *mut *mut ArrowSchema,
    dictionary: *mut ArrowSchema,
    release: Option<unsafe extern "C" fn(*mut ArrowSchema)>,
    private_data: *mut c_void,
}

#[repr(C)]
pub struct ArrowArray {
    length: i64,
    null_count: i64,
    offset: i64,
    n_buffers: i64,
    n_children: i64,
    buffers: *mut *const c_void,
    children: *mut *mut ArrowArray,
    dictionary: *mut ArrowArray,
    release: Option<unsafe extern "C" fn(*mut ArrowArray)>,
    private_data: *mut c_void,
}

// The structs are moved to another thread only as a whole, by their owner
unsafe impl Send for ArrowSchema {}
unsafe impl Send for ArrowArray {}

struct SchemaPrivate {
    _format: CString,
    _name: CString,
    children: Vec<*mut ArrowSchema>,
}

struct ArrayPrivate {
    buffers: Vec<*const c_void>,
    _owned: Vec<Vec<u8>>,       // the memory `buffers` points into
    children: Vec<*mut ArrowArray>,
}

static EMPTY: [u64; 1] = [0]; // an aligned address for zero-length buffers

unsafe extern "C" fn release_schema(s: *mut ArrowSchema) {
    if s.is_null() || (*s).release.is_none() {
        return;
    }
    let p = Box::from_raw((*s).private_data as *mut SchemaPrivate);
    for &c in &p.children {
        if let Some(r) = (*c).release {
            r(c);
        }
        drop(Box::from_raw(c));
    }
    drop(p);
    (*s).release = None;
}

unsafe extern "C" fn release_array(a: *mut ArrowArray) {
    if a.is_null() || (*a).release.is_none() {
        return;
    }
    let p = Box::from_raw((*a).private_data as *mut ArrayPrivate);
    for &c in &p.children {
        if let Some(r) = (*c).release {
            r(c);
        }
        drop(Box::from_raw(c));
    }
    drop(p);
    (*a).release = None;
}

fn schema(format: &str, name: &str, flags: i64, children: Vec<*mut ArrowSchema>) -> ArrowSchema {
    let fmt = CString::new(format).unwrap();
    let nm = CString::new(name).unwrap();
    let mut p = Box::new(SchemaPrivate { _format: fmt, _name: nm, children });
    let s = ArrowSchema {
        format: p._format.as_ptr(), name: p._name.as_ptr(), metadata: ptr::null(), flags,
        n_children: p.children.len() as i64,
        children: if p.children.is_empty() { ptr::null_mut() } else { p.children.as_mut_ptr() },
        dictionary: ptr::null_mut(), release: Some(release_schema), private_data: ptr::null_mut(),
    };
    let mut s = s;
    s.private_data = Box::into_raw(p) as *mut c_void;
    s
}

fn buf_ptr(v: &[u8]) -> *const c_void {
    if v.is_empty() {
        EMPTY.as_ptr() as *const c_void
    } else {
        v.as_ptr() as *const c_void
    }
}

fn array(length: usize, null_count: usize, mut owned: Vec<Vec<u8>>, valid: bool, children: Vec<*mut ArrowArray>)
         -> ArrowArray {
    // buffers: [validity or null, then the owned buffers in order]
    let mut buffers: Vec<*const c_void> = Vec::with_capacity(owned.len() + 1);
    let mut iter = owned.iter_mut();
    if valid {
        let v = iter.next().unwrap();
        buffers.push(if null_count == 0 { ptr::null() } else { buf_ptr(v) });
    } else {
        buffers.push(ptr::null());
    }
    for b in iter {
        buffers.push(buf_ptr(b));
    }
    let mut p = Box::new(ArrayPrivate { buffers, _owned: owned, children });
    ArrowArray {
        length: length as i64, null_count: null_count as i64, offset: 0, n_buffers: p.buffers.len() as i64,
        n_children: p.children.len() as i64, buffers: p.buffers.as_mut_ptr(),
        children: if p.children.is_empty() { ptr::null_mut() } else { p.children.as_mut_ptr() },
        dictionary: ptr::null_mut(), release: Some(release_array),
        private_data: Box::into_raw(p) as *mut c_void,
    }
}

/// The store columns as one struct array (a record batch) and its schema.
pub fn export(n: usize, cols: Vec<Column>) -> (ArrowSchema, ArrowArray) {
    let mut fields = Vec::with_capacity(cols.len());
    let mut arrays = Vec::with_capacity(cols.len());
    for c in cols {
        let (format, owned) = if c.kind == 's' {
            ("u", vec![c.validity, c.offsets, c.data])
        } else {
            ("i", vec![c.validity, c.data])
        };
        fields.push(Box::into_raw(Box::new(schema(format, c.name, FLAG_NULLABLE, vec![]))));
        arrays.push(Box::into_raw(Box::new(array(n, c.nulls, owned, true, vec![]))));
    }
    (schema("+s", "", 0, fields), array(n, 0, vec![], false, arrays))
}

impl Drop for ArrowSchema {
    fn drop(&mut self) {
        if let Some(r) = self.release {
            unsafe { r(self) };
        }
    }
}

impl Drop for ArrowArray {
    fn drop(&mut self) {
        if let Some(r) = self.release {
            unsafe { r(self) };
        }
    }
}

/// Every non-null value of an imported Arrow string array (`u` utf8 or `U` large utf8),
/// borrowed: the producer's capsules keep the buffers alive and release them.
///
/// # Safety
/// `schema` and `array` must point to valid, unreleased C Data Interface structs describing the
/// same array (as a `__arrow_c_array__` capsule pair guarantees while the capsules live).
pub unsafe fn for_each_utf8(schema: *const ArrowSchema, array: *const ArrowArray,
                            mut f: impl FnMut(&[u8])) -> Result<(), String> {
    let s = &*schema;
    let a = &*array;
    let fmt = std::ffi::CStr::from_ptr(s.format).to_bytes();
    let large = match fmt {
        b"u" => false,
        b"U" => true,
        other => return Err(format!("expected a string array, got format {:?}", String::from_utf8_lossy(other))),
    };
    if a.n_buffers != 3 || a.length < 0 || a.offset < 0 {
        return Err("malformed string array".into());
    }
    let bufs = std::slice::from_raw_parts(a.buffers, 3);
    let validity = bufs[0] as *const u8;
    let data = bufs[2] as *const u8;
    for i in 0..a.length as usize {
        let j = i + a.offset as usize;
        if !validity.is_null() && a.null_count != 0 && (*validity.add(j / 8) >> (j % 8)) & 1 == 0 {
            continue;
        }
        let (lo, hi) = if large {
            let o = bufs[1] as *const i64;
            (*o.add(j) as usize, *o.add(j + 1) as usize)
        } else {
            let o = bufs[1] as *const i32;
            (*o.add(j) as usize, *o.add(j + 1) as usize)
        };
        if hi < lo {
            return Err("malformed string offsets".into());
        }
        f(if hi == lo { &[] } else { std::slice::from_raw_parts(data.add(lo), hi - lo) });
    }
    Ok(())
}
