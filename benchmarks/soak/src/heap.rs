//! A counting wrapper over the system allocator, so a sample can tell live heap from the memory
//! the allocator keeps after a free. The counters are process-wide atomics: the reader thread
//! allocates what the main thread frees. With the `heap-profile` feature dhat is the allocator
//! instead and the samples read its totals.

#[cfg(not(feature = "heap-profile"))]
use std::alloc::{GlobalAlloc, Layout, System};
#[cfg(not(feature = "heap-profile"))]
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

#[cfg(not(feature = "heap-profile"))]
pub struct CountingAlloc;

#[cfg(not(feature = "heap-profile"))]

static LIVE: AtomicUsize = AtomicUsize::new(0);
#[cfg(not(feature = "heap-profile"))]
static PEAK: AtomicUsize = AtomicUsize::new(0);

#[cfg(not(feature = "heap-profile"))]
fn grow(by: usize) {
    let now = LIVE.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(now, Relaxed);
}

#[cfg(not(feature = "heap-profile"))]
// SAFETY: every call is forwarded unchanged to `System`; the counters only observe sizes.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size >= layout.size() {
                grow(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Relaxed);
            }
        }
        p
    }
}

/// Live heap bytes now and the high-water mark since the previous call (which restarts it).
#[cfg(not(feature = "heap-profile"))]
pub fn take() -> (usize, usize) {
    let live = LIVE.load(Relaxed);
    let peak = PEAK.swap(live, Relaxed);
    (live, peak.max(live))
}

/// Live heap bytes now and dhat's high-water mark since the start (it cannot restart it).
#[cfg(feature = "heap-profile")]
pub fn take() -> (usize, usize) {
    let stats = dhat::HeapStats::get();
    (stats.curr_bytes, stats.max_bytes)
}
