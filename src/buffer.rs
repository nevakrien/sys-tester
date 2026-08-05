use std::mem::MaybeUninit;
use std::mem::transmute;
use std::ops::Deref;
use std::ptr::copy_nonoverlapping;
use std::{error, fmt};

pub const MAX_PATH: usize = libc::PATH_MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathTooLong;

impl fmt::Display for PathTooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("path exceeds PATH_MAX")
    }
}

impl error::Error for PathTooLong {}

///rust is being anoying this SHOULD be PATH_MAX
#[repr(C, align(4096))]
struct Buffer {
    bytes: [MaybeUninit<u8>; MAX_PATH],
}

// Verify that Buffer is naturally aligned
// this means it is for sure on minimal pages it can be (for pages 4096 or more its on 1 page)
const _: () = assert!(size_of::<Buffer>() == MAX_PATH);
const _: () = assert!(align_of::<Buffer>() == MAX_PATH);

/// A constant size buffer for writing paths into
/// this is
pub struct PathBuffer {
    buf: Box<Buffer>,
    len: usize,
}

impl Deref for PathBuffer {
    type Target = [u8];
    fn deref<'a>(&'a self) -> &'a [u8] {
        let r: &'a [_] = &self.buf.bytes[..self.len];
        unsafe { transmute(r) }
    }
}

impl PathBuffer {
    pub fn truncate(&mut self, l: usize) {
        if l >= self.len {
            return;
        }

        for b in self.buf.bytes[l..].iter_mut() {
            *b = MaybeUninit::uninit();
        }

        self.len = l;
    }
    pub fn clear(&mut self) {
        self.truncate(0);
    }

    pub fn set_slice(&mut self, s: &[u8]) -> Result<(), PathTooLong> {
        if s.len() > MAX_PATH {
            return Err(PathTooLong);
        }

        unsafe {
            self.write_some(|p| {
                copy_nonoverlapping(s.as_ptr(), p, s.len());
                s.len()
            })
        };
        Ok(())
    }

    /// # Safety
    ///
    /// The closure must initialize every byte before the returned length and
    /// must neither write nor return a length greater than [`MAX_PATH`].
    pub unsafe fn write_some(&mut self, f: impl FnOnce(*mut u8) -> usize) {
        self.clear();
        let r = &raw mut self.buf.bytes;
        self.len = f(r.cast());
    }

    pub fn chop_by_null(&mut self) {
        for (i, b) in self.iter().enumerate() {
            if *b == 0 {
                self.truncate(i);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_buffer_manages_initialized_bytes() {
        let mut buffer = PathBuffer {
            buf: Box::new(Buffer {
                bytes: [MaybeUninit::uninit(); MAX_PATH],
            }),
            len: 0,
        };

        assert_eq!((buffer.buf.bytes.as_ptr() as usize) % MAX_PATH, 0);
        assert!(buffer.is_empty());

        buffer.set_slice(b"some/path\0ignored").unwrap();
        assert_eq!(&*buffer, b"some/path\0ignored");

        buffer.chop_by_null();
        assert_eq!(&*buffer, b"some/path");

        buffer.truncate(4);
        assert_eq!(&*buffer, b"some");

        buffer.clear();
        assert!(buffer.is_empty());

        assert_eq!(buffer.set_slice(&[0; MAX_PATH + 1]), Err(PathTooLong));
        assert!(buffer.is_empty());
    }
}
