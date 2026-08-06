#[cfg(not(target_arch = "x86_64"))]
compile_error!("seccomp filters currently support only x86_64");

use std::mem::{align_of, size_of};

macro_rules! generated_filter_bytes {
    ($file:literal) => {
        include_bytes!(concat!(env!("OUT_DIR"), "/", $file))
    };
}

macro_rules! filter_len {
    ($file:literal) => {{
        const BYTE_LEN: usize = generated_filter_bytes!($file).len();
        const {
            assert!(
                BYTE_LEN % size_of::<libc::sock_filter>() == 0,
                "generated seccomp filter has an incomplete sock_filter"
            );
        }

        BYTE_LEN / size_of::<libc::sock_filter>()
    }};
}

macro_rules! include_filter {
    ($file:literal) => {{
        const BYTES: &[u8; generated_filter_bytes!($file).len()] = generated_filter_bytes!($file);

        const LEN: usize = filter_len!($file);

        // Safe because:
        // - the input and output arrays have identical sizes;
        // - sock_filter contains only integer fields;
        // - therefore every possible byte pattern is valid;
        // - transmute copies the value, so BYTES need not have sock_filter alignment.
        unsafe { std::mem::transmute::<[u8; BYTES.len()], [libc::sock_filter; LEN]>(*BYTES) }
    }};
}

// The generated file is a raw array of Linux `struct sock_filter`.
const _: () = {
    assert!(size_of::<libc::sock_filter>() == 8);
    assert!(align_of::<libc::sock_filter>() <= 4);
};

pub type SeccompFilter<const LEN: usize> = [libc::sock_filter; LEN];

#[allow(dead_code)]
pub const X86_64_RANGE_FILE_ONLY: SeccompFilter<{ filter_len!("x86_64_range_file_only.bpf") }> =
    include_filter!("x86_64_range_file_only.bpf");

pub const X86_64_RANGE_STRICT: SeccompFilter<{ filter_len!("x86_64_range_strict.bpf") }> =
    include_filter!("x86_64_range_strict.bpf");

#[allow(dead_code)]
pub const X86_64_MAPPED_FILE_ONLY: SeccompFilter<{ filter_len!("x86_64_mapped_file_only.bpf") }> =
    include_filter!("x86_64_mapped_file_only.bpf");

#[allow(dead_code)]
pub const X86_64_MAPPED_STRICT: SeccompFilter<{ filter_len!("x86_64_mapped_strict.bpf") }> =
    include_filter!("x86_64_mapped_strict.bpf");
