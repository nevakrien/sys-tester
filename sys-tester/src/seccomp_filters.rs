#[cfg(not(target_arch = "x86_64"))]
compile_error!("seccomp filters currently support only x86_64");

use std::mem::size_of;

macro_rules! generated_filter_bytes {
    ($file:literal) => {
        include_bytes!(concat!(env!("OUT_DIR"), "/", $file))
    };
}

macro_rules! filter_len {
    ($file:literal) => {
        generated_filter_bytes!($file).len() / size_of::<libc::sock_filter>()
    };
}

macro_rules! include_filter {
    ($file:literal) => {{
        const BYTES: &[u8; generated_filter_bytes!($file).len()] = generated_filter_bytes!($file);
        const LEN: usize = filter_len!($file);
        const { assert!(BYTES.len() % size_of::<libc::sock_filter>() == 0) };

        unsafe { std::mem::transmute::<[u8; BYTES.len()], [libc::sock_filter; LEN]>(*BYTES) }
    }};
}

const _: () = assert!(size_of::<libc::sock_filter>() == 8);

type SeccompFilter<const LEN: usize> = [libc::sock_filter; LEN];

#[allow(dead_code)]
pub const X86_64_BOOTSTRAP: SeccompFilter<{ filter_len!("x86_64_bootstrap.bpf") }> =
    include_filter!("x86_64_bootstrap.bpf");

pub const X86_64_FINAL: SeccompFilter<{ filter_len!("x86_64_final.bpf") }> =
    include_filter!("x86_64_final.bpf");
