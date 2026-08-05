#[cfg(not(target_arch = "x86_64"))]
compile_error!("seccomp filters currently support only x86_64");

use std::mem::size_of;

macro_rules! include_filter {
    ($file:literal) => {{
        const BYTES: &[u8; include_bytes!(concat!(env!("OUT_DIR"), "/", $file)).len()] =
            include_bytes!(concat!(env!("OUT_DIR"), "/", $file));
        const LEN: usize = BYTES.len() / size_of::<libc::sock_filter>();
        const { assert!(BYTES.len() % size_of::<libc::sock_filter>() == 0) };

        unsafe { std::mem::transmute::<[u8; BYTES.len()], [libc::sock_filter; LEN]>(*BYTES) }
    }};
}

const _: () = assert!(size_of::<libc::sock_filter>() == 8);

#[allow(dead_code)]
pub const X86_64_BOOTSTRAP: [libc::sock_filter;
    include_bytes!(concat!(env!("OUT_DIR"), "/x86_64_bootstrap.bpf")).len()
        / size_of::<libc::sock_filter>()] = include_filter!("x86_64_bootstrap.bpf");

pub const X86_64_FINAL: [libc::sock_filter;
    include_bytes!(concat!(env!("OUT_DIR"), "/x86_64_final.bpf")).len()
        / size_of::<libc::sock_filter>()] = include_filter!("x86_64_final.bpf");
