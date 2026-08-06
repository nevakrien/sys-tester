use std::env;
use std::error::Error;
use std::fs::File;
use std::path::Path;

use libseccomp::{ScmpAction, ScmpArch, ScmpFilterAttr, ScmpFilterContext, ScmpSyscall};

const MONITORED_SYSCALLS: &[&str] = &["open", "openat", "openat2", "read", "write", "close"];

const POLICIES: &[(&str, &[&str])] = &[
    (
        "x86_64_bootstrap.bpf",
        &["sendmsg", "seccomp", "exit", "exit_group"],
    ),
    ("x86_64_final.bpf", &["exit", "exit_group"]),
];

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-changed=build.rs");

    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64") {
        return Err("seccomp filters currently support only x86_64 targets".into());
    }

    let output_dir = env::var_os("OUT_DIR").ok_or("Cargo did not provide OUT_DIR")?;
    for &(file_name, allowed) in POLICIES {
        export_filter(&Path::new(&output_dir).join(file_name), allowed)?;
    }

    Ok(())
}

fn export_filter(path: &Path, allowed: &[&str]) -> Result<(), Box<dyn Error>> {
    let mut context = ScmpFilterContext::new(ScmpAction::KillProcess)?;
    context.set_filter_attr(ScmpFilterAttr::CtlOptimize, 2)?;

    for &name in MONITORED_SYSCALLS {
        context.add_rule_exact(ScmpAction::Notify, resolve(name)?)?;
    }
    for &name in allowed {
        context.add_rule_exact(ScmpAction::Allow, resolve(name)?)?;
    }

    let file = File::create(path)?;
    context.export_bpf(&file)?;
    if file.metadata()?.len() % 8 != 0 {
        return Err("libseccomp emitted a partial sock_filter instruction".into());
    }

    Ok(())
}

fn resolve(name: &str) -> Result<ScmpSyscall, Box<dyn Error>> {
    Ok(ScmpSyscall::from_name_by_arch(name, ScmpArch::X8664)?)
}
