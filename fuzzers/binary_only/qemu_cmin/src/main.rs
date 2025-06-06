//! A binary-only corpus minimizer using qemu, similar to AFL++ afl-cmin
#[cfg(target_os = "linux")]
mod fuzzer;

#[cfg(target_os = "linux")]
pub fn main() {
    fuzzer::fuzz().unwrap();
}

#[cfg(not(target_os = "linux"))]
pub fn main() {
    panic!("qemu-user and libafl_qemu is only supported on linux!");
}
