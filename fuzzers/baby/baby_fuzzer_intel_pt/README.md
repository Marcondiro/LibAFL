# Baby fuzzer

This is a minimalistic example about how to create a libafl based fuzzer with Intel PT tracing.

It runs on a single core until a crash occurs and then exits.

The tested program is a simple Rust function without any instrumentation.

After building this example with `cargo build --release`, you need to give to the executable the necessary capabilities 
with `sudo setcap cap_ipc_lock,cap_sys_ptrace,cap_sys_admin,cap_syslog=ep ./target/release/baby_fuzzer_intel_pt`.

You can run this example using `cargo run --release`, and you can enable the TUI feature by running
`cargo run --release --features tui`.

This fuzzer is compatible with Linux hosts only having an Intel PT compatible CPU.