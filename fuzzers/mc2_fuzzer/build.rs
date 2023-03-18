// build.rs

use std::env;

// clang-11 -c harness.c -g3 -O0 -o harness.o
// clang-11 -Xclang -load -Xclang build/skeleton/libSkeletonPass.so -g3 -O0 onebyte_test.c runtime_func.o -o onebyte_test -lm

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();

    println!("cargo:rerun-if-changed=harness.c");

    std::env::set_var("CC", "clang");
    std::env::set_var("CXX", "clang++");

    cc::Build::new()
        .flag("-g3")
        .flag("-O0")
        .file("harness.c")
        .compile("harness");

    println!("cargo:rustc-link-search=native={}", &out_dir);

    println!("cargo:rerun-if-changed=build.rs");
}