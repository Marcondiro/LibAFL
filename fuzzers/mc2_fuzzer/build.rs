// build.rs

use std::process::Command;

// clang-11 -Xclang -load -Xclang build/skeleton/libSkeletonPass.so -g3 -c -O0 harness.c -o harness.o

fn main() {
    std::env::set_var("CC", "clang-11");

    Command::new("make")
        .arg("clean")
        .current_dir("./harness")
        .status()
        .expect("failed to execute make clean");

    Command::new("make")
        .arg("build")
        .current_dir("./harness")
        .status()
        .expect("failed to execute make build");

    Command::new("clang-11")
        .current_dir("./harness")
        // .arg("-fexperimental-new-pass-manager")
        .arg("./split-switches-pass.so")
        .arg("harness.c")
        .arg("-emit-llvm")
        // .arg("-S")
        .arg("-g3")
        .arg("-O1")
        .arg("-funroll-loops")
        .arg("-c")
        .arg("-o")
        .arg("harness.bc")
        .output()
        .expect("Failed to process harness.bc with split-switches-pass.so");

    cc::Build::new()
        .flag("-Xclang")
        .flag("-load")
        .flag("-Xclang")
        .flag("harness/split-switches-pass.so")
        .flag("-Xclang")
        .flag("-load")
        .flag("-Xclang")
        .flag("harness/build/skeleton/libSkeletonPass.so")
        .file("./harness/harness.bc")
        // .file("./harness/harness.c")
        .flag("-g3")
        .flag("-O0")
        .compile("harness");

    println!("cargo:rerun-if-changed=harness/harness.c");
    println!("cargo:rerun-if-changed=harness/skeleton/Skeleton.cpp");
}
