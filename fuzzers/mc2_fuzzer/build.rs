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

    //Save .bc in text format for switch splitting debugging
    // Command::new("clang-11")
    //     .current_dir("./harness")
    //     .arg("-Xclang")
    //     .arg("-load")
    //     .arg("-Xclang")
    //     .arg("build/skeleton/libSkeletonPass.so")
    //     .arg("harness.c")
    //     .arg("-emit-llvm")
    //     .arg("-S")
    //     .arg("-g3")
    //     .arg("-O0")
    //     .arg("-c")
    //     .arg("-o")
    //     .arg("harness.bc")
    //     .output()
    //     .expect("Failed to produce harness.bc");

    cc::Build::new()
        .flag("-Xclang")
        .flag("-load")
        .flag("-Xclang")
        .flag("harness/build/skeleton/libSkeletonPass.so")
        .file("./harness/harness.c")
        .flag("-g3")
        .flag("-O0")
        .compile("harness");

    println!("cargo:rerun-if-changed=harness/harness.c");
    println!("cargo:rerun-if-changed=harness/skeleton/skeleton.cpp");
}
