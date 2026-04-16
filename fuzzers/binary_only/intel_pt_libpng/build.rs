use std::{
    env,
    path::{Path, PathBuf},
};

fn main() {
    println!("cargo:rustc-link-lib=z");

    let libpng_dst = cmake::build("./third_party/libpng");

    // Tell cargo to look for shared libraries in the specified directory
    println!("cargo:rustc-link-search=native={}", libpng_dst.display());
    println!("cargo:rustc-link-lib=static=png");

    println!("cargo:rerun-if-changed=libpng_read_fuzzer.cc");

    let abseil_path = Path::new("third_party").join("abseil-cpp");
    cc::Build::new()
        .cpp(true)
        .flag("-std=c++17")
        .file("libpng_read_fuzzer.cc")
        .include(&abseil_path)
        .compile("libpng_read_fuzzer");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
