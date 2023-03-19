extern crate libloading;

use libloading::{Library, Symbol};
use libc::{c_int, size_t};

type LLVMFuzzerTestOneInputFn = extern "C" fn(data: *const u8, size: size_t) -> c_int;

// #[no_mangle]
// pub extern "C" fn log_func32(br_id: u32, old_cond: bool, arg1: u32, arg2: u32,
//                             is_signed: u8, cond_type: u8) -> bool {
//     println!("br_id: {}, old_cond: {}, arg1: {}, arg2: {}, is_signed: {}, cond_type: {}",
//                                 br_id, old_cond, arg1, arg2, is_signed, cond_type);
//     old_cond
// }



/*
    The code is broken, we need to define functions for log_func32
    otherwise the runtime cannot resolve the symbol
 */

fn main() {
    
    // Load the shared library
    let lib = Library::new("./harness/harness.so").unwrap();

    // Get a reference to the LLVMFuzzerTestOneInput function.
    let fuzzer_test_one_input: Symbol<LLVMFuzzerTestOneInputFn> = unsafe {
        lib.get(b"LLVMFuzzerTestOneInput\0")
            .unwrap()
    };
    
    // Call the LLVMFuzzerTestOneInput function with some data.
    let data = b"input data";
    let result = fuzzer_test_one_input(data.as_ptr(), data.len());

    println!("LLVMFuzzerTestOneInput returned: {}", result);
}