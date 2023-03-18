use libafl_targets::libfuzzer_test_one_input;

fn main() {
    let bytes: [u8; 1] = [b'a'];

    libfuzzer_test_one_input(&bytes);

    println!("Hello, world!");
}
