use libafl_targets::{
    libfuzzer_test_one_input
};

fn main() {

    let input = b"a";
    libfuzzer_test_one_input(input);

    println!("Hello");
}