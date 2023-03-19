// build.rs

use std::process::Command;


fn main() {

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

}
