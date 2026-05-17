use std::process::Command;

fn main() {
    let _ = Command::new("sh").arg("-c").arg("cc native.c").status();
}
