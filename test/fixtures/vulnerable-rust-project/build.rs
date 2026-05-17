use std::process::Command;

fn main() {
    let _ = Command::new("cc").arg("native.c").status();
}
