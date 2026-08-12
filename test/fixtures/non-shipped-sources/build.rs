fn main() {
    let _ = std::process::Command::new("cc").arg("native.c").status();
}
