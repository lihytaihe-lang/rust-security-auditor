// Sample input, not reachable from any Cargo target.
pub fn stray(p: *const u8) -> u8 {
    unsafe { *p }
}
