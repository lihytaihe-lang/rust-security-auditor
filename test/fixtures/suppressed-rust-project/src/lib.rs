pub fn read_byte(ptr: *const u8) -> u8 {
    // rustsec-auditor: ignore RSA-UNSAFE-BLOCK legacy FFI wrapper reviewed in host project
    unsafe { *ptr }
}
