pub fn valid_reason(ptr: *const u8) -> u8 {
    // rustsec-auditor: ignore RSA-UNSAFE-BLOCK -- legacy FFI wrapper reviewed in host project
    unsafe { *ptr }
}

pub fn missing_reason(ptr: *const u8) -> u8 {
    // rustsec-auditor: ignore RSA-UNSAFE-BLOCK
    unsafe { *ptr }
}

pub fn valid_owner(ptr: *const u8) -> u8 {
    // rustsec-auditor: ignore RSA-UNSAFE-BLOCK owner=@security -- reviewed wrapper owned by platform security
    unsafe { *ptr }
}

pub fn valid_ticket(ptr: *const u8) -> u8 {
    // rustsec-auditor: ignore RSA-UNSAFE-BLOCK ticket=SEC-123 -- tracked accepted risk for compatibility
    unsafe { *ptr }
}

pub fn valid_future_until(ptr: *const u8) -> u8 {
    // rustsec-auditor: ignore RSA-UNSAFE-BLOCK until=2999-12-31 -- temporary accepted risk until migration lands
    unsafe { *ptr }
}

pub fn expired_until(ptr: *const u8) -> u8 {
    // rustsec-auditor: ignore RSA-UNSAFE-BLOCK until=2000-01-01 -- temporary risk acceptance expired
    unsafe { *ptr }
}
