pub fn first_byte(bytes: &[u8]) -> Option<u8> {
    if bytes.is_empty() {
        return None;
    }

    // SAFETY: the slice is checked to be non-empty before dereferencing the pointer.
    let value = unsafe { *bytes.as_ptr() };
    Some(value)
}
