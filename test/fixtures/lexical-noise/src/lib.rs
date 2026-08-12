/*
  Historical note: this module used to contain unsafe { *ptr }.
  It also declared extern "C" bindings and a static mut COUNTER.
*/

/// Documentation example, not compiled by this scanner:
/// ```
/// let x = unsafe { std::mem::transmute::<u32, i32>(1) };
/// ```
pub fn documented() -> &'static str {
    "unsafe { transmute(x) } inside a string literal is not code"
}

pub fn raw_string_noise() -> &'static str {
    r#"static mut GLOBAL: u8 = 0; unsafe { GLOBAL += 1 }"#
}

pub fn char_literals_are_not_strings(input: char) -> bool {
    input == '"' || input == '\'' || input == '{'
}

pub fn real_unsafe(values: &[u8]) -> u8 {
    unsafe { *values.get_unchecked(0) }
}

#[cfg(test)]
mod tests {
    #[test]
    fn transmute_in_test_code() {
        let value = 1u32;
        let _converted: i32 = unsafe { std::mem::transmute(value) };
    }
}
