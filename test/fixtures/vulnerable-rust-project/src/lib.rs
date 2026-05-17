pub unsafe fn read_byte(ptr: *const u8) -> u8 {
    unsafe { *ptr }
}

pub struct Shared(*mut u8);

unsafe impl Send for Shared {}
unsafe impl Sync for Shared {}

pub extern "C" fn exported(ptr: *const u8) -> usize {
    unsafe { std::slice::from_raw_parts(ptr, 4).len() }
}

pub fn transmute_it(value: u32) -> i32 {
    unsafe { std::mem::transmute(value) }
}

pub fn uninit_byte() -> u8 {
    let value = std::mem::MaybeUninit::<u8>::uninit();
    unsafe { value.assume_init() }
}

pub fn widen(values: &mut Vec<u8>) {
    unsafe { values.set_len(values.capacity()) }
}

pub unsafe fn take(ptr: *mut u8) -> Box<u8> {
    Box::from_raw(ptr)
}
