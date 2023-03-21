pub fn vec(size: usize) -> Vec<u8> {
    let mut random_buf = vec![0 as u8; size].into_boxed_slice();

    unsafe {
        sodium_sys::randombytes_buf(random_buf.as_mut_ptr() as *mut libc::c_void, size as u64);
    }

    return random_buf.to_vec();
}
