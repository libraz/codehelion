#![no_std]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

trait Duplicate: Copy {
    fn transform(value: Self) -> Self;
}

impl Duplicate for u32 {
    fn transform(value: Self) -> Self {
        value.wrapping_mul(3).wrapping_add(11)
    }
}

#[inline(never)]
fn duplicate_template<T: Duplicate>(value: T) -> T {
    T::transform(value)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn duplicate_left(value: u32) -> u32 {
    let mut value = duplicate_template(value);
    value = value.wrapping_add(1);
    value = value.rotate_left(3);
    value = value.wrapping_mul(5);
    value = value.wrapping_add(7);
    value = value.rotate_left(5);
    value = value.wrapping_mul(11);
    value = value.wrapping_add(13);
    value = value.rotate_left(7);
    value = value.wrapping_mul(17);
    value = value.wrapping_add(19);
    value = value.rotate_left(11);
    value = value.wrapping_mul(23);
    value = value.wrapping_add(29);
    value = value.rotate_left(13);
    value
}

#[unsafe(no_mangle)]
pub static DUPLICATE_DATA_LEFT: [u8; 16] = *b"artifact-data-v1";

#[unsafe(no_mangle)]
pub static DUPLICATE_DATA_RIGHT: [u8; 16] = *b"artifact-data-v1";
