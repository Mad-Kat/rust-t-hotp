use t_hotp::wasm::new_totp;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn new_totp_returns_always_6_digits() {
    assert_eq!(new_totp("").unwrap().chars().count(), 6);
}

#[wasm_bindgen_test]
fn new_totp_returns_error_as_string() {
    assert_eq!(new_totp("===").unwrap_err(), "invalid length at 2");
}
