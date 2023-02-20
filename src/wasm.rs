use js_sys::Date;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn new_totp(key: &str) -> Result<String, String> {
    match crate::create_otp(key, Date::now() as u64 / 30).map(|x| {
        let mut s = x.to_string();
        while s.len() < 6 {
            s = format!("0{}", s);
        }
        s
    }) {
        Ok(x) => Ok(x),
        Err(e) => Err(e.as_str()),
    }
}

impl crate::OtpError {
    fn as_str(&self) -> String {
        match self {
            crate::OtpError::UnixEpochError(err) => err.to_string(),
            crate::OtpError::PrivateKeyError(err) => err.to_string(),
        }
    }
}
