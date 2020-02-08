use data_encoding::BASE32_NOPAD;
use hmacsha1::hmac_sha1;
use std::time::SystemTime;

pub fn create_totp(key: &str) -> Result<u32, OtpError> {
    let now = SystemTime::now();
    let time_since_epoch = now.duration_since(SystemTime::UNIX_EPOCH)?;
    create_otp(key, (time_since_epoch.as_secs() as u64) / 30)
}

pub fn create_otp(key: &str, counter: u64) -> Result<u32, OtpError> {
    let bytes = BASE32_NOPAD.decode(key.as_bytes())?;
    let res = hmac_sha1(bytes.as_slice(), &counter.to_be_bytes());
    let offset = offset(&res);
    let truncated_hash = truncate_hash(&res, offset);
    Ok(truncated_hash % 1_000_000)
}

fn offset(hash: &[u8; 20]) -> usize {
    (hash[19] & 0xf) as usize
}

fn truncate_hash(hash: &[u8; 20], offset: usize) -> u32 {
    ((hash[offset] & 0x7F) as u32) << 24
        | (hash[offset + 1] as u32) << 16
        | (hash[offset + 2] as u32) << 8
        | hash[offset + 3] as u32
}

#[derive(Debug)]
pub enum OtpError {
    UnixEpochError(std::time::SystemTimeError),
    PrivateKeyError(data_encoding::DecodeError),
}

impl From<std::time::SystemTimeError> for OtpError {
    fn from(err: std::time::SystemTimeError) -> OtpError {
        OtpError::UnixEpochError(err)
    }
}

impl From<data_encoding::DecodeError> for OtpError {
    fn from(err: data_encoding::DecodeError) -> OtpError {
        OtpError::PrivateKeyError(err)
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn when_truncate_hash_get_called_with_offset_should_return_hash_from_offset_to_offset_plus_4() {
        let hash = [0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let offset = 3;
        assert_eq!(16909060, truncate_hash(&hash, offset));
    }

    #[test]
    fn when_truncate_hash_get_called_with_upper_bound_offset_should_return_hash_from_offset_to_offset_plus_4(
    ) {
        let hash = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 255, 30, 10, 0,
        ];
        let offset = 15;
        assert_eq!(234823178, truncate_hash(&hash, offset));
    }

    #[test]
    fn when_truncate_hash_get_called_with_lower_bound_offset_should_return_hash_from_offset_to_offset_plus_4(
    ) {
        let hash = [32, 16, 8, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let offset = 0;
        assert_eq!(537921540, truncate_hash(&hash, offset));
    }

    #[test]
    pub fn when_offset_get_called_with_small_number_in_last_hash_entry_should_return_whole_number()
    {
        let hash = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10];

        assert_eq!(10, offset(&hash));
    }

    #[test]
    pub fn when_offset_get_called_with_large_number_in_last_hash_entry_should_return_truncated_number(
    ) {
        let hash = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17];

        assert_eq!(1, offset(&hash));
    }

    #[test]
    fn rfc_6238_tests() {
        assert_eq!(
            create_otp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap(),
            83773
        );
        assert_eq!(
            create_otp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1111111109).unwrap(),
            510233
        );
        assert_eq!(
            create_otp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1111111111).unwrap(),
            73950
        );
        assert_eq!(
            create_otp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1234567890).unwrap(),
            965462
        );
        assert_eq!(
            create_otp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 2000000000).unwrap(),
            54266
        );
        assert_eq!(
            create_otp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 20000000000).unwrap(),
            468884
        );
    }
}
