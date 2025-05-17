#![no_std]
#![cfg_attr(not(test), no_main)]

extern crate alloc;

use risc0_zkvm::guest::env;
use sha2::{Digest as _, Sha256};

fn verify_otp(hmac: [u8; 20], otp_code: u32) {
    let o = (hmac[19] & 0x0f) as usize;
    let bin = ((hmac[o] as u32 & 0x7f) << 24)
        | (hmac[o + 1] as u32) << 16
        | (hmac[o + 2] as u32) << 8
        | (hmac[o + 3] as u32);

    assert_eq!(bin % 1_000_000, otp_code, "OTP mismatch");
}

#[cfg(not(test))]
risc0_zkvm::guest::entry!(main);

fn main() {
    let hmac: [u8; 20] = env::read();
    let secret_bytes: [u8; 32] = env::read();
    let otp_code: u32 = env::read();
    let action_hash: [u8; 32] = env::read();
    let tx_nonce: u32 = env::read();

    let hashed_secret: [u8; 32] = Sha256::digest(secret_bytes).into();

    verify_otp(hmac, otp_code);

    env::commit(&hashed_secret);
    env::commit(&action_hash);
    env::commit(&tx_nonce);
}

/*──────────────────────────  UNIT TESTS  ──────────────────────────*/

#[cfg(test)]
mod tests {
    extern crate std;

    use super::verify_otp;
    use byteorder::{BigEndian, ByteOrder};
    use data_encoding::BASE32_NOPAD;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    const SECRET_B32: &str = "HNKHWJTBOISS65S6IM2D6UDYNEZCCZLZI5TEWRJJGBJUE33IEVXQ";

    const TIME_STEP: u64 = 0;
    const EXPECTED_OTP: u32 = 400_613;

    type HmacSha1 = Hmac<Sha1>;

    #[test]
    fn verify_and_hash_matches_reference() {
        let secret_bytes: [u8; 32];
        secret_bytes = BASE32_NOPAD
            .decode(SECRET_B32.as_bytes())
            .expect("valid base32")
            .try_into()
            .expect("valid base32 length");

        let mut counter = [0u8; 8];
        BigEndian::write_u64(&mut counter, TIME_STEP);

        let mut mac = HmacSha1::new_from_slice(&secret_bytes).unwrap();
        mac.update(&counter);
        let hmac = mac.finalize().into_bytes();
        let hmac_array: [u8; 20] = hmac.as_slice().try_into().unwrap();

        verify_otp(hmac_array, EXPECTED_OTP);
    }
}
