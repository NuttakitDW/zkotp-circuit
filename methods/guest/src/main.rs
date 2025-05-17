#![no_std]
#![cfg_attr(not(test), no_main)]

extern crate alloc;

use alloc::{format, vec::Vec};
use byteorder::{BigEndian, ByteOrder};
use hmac::{Hmac, Mac};
use risc0_zkvm::guest::env;
use sha1::Sha1;
use sha2::{Digest as _, Sha256};

type HmacSha1 = Hmac<Sha1>;

fn verify_and_hash(secret: &[u8], otp_code: u32, time_step: u64) -> ([u8; 32], [u8; 32]) {
    let mut counter = [0u8; 8];
    BigEndian::write_u64(&mut counter, time_step);

    let mut mac = HmacSha1::new_from_slice(secret).unwrap();
    mac.update(&counter);
    let hmac = mac.finalize().into_bytes();

    let o = (hmac[19] & 0x0f) as usize;
    let bin = ((hmac[o] as u32 & 0x7f) << 24)
        | (hmac[o + 1] as u32) << 16
        | (hmac[o + 2] as u32) << 8
        | (hmac[o + 3] as u32);
    assert_eq!(bin % 1_000_000, otp_code, "OTP mismatch");

    let mut otp_buf = [0u8; 32];
    otp_buf[..4].copy_from_slice(&otp_code.to_be_bytes());

    let hashed_secret: [u8; 32] = Sha256::digest(secret).into();
    let hashed_otp: [u8; 32] = Sha256::digest(&otp_buf).into();

    (hashed_secret, hashed_otp)
}

#[cfg(not(test))]
risc0_zkvm::guest::entry!(main);

fn main() {
    let secret_bytes: Vec<u8> = env::read();
    let otp_code: u32 = env::read();
    let time_step: u64 = env::read();
    let action_hash: [u8; 32] = env::read();
    let tx_nonce: u32 = env::read();

    let (hashed_secret, hashed_otp) = verify_and_hash(&secret_bytes, otp_code, time_step);

    env::commit(&hashed_secret);
    env::commit(&hashed_otp);
    env::commit(&time_step);
    env::commit(&action_hash);
    env::commit(&tx_nonce);
}

/*──────────────────────────  UNIT TESTS  ──────────────────────────*/

#[cfg(test)]
mod tests {
    extern crate std;

    use super::verify_and_hash;
    use data_encoding::BASE32_NOPAD;
    use hex_literal::hex;

    const SECRET_B32: &str = "HNKHWJTBOISS65S6IM2D6UDYNEZCCZLZI5TEWRJJGBJUE33IEVXQ";

    const TIME_STEP: u64 = 0;
    const EXPECTED_OTP: u32 = 400_613;

    const EXPECTED_HASHED_SECRET: [u8; 32] =
        hex!("d89a1013230800f8f24a86ab4071be65dd90c524dcc3b1010c9c00dc9dd81ec6");

    const EXPECTED_HASHED_OTP: [u8; 32] =
        hex!("a07c8cafc9569202524e0f21317c0cb92e129f19c77392b1adb4ec6e42e3d512");

    #[test]
    fn verify_and_hash_matches_reference() {
        let secret_bytes = BASE32_NOPAD
            .decode(SECRET_B32.as_bytes())
            .expect("valid base32");

        let (hashed_secret, hashed_otp) = verify_and_hash(&secret_bytes, EXPECTED_OTP, TIME_STEP);

        assert_eq!(
            hashed_secret, EXPECTED_HASHED_SECRET,
            "secret hash mismatch"
        );
        assert_eq!(hashed_otp, EXPECTED_HASHED_OTP, "OTP hash mismatch");
    }
}
