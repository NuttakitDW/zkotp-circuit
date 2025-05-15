#![no_std]
#![no_main]

use byteorder::{BigEndian, ByteOrder};
use hmac::{Hmac, Mac};
use risc0_zkvm::guest::env;
use sha1::Sha1;
use sha2::{Digest as _, Sha256};

type HmacSha1 = Hmac<Sha1>;

risc0_zkvm::guest::entry!(main);

fn main() {
    let secret: [u8; 20] = env::read();
    let otp_code: u32 = env::read();
    let time_step: u64 = env::read();
    let action_hash: [u8; 32] = env::read();
    let tx_nonce: u32 = env::read();

    let mut counter = [0u8; 8];
    BigEndian::write_u64(&mut counter, time_step);

    let mut mac = HmacSha1::new_from_slice(&secret).unwrap();
    mac.update(&counter);
    let hmac = mac.finalize().into_bytes();

    let o = (hmac[19] & 0x0f) as usize;
    let bin = ((hmac[o] as u32 & 0x7f) << 24)
        | (hmac[o + 1] as u32) << 16
        | (hmac[o + 2] as u32) << 8
        | (hmac[o + 3] as u32);
    assert_eq!(bin % 1_000_000, otp_code);

    let mut otp_buf = [0u8; 32];
    otp_buf[..4].copy_from_slice(&otp_code.to_be_bytes());

    let hashed_secret: [u8; 32] = Sha256::digest(&secret).into();
    let hashed_otp: [u8; 32] = Sha256::digest(&otp_buf).into();

    env::commit(&hashed_secret);
    env::commit(&hashed_otp);
    env::commit(&time_step);
    env::commit(&action_hash);
    env::commit(&tx_nonce);
}
