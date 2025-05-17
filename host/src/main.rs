use anyhow::Result;
use byteorder::{BigEndian, ByteOrder};
use data_encoding::BASE32_NOPAD;
use hex_literal::hex;
use hmac::{Hmac, Mac};
use methods::{OTP_ELF, OTP_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use std::time::Instant;
use tracing_subscriber::filter::EnvFilter;

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct Journal {
    hashed_secret: [u8; 32],
    action_hash: [u8; 32],
    tx_nonce: u32,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    type HmacSha1 = Hmac<Sha1>;

    const SECRET_B32: &str = "HNKHWJTBOISS65S6IM2D6UDYNEZCCZLZI5TEWRJJGBJUE33IEVXQ";
    const EXPECTED_OTP: u32 = 400_613;
    const TIME_STEP: u64 = 0;
    const ACTION_HASH_BYTES: [u8; 32] =
        hex!("9f68041ff3c6f6acf9bd1980ec97e83265fb6cfcfb8b3a5d8d4baabd4b4c418e");
    const TX_NONCE: u32 = 7;

    let secret_bytes: [u8; 32] = BASE32_NOPAD
        .decode(SECRET_B32.as_bytes())
        .expect("valid base32")
        .try_into()
        .expect("valid base32 length");

    let hashed_secret: [u8; 32] = Sha256::digest(secret_bytes).into();

    let mut counter = [0u8; 8];
    BigEndian::write_u64(&mut counter, TIME_STEP);

    let mut mac = HmacSha1::new_from_slice(&secret_bytes).unwrap();
    mac.update(&counter);
    let hmac = mac.finalize().into_bytes();
    let hmac_array: [u8; 20] = hmac.as_slice().try_into().unwrap();

    let env = ExecutorEnv::builder()
        .write(&hmac_array)?
        .write(&hashed_secret)?
        .write(&EXPECTED_OTP)?
        .write(&ACTION_HASH_BYTES)?
        .write(&TX_NONCE)?
        .build()?;

    let prover = default_prover();
    let mut start = Instant::now();
    let prove_info = prover.prove(env, OTP_ELF)?;
    let mut duration = start.elapsed();
    let receipt = prove_info.receipt;

    println!("Time taken to generate proof: {:?}", duration);

    let _: Journal = receipt.journal.decode()?;

    start = Instant::now();
    receipt.verify(OTP_ID)?;
    duration = start.elapsed();
    println!("Time taken to verify proof: {:?}", duration);
    Ok(())
}
