use anyhow::Result;
use data_encoding::BASE32_NOPAD;
use hex_literal::hex;
use methods::{OTP_ELF, OTP_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use tracing_subscriber::filter::EnvFilter;

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct Journal {
    hashed_secret: [u8; 32],
    hashed_otp: [u8; 32],
    time_step: u64,
    action_hash: [u8; 32],
    tx_nonce: u32,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    const SECRET_B32: &str = "HNKHWJTBOISS65S6IM2D6UDYNEZCCZLZI5TEWRJJGBJUE33IEVXQ";
    const EXPECTED_OTP: u32 = 400_613;
    const TIME_STEP: u64 = 0;
    const ACTION_HASH_BYTES: [u8; 32] =
        hex!("9f68041ff3c6f6acf9bd1980ec97e83265fb6cfcfb8b3a5d8d4baabd4b4c418e");
    const TX_NONCE: u32 = 7;

    let secret_bytes = BASE32_NOPAD
        .decode(SECRET_B32.as_bytes())
        .expect("valid base32");

    let env = ExecutorEnv::builder()
        .write(&secret_bytes)?
        .write(&EXPECTED_OTP)?
        .write(&TIME_STEP)?
        .write(&ACTION_HASH_BYTES)?
        .write(&TX_NONCE)?
        .build()?;

    let prover = default_prover();
    let prove_info = prover.prove(env, OTP_ELF)?;
    let receipt = prove_info.receipt;

    let _: Journal = receipt.journal.decode()?;

    receipt.verify(OTP_ID)?;
    Ok(())
}
