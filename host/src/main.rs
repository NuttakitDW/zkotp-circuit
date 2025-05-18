use anyhow::{Context, Result};
use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use byteorder::{BigEndian, ByteOrder};
use data_encoding::BASE32_NOPAD;
use base64;
use bincode;
use hmac::{Hmac, Mac};
use methods::{OTP_ELF, OTP_ID};
use rand::Rng;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use tracing_subscriber::filter::EnvFilter;

#[derive(Debug, serde::Deserialize)]
struct ProofRequest {
    secret: String,
    otp_code: u32,
    action_message: String,
}

#[derive(Debug, serde::Serialize)]
struct ProofResponse {
    valid: bool,
    tx_nonce: Option<u32>,
    proof: Option<String>,
    error: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct VerifyRequest {
    proof: String,
}

#[derive(Debug, serde::Serialize)]
struct VerifyResponse {
    valid: bool,
    error: Option<String>,
}

#[actix_web::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    HttpServer::new(|| {
        App::new()
            .service(prove_handler)
            .service(verify_handler)
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await?;
    Ok(())
}

#[post("/prove")]
async fn prove_handler(req: web::Json<ProofRequest>) -> impl Responder {
    match generate_proof(req.into_inner()).await {
        Ok((receipt, tx_nonce)) => {
            let proof_bytes = bincode::serialize(&receipt).unwrap();
            let proof = base64::encode(proof_bytes);
            HttpResponse::Ok().json(ProofResponse {
                valid: true,
                tx_nonce: Some(tx_nonce),
                proof: Some(proof),
                error: None,
            })
        }
        Err(e) => HttpResponse::Ok().json(ProofResponse {
            valid: false,
            tx_nonce: None,
            proof: None,
            error: Some(format!("{e}")),
        }),
    }
}

#[post("/verify")]
async fn verify_handler(req: web::Json<VerifyRequest>) -> impl Responder {
    match verify_proof(req.into_inner()) {
        Ok(()) => HttpResponse::Ok().json(VerifyResponse { valid: true, error: None }),
        Err(e) => HttpResponse::Ok().json(VerifyResponse { valid: false, error: Some(format!("{e}")) }),
    }
}

async fn generate_proof(req: ProofRequest) -> Result<(Receipt, u32)> {
    type HmacSha1 = Hmac<Sha1>;

    let secret_bytes_vec = BASE32_NOPAD
        .decode(req.secret.as_bytes())
        .context("invalid secret encoding")?;
    let secret_bytes: [u8; 32] = secret_bytes_vec
        .as_slice()
        .try_into()
        .context("secret must be 32 bytes")?;

    let hashed_secret: [u8; 32] = Sha256::digest(secret_bytes).into();

    let mut counter = [0u8; 8];
    BigEndian::write_u64(&mut counter, 0);
    let mut mac = HmacSha1::new_from_slice(&secret_bytes).unwrap();
    mac.update(&counter);
    let hmac = mac.finalize().into_bytes();
    let hmac_array: [u8; 20] = hmac.as_slice().try_into().unwrap();

    let action_hash: [u8; 32] = Sha256::digest(req.action_message.as_bytes()).into();

    let tx_nonce: u32 = rand::thread_rng().gen();

    let env = ExecutorEnv::builder()
        .write(&hmac_array)?
        .write(&hashed_secret)?
        .write(&req.otp_code)?
        .write(&action_hash)?
        .write(&tx_nonce)?
        .build()?;

    let prover = default_prover();
    let prove_info = prover.prove(env, OTP_ELF)?;
    let receipt = prove_info.receipt;

    receipt.verify(OTP_ID)?;
    Ok((receipt, tx_nonce))
}

fn verify_proof(req: VerifyRequest) -> Result<()> {
    let bytes = base64::decode(req.proof).context("invalid base64 proof")?;
    let receipt: Receipt = bincode::deserialize(&bytes).context("invalid receipt data")?;
    receipt.verify(OTP_ID)?;
    Ok(())
}
