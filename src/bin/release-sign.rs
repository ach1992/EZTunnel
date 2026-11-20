//! Release operator utility, never part of a running tunnel or the dashboard.
//! Use only in the manual GitHub Actions release job. No signing seed is stored in Git.
use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::{Signer, SigningKey};
use std::{env, fs::OpenOptions, io::Write};

fn key() -> Result<SigningKey> {
    let secret = env::var("EZTUNNEL_RELEASE_KEY_HEX")
        .context("set EZTUNNEL_RELEASE_KEY_HEX from the GitHub Actions secret")?;
    let bytes: [u8; 32] = hex::decode(secret.trim())
        .context("release seed is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("release seed must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let signer = key()?;
    if args.as_slice() == ["--public-key"] {
        println!("{}", hex::encode(signer.verifying_key().to_bytes()));
        return Ok(());
    }
    if args.len() != 3 || args[0] != "--sign" {
        bail!("usage: release-sign --public-key | --sign <unsigned-program> <signed-program>");
    }
    let source = &args[1];
    let destination = &args[2];
    ensure!(source != destination, "sign into a separate output file");
    let mut bytes = std::fs::read(source).with_context(|| format!("read {source}"))?;
    ensure!(bytes.starts_with(b"\x7fELF"), "only Linux ELF program files can be signed");
    ensure!(bytes.len() < 256 * 1024 * 1024, "unexpectedly large program");
    ensure!(bytes.len() < 72 || &bytes[bytes.len()-72..bytes.len()-68] != b"EZT1", "program already has a release trailer");
    let signature = signer.sign(blake3::hash(&bytes).as_bytes());
    bytes.extend_from_slice(b"EZT1");
    bytes.push(1);
    bytes.extend_from_slice(&signature.to_bytes());
    bytes.extend_from_slice(&[0; 3]);
    // A build without the matching embedded public key must never publish this binary.
    ensure!(eztunnel::release::verify_bytes(&bytes) == eztunnel::release::Outcome::Verified,
            "the configured build public key does not match the release seed");
    let mut output = OpenOptions::new().write(true).create_new(true)
        .open(destination).with_context(|| format!("create {destination}"))?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    println!("Signed {destination} with release key ID 1");
    Ok(())
}
