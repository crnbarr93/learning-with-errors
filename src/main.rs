use lwe::lwe::{Params, decrypt, encrypt, keygen as lwe_keygen};
use lwe::ring_lwe::{
    RingParams, decrypt as rlwe_decrypt, encrypt as rlwe_encrypt, keygen as rlwe_keygen,
};

fn main() {
    println!("LWE vs Ring-LWE Comparison");
    println!("==========================\n");

    // LWE example
    println!("=== LWE Encryption ===");
    let lwe_params = Params::toy();
    println!(
        "Parameters: n={}, m={}, q={}",
        lwe_params.n, lwe_params.m, lwe_params.q
    );

    let (lwe_pk, lwe_sk) = lwe_keygen(lwe_params);
    println!("\nTesting LWE encryption/decryption:");
    for &bit in &[0u8, 1u8, 1u8, 0u8] {
        let ct = encrypt(&lwe_pk, bit);
        let dec = decrypt(&lwe_sk, &ct);
        println!(
            "  bit={} -> encrypted -> decrypted={} {}",
            bit,
            dec,
            if bit == dec { "✓" } else { "✗" }
        );
    }

    // Ring-LWE example
    println!("\n=== Ring-LWE Encryption ===");
    let rlwe_params = RingParams::toy();
    println!("Parameters: n={}, q={}", rlwe_params.n, rlwe_params.q);

    let (rlwe_pk, rlwe_sk) = rlwe_keygen(rlwe_params);
    println!("\nTesting Ring-LWE encryption/decryption:");
    for &bit in &[0u8, 1u8, 1u8, 0u8] {
        let ct = rlwe_encrypt(&rlwe_pk, bit);
        let dec = rlwe_decrypt(&rlwe_sk, &ct);
        println!(
            "  bit={} -> encrypted -> decrypted={} {}",
            bit,
            dec,
            if bit == dec { "✓" } else { "✗" }
        );
    }
}
