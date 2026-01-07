use lwe::lwe::{Params, decrypt, encrypt, keygen};

fn main() {
    println!("LWE Encryption Learning Exercise");
    println!("================================\n");

    let params = Params::toy();
    println!(
        "Using toy parameters: n={}, m={}, q={}",
        params.n, params.m, params.q
    );

    let (pk, sk) = keygen(params);

    println!("\nTesting encryption/decryption:");
    for &bit in &[0u8, 1u8, 1u8, 0u8] {
        let ct = encrypt(&pk, bit);
        let dec = decrypt(&sk, &ct);
        println!(
            "  bit={} -> encrypted -> decrypted={} {}",
            bit,
            dec,
            if bit == dec { "✓" } else { "✗" }
        );
    }
}
