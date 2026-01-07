//! Ring Learning With Errors (Ring-LWE) encryption - implement step by step!
//!
//! Ring-LWE is a variant of LWE that works over polynomial rings, making it
//! more efficient and enabling homomorphic operations.
//!
//! Key difference: Instead of vectors/matrices, we work with polynomials
//! in the ring R_q = Z_q[x] / (x^n + 1)

use rand::Rng;

// ============================================================================
// Data Structures
// ============================================================================

/// Polynomial represented as a vector of coefficients.
/// poly[0] is the constant term, poly[i] is the coefficient of x^i.
pub type Polynomial = Vec<i64>;

#[derive(Clone, Copy, Debug)]
pub struct RingParams {
    /// Polynomial degree (must be a power of 2, e.g., 8, 16, 32)
    pub n: usize,
    /// Modulus for coefficients
    pub q: i64,
}

impl RingParams {
    pub fn toy() -> Self {
        // Small parameters for learning
        Self { n: 8, q: 97 }
    }
}

#[derive(Clone, Debug)]
pub struct PublicKey {
    pub params: RingParams,
    /// Polynomial a(x) in R_q
    pub a: Polynomial,
    /// Polynomial b(x) = a(x)*s(x) + e(x) in R_q
    pub b: Polynomial,
}

#[derive(Clone, Debug)]
pub struct SecretKey {
    pub params: RingParams,
    /// Secret polynomial s(x) in R_q
    pub s: Polynomial,
}

#[derive(Clone, Debug)]
pub struct Ciphertext {
    /// Polynomial u(x) in R_q
    pub u: Polynomial,
    /// Polynomial v(x) in R_q
    pub v: Polynomial,
}

// ============================================================================
// Core Functions (TODO: implement these!)
// ============================================================================

/// Generate a public/secret key pair.
///
/// Steps:
/// 1. Sample a random polynomial a(x) in R_q (coefficients in [0, q))
/// 2. Sample a random secret polynomial s(x) in R_q
/// 3. Sample a small noise polynomial e(x) (coefficients in {-1, 0, 1})
/// 4. Compute b(x) = a(x) * s(x) + e(x) in R_q
///    (Remember: polynomial multiplication mod (x^n + 1))
/// 5. Return (PublicKey {a, b}, SecretKey {s})
pub fn keygen(params: RingParams) -> (PublicKey, SecretKey) {
    // a(x)
    let a_x = sample_uniform_poly(params.n, params.q, &mut rand::thread_rng());
    // s(x)
    let s_x = sample_uniform_poly(params.n, params.q, &mut rand::thread_rng());
    // e(x)
    let e_x = sample_noise_poly(params.n, &mut rand::thread_rng());
    // a(x) * s(x)
    let a_x_mul_s_x = poly_mul_ring(&a_x, &s_x, params.n, params.q);
    // b(x) = a(x) * s(x) + e(x) (mod q)
    let b_x = poly_mod_q(&poly_add(&a_x_mul_s_x, &e_x), params.q);

    let pk = PublicKey {
        params: params,
        a: a_x,
        b: b_x,
    };
    let sk = SecretKey {
        params: params,
        s: s_x,
    };
    (pk, sk)
}

/// Encrypt a single bit (0 or 1).
///
/// Steps:
/// 1. Sample a random binary polynomial r(x) (coefficients in {0, 1})
/// 2. Compute u(x) = r(x) * a(x) in R_q
/// 3. Compute v(x) = r(x) * b(x) + bit * (q/2) in R_q
///    (The bit encoding: multiply each coefficient by bit, then add q/2 to each if bit=1)
/// 4. Return Ciphertext {u, v}
pub fn encrypt(pk: &PublicKey, bit: u8) -> Ciphertext {
    assert!(bit == 0 || bit == 1, "bit must be 0 or 1");

    // u_x = r(x) * a(x)
    let r_x = sample_binary_poly(pk.params.n, &mut rand::thread_rng());
    let u_x = poly_mul_ring(&r_x, &pk.a, pk.params.n, pk.params.q);

    // v_x = r(x) * b(x) + bit * (q/2)
    // r(x) * b(x)
    let r_x_mul_b_x = poly_mul_ring(&r_x, &pk.b, pk.params.n, pk.params.q);
    // bit * (q/2)
    let bit_mul_q_over_2 = constant_poly(pk.params.n, (bit as i64) * pk.params.q / 2);
    // r(x) * b(x) + bit * (q/2)
    let r_x_mul_b_x_plus_bit_mul_q_over_2 = poly_add(&r_x_mul_b_x, &bit_mul_q_over_2);
    let v_x = poly_mod_q(&r_x_mul_b_x_plus_bit_mul_q_over_2, pk.params.q);

    Ciphertext { u: u_x, v: v_x }
}

/// Decrypt a ciphertext to recover the bit.
///
/// Steps:
/// 1. Compute x(x) = v(x) - u(x) * s(x) in R_q
/// 2. Look at the constant term (x[0]) - this should be close to 0 or q/2
/// 3. If x[0] is in [q/4, 3q/4), return 1; otherwise return 0
pub fn decrypt(sk: &SecretKey, ct: &Ciphertext) -> u8 {
    // x_x = v(x) - u(x) * s(x) (mod q)
    let u_x_mul_s_x = poly_mul_ring(&ct.u, &sk.s, sk.params.n, sk.params.q);
    let x_x = poly_mod_q(&poly_sub(&ct.v, &u_x_mul_s_x), sk.params.q);

    let const_term = x_x[0];

    let upper_bound = 3 * sk.params.q / 4;
    let lower_bound = sk.params.q / 4;

    if const_term >= lower_bound && const_term < upper_bound {
        1
    } else {
        0
    }
}

// ============================================================================
// Helper Functions (already implemented for you)
// ============================================================================

/// Modular arithmetic: reduce x mod q to [0, q)
pub fn mod_q(x: i64, q: i64) -> i64 {
    let r = x % q;
    if r < 0 { r + q } else { r }
}

/// Reduce all coefficients of a polynomial mod q
pub fn poly_mod_q(poly: &Polynomial, q: i64) -> Polynomial {
    poly.iter().map(|&c| mod_q(c, q)).collect()
}

/// Add two polynomials: result = a(x) + b(x)
pub fn poly_add(a: &Polynomial, b: &Polynomial) -> Polynomial {
    let max_len = a.len().max(b.len());
    let mut result = vec![0i64; max_len];
    for i in 0..a.len() {
        result[i] += a[i];
    }
    for i in 0..b.len() {
        result[i] += b[i];
    }
    result
}

// Subtract two polynomials: result = a(x) - b(x)
pub fn poly_sub(a: &Polynomial, b: &Polynomial) -> Polynomial {
    let max_len = a.len().max(b.len());
    let mut result = vec![0i64; max_len];
    for i in 0..a.len() {
        result[i] += a[i];
    }
    for i in 0..b.len() {
        result[i] -= b[i];
    }
    result
}

/// Multiply two polynomials in the ring R_q = Z_q[x] / (x^n + 1)
/// This is the key operation! The ring structure means:
/// - x^n ≡ -1 (mod x^n + 1)
/// - So we can reduce higher-degree terms using this relation
pub fn poly_mul_ring(a: &Polynomial, b: &Polynomial, n: usize, q: i64) -> Polynomial {
    // Standard polynomial multiplication, then reduce mod (x^n + 1)
    let mut result = vec![0i64; 2 * n - 1];

    // Multiply polynomials
    for i in 0..a.len() {
        for j in 0..b.len() {
            result[i + j] += a[i] * b[j];
        }
    }

    // Reduce mod (x^n + 1): for terms x^k where k >= n, use x^k = -x^(k-n)
    let mut reduced = vec![0i64; n];
    for i in 0..result.len() {
        if i < n {
            reduced[i] = result[i];
        } else {
            // x^i = -x^(i-n) mod (x^n + 1)
            let idx = i - n;
            reduced[idx] -= result[i];
        }
    }

    // Reduce coefficients mod q
    poly_mod_q(&reduced, q)
}

/// Sample a random polynomial with coefficients uniformly in [0, q)
pub fn sample_uniform_poly<R: Rng + ?Sized>(n: usize, q: i64, rng: &mut R) -> Polynomial {
    (0..n).map(|_| rng.gen_range(0..q)).collect()
}

/// Sample a small noise polynomial with coefficients in {-1, 0, 1}
pub fn sample_noise_poly<R: Rng + ?Sized>(n: usize, rng: &mut R) -> Polynomial {
    (0..n)
        .map(|_| match rng.gen_range(0..3) {
            0 => -1,
            1 => 0,
            _ => 1,
        })
        .collect()
}

/// Sample a random binary polynomial with coefficients in {0, 1}
pub fn sample_binary_poly<R: Rng + ?Sized>(n: usize, rng: &mut R) -> Polynomial {
    (0..n)
        .map(|_| if rng.gen_bool(0.5) { 1 } else { 0 })
        .collect()
}

/// Create a constant polynomial (all coefficients are the same value)
pub fn constant_poly(n: usize, value: i64) -> Polynomial {
    let mut poly = vec![0i64; n];
    poly[0] = value; // Only constant term is non-zero
    poly
}

// ============================================================================
// Tests (uncomment and fix once you implement the functions)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_poly_mul_ring() {
        // Test that polynomial multiplication works correctly in the ring
        let params = RingParams::toy();
        let a = vec![1, 2, 3, 0, 0, 0, 0, 0]; // 1 + 2x + 3x^2
        let b = vec![2, 1, 0, 0, 0, 0, 0, 0]; // 2 + x

        let result = poly_mul_ring(&a, &b, params.n, params.q);
        // (1+2x+3x^2) * (2+x) = 2 + 5x + 8x^2 + 3x^3
        // In ring mod (x^8 + 1), we don't need to reduce for low degrees
        assert_eq!(result[0], 2);
        assert_eq!(result[1], 5);
        assert_eq!(result[2], 8);
        assert_eq!(result[3], 3);
    }

    #[test]
    fn test_keygen() {
        let params = RingParams::toy();
        let (pk, sk) = keygen(params);

        // Check dimensions
        assert_eq!(pk.a.len(), params.n);
        assert_eq!(pk.b.len(), params.n);
        assert_eq!(sk.s.len(), params.n);
    }

    #[test]
    fn test_roundtrip() {
        let params = RingParams::toy();
        let (pk, sk) = keygen(params);

        // Test encrypting and decrypting bits
        for bit in [0u8, 1u8] {
            let ct = encrypt(&pk, bit);
            let dec = decrypt(&sk, &ct);
            assert_eq!(bit, dec, "Failed to roundtrip bit {}", bit);
        }
    }
}
