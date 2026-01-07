//! Learning With Errors (LWE) encryption - implement step by step!
//!
//! This is a scaffold to help you implement LWE encryption yourself.
//! Start with keygen, then encrypt, then decrypt.

use rand::Rng;

// ============================================================================
// Data Structures (already defined for you)
// ============================================================================

#[derive(Clone, Copy, Debug)]
pub struct Params {
    /// Secret dimension (length of secret key vector)
    pub n: usize,
    /// Number of LWE samples (rows of matrix A)
    pub m: usize,
    /// Modulus (all arithmetic is mod q)
    pub q: i64,
}

impl Params {
    pub fn toy() -> Self {
        // Small parameters for learning - q is odd, noise is small
        Self { n: 8, m: 16, q: 97 }
    }
}

#[derive(Clone, Debug)]
pub struct PublicKey {
    pub params: Params,
    /// Matrix A: m rows × n columns (each row is a vector)
    pub a: Vec<Vec<i64>>,
    /// Vector b: length m, where b = A*s + e (mod q)
    pub b: Vec<i64>,
}

#[derive(Clone, Debug)]
pub struct SecretKey {
    pub params: Params,
    /// Secret vector s: length n
    pub s: Vec<i64>,
}

#[derive(Clone, Debug)]
pub struct Ciphertext {
    /// Vector u: length n
    pub u: Vec<i64>,
    /// Scalar v
    pub v: i64,
}

// ============================================================================
// Core Functions (TODO: implement these!)
// ============================================================================

/// Generate a public/secret key pair.
///
/// Steps:
/// 1. Sample a random matrix A (m × n) with entries in [0, q)
/// 2. Sample a random secret vector s (length n) with entries in [0, q)
/// 3. Sample a small noise vector e (length m) - try values in {-1, 0, 1}
/// 4. Compute b = A*s + e (mod q)
/// 5. Return (PublicKey {a: A, b: b}, SecretKey {s: s})
pub fn keygen(params: Params) -> (PublicKey, SecretKey) {
    let a = sample_uniform_matrix(params.m, params.n, params.q, &mut rand::thread_rng());
    let s = sample_uniform_vec(params.n, params.q, &mut rand::thread_rng());
    let e = sample_noise_vec(params.m, &mut rand::thread_rng());

    // A*s
    let a_mul_s = matrix_vector_product(&a, &s);
    // A*s + e (mod q)
    let b = a_mul_s
        .iter()
        .enumerate()
        .map(|(i, x)| mod_q(*x + e[i], params.q))
        .collect();

    let pubkey = PublicKey { params, a, b };
    let secretkey = SecretKey { params, s };

    (pubkey, secretkey)
}

/// Encrypt a single bit (0 or 1).
///
/// Steps:
/// 1. Sample a random binary vector r (length m) with entries in {0, 1}
/// 2. Compute u = r^T * A (matrix-vector product, result is length n)
/// 3. Compute v = r^T * b + bit * (q/2) (mod q)
/// 4. Return Ciphertext {u, v}
pub fn encrypt(pk: &PublicKey, bit: u8) -> Ciphertext {
    assert!(bit == 0 || bit == 1, "bit must be 0 or 1");

    // u = r^T * A (row vector times matrix) mod q
    let r = sample_binary_vec(pk.params.m, &mut rand::thread_rng());
    let r_i64 = r.iter().map(|x| *x as i64).collect::<Vec<i64>>();
    let u: Vec<i64> = vector_matrix_product(&r_i64, &pk.a)
        .iter()
        .map(|&x| mod_q(x, pk.params.q))
        .collect();

    // v = r^T * b + bit * (q/2) (mod q)
    // q/2
    let q_over_2 = pk.params.q / 2;
    // r^T * b
    let r_dot_b = dot(&r_i64, &pk.b);
    // bit * (q/2)
    let bit_times_q_over_2 = (bit as i64) * q_over_2;
    let v = mod_q(r_dot_b + bit_times_q_over_2, pk.params.q);

    Ciphertext { u, v }
}

/// Decrypt a ciphertext to recover the bit.
///
/// Steps:
/// 1. Compute x = v - <u, s> (mod q) where <u, s> is the dot product
/// 2. If x is "close" to q/2, return 1; if "close" to 0, return 0
pub fn decrypt(sk: &SecretKey, ct: &Ciphertext) -> u8 {
    // x = v - u.s
    // u.s
    let u_dot_s = dot(&ct.u, &sk.s);
    // v - u.s
    let v_minus_u_dot_s = ct.v - u_dot_s;
    let x = mod_q(v_minus_u_dot_s, sk.params.q);

    // q/4
    let lower_bound = sk.params.q / 4;
    // 3q/4
    let upper_bound = 3 * sk.params.q / 4;

    // if x is in [q/4, 3q/4), return 1, otherwise return 0
    if x >= lower_bound && x < upper_bound {
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

/// Dot product of two vectors
pub fn dot(a: &[i64], b: &[i64]) -> i64 {
    debug_assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// Sample a random vector of length `len` with entries uniformly in [0, q)
pub fn sample_uniform_vec<R: Rng + ?Sized>(len: usize, q: i64, rng: &mut R) -> Vec<i64> {
    (0..len).map(|_| rng.gen_range(0..q)).collect()
}

/// Sample a random matrix (rows × cols) with entries uniformly in [0, q)
pub fn sample_uniform_matrix<R: Rng + ?Sized>(
    rows: usize,
    cols: usize,
    q: i64,
    rng: &mut R,
) -> Vec<Vec<i64>> {
    (0..rows)
        .map(|_| sample_uniform_vec(cols, q, rng))
        .collect()
}

/// Sample a small noise vector (length `len`) with entries in {-1, 0, 1}
pub fn sample_noise_vec<R: Rng + ?Sized>(len: usize, rng: &mut R) -> Vec<i64> {
    (0..len)
        .map(|_| match rng.gen_range(0..3) {
            0 => -1,
            1 => 0,
            _ => 1,
        })
        .collect()
}

/// Sample a random binary vector (length `len`) with entries in {0, 1}
pub fn sample_binary_vec<R: Rng + ?Sized>(len: usize, rng: &mut R) -> Vec<u8> {
    (0..len)
        .map(|_| if rng.gen_bool(0.5) { 1 } else { 0 })
        .collect()
}

fn matrix_vector_product(a: &[Vec<i64>], v: &[i64]) -> Vec<i64> {
    a.iter().map(|row| dot(row, v)).collect()
}

fn vector_matrix_product(v: &[i64], a: &[Vec<i64>]) -> Vec<i64> {
    // Compute r^T * A where r is length m and A is m × n
    // Result: for each column j, sum_i (r[i] * A[i][j])
    let n = a[0].len();
    let mut result = vec![0i64; n];
    for j in 0..n {
        for i in 0..v.len() {
            result[j] += v[i] * a[i][j];
        }
    }
    result
}

// ============================================================================
// Tests (uncomment and fix once you implement the functions)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_keygen() {
        let params = Params::toy();
        let (pk, sk) = keygen(params);

        // Check dimensions
        assert_eq!(pk.a.len(), params.m);
        assert_eq!(pk.b.len(), params.m);
        assert_eq!(sk.s.len(), params.n);
        assert_eq!(pk.a[0].len(), params.n);
    }

    #[test]
    fn test_keygen_invariants() {
        let params = Params::toy();
        let (pk, sk) = keygen(params);

        // Check dimensions
        assert_eq!(pk.a.len(), params.m, "Matrix A should have m rows");
        assert_eq!(pk.b.len(), params.m, "Vector b should have length m");
        assert_eq!(sk.s.len(), params.n, "Secret vector s should have length n");

        // Check that all rows of A have the correct length
        for (i, row) in pk.a.iter().enumerate() {
            assert_eq!(row.len(), params.n, "Row {} of A should have length n", i);
        }

        // Check that all elements in A are in [0, q)
        for (i, row) in pk.a.iter().enumerate() {
            for (j, &elem) in row.iter().enumerate() {
                assert!(
                    elem >= 0 && elem < params.q,
                    "A[{}][{}] = {} should be in [0, {})",
                    i,
                    j,
                    elem,
                    params.q
                );
            }
        }

        // Check that all elements in b are in [0, q)
        for (i, &elem) in pk.b.iter().enumerate() {
            assert!(
                elem >= 0 && elem < params.q,
                "b[{}] = {} should be in [0, {})",
                i,
                elem,
                params.q
            );
        }

        // Check that all elements in s are in [0, q)
        for (i, &elem) in sk.s.iter().enumerate() {
            assert!(
                elem >= 0 && elem < params.q,
                "s[{}] = {} should be in [0, {})",
                i,
                elem,
                params.q
            );
        }
    }

    #[test]
    fn test_roundtrip() {
        let params = Params::toy();
        let (pk, sk) = keygen(params);

        // Test encrypting and decrypting bits
        for bit in [0u8, 1u8] {
            let ct = encrypt(&pk, bit);
            let dec = decrypt(&sk, &ct);
            assert_eq!(bit, dec, "Failed to roundtrip bit {}", bit);
        }
    }
}
