# How Ring-LWE Encryption Works

## The Big Picture

Ring-LWE (Ring Learning With Errors) encryption is a variant of LWE that works over polynomial rings, making it more efficient and enabling homomorphic operations. Instead of vectors and matrices, Ring-LWE uses polynomials in the ring `R_q = Z_q[x] / (x^n + 1)`. The security still comes from the **Learning With Errors** problem, but now applied to polynomial rings.

---

## Step-by-Step Breakdown

### 1. Key Generation: Creating the Public/Secret Key Pair

**What happens:**

- Generate random polynomial `a(x)` in R_q (coefficients in [0, q))
- Generate random secret polynomial `s(x)` in R_q
- Generate small noise polynomial `e(x)` (coefficients in {-1, 0, 1})
- Compute `b(x) = a(x) * s(x) + e(x)` (mod q, mod x^n + 1)

**Why this works:**

- **Public key**: `(a(x), b(x))` - looks random to attackers
- **Secret key**: `s(x)` - only you know this
- The relationship `b(x) = a(x) * s(x) + e(x)` is hidden by the noise `e(x)`

**Key insight**: Without knowing `s(x)`, `b(x)` looks like a random polynomial. But with `s(x)`, you can "almost" compute `a(x) * s(x)` and see that `b(x)` is close to it (differing only by small noise).

**The Ring Structure**: The ring `R_q = Z_q[x] / (x^n + 1)` means:

- All polynomials have degree < n
- The relation `x^n ≡ -1` (mod x^n + 1) is used to reduce higher-degree terms
- This makes polynomial multiplication efficient: `x^k = -x^(k-n)` when k ≥ n

---

### 2. Encryption: Hiding the Bit

**What happens:**

- Sample random binary polynomial `r(x)` (coefficients in {0, 1})
- Compute `u(x) = r(x) * a(x)` in R_q
- Compute `v(x) = r(x) * b(x) + bit * (q/2)` in R_q
  - The bit is encoded in the constant term: `v[0] = r(x)*b(x)[0] + bit*(q/2)`

**The mathematical trick:**

Let's expand what `v(x)` actually contains:

```text
v(x) = r(x) * b(x) + bit * (q/2)
     = r(x) * (a(x)*s(x) + e(x)) + bit * (q/2)
     = r(x) * a(x) * s(x) + r(x) * e(x) + bit * (q/2)
     = u(x) * s(x) + r(x) * e(x) + bit * (q/2)
```

Notice that `u(x) = r(x) * a(x)`, so `u(x) * s(x) = r(x) * a(x) * s(x)`!

**Why this is clever:**

- `u(x)` and `v(x)` together look random to attackers
- But notice: `v(x) - u(x)*s(x) = r(x) * e(x) + bit * (q/2)`
- Since `r(x) * e(x)` is small (because `e(x)` is small and `r(x)` is binary), the constant term `v[0] - u(x)*s(x)[0]` will be close to either `0` or `q/2` depending on the bit!

**Bit Encoding**: The bit is encoded only in the constant term (coefficient of x^0). This is more efficient than encoding in all coefficients and is the standard approach for Ring-LWE.

---

### 3. Decryption: Recovering the Bit

**What happens:**

- Compute `x(x) = v(x) - u(x) * s(x)` in R_q
- Look at the constant term `x[0]` - this should be close to 0 or q/2
- If `x[0]` is in `[q/4, 3q/4)`, return 1; otherwise return 0

**Why this works:**

From the encryption step, we know:

```text
x(x) = v(x) - u(x)*s(x)
     = (r(x) * e(x) + bit * (q/2)) mod q
```

Since `r(x) * e(x)` is small (polynomial with small coefficients):

- **If bit = 0**: `x[0] ≈ 0 + small_noise` → close to 0
- **If bit = 1**: `x[0] ≈ q/2 + small_noise` → close to q/2

**The threshold `[q/4, 3q/4)`**:

- With `q = 97`, we have `q/4 = 24` and `3q/4 = 72`
- If `x[0]` is around `q/2 = 48`, it's in `[24, 72)` → decode as 1 ✓
- If `x[0]` is around `0`, it's not in `[24, 72)` → decode as 0 ✓

---

## Why Is This Secure?

### The Ring-LWE Hardness Assumption

The security relies on the fact that **distinguishing `(a(x), a(x)*s(x) + e(x))` from `(a(x), random)` is computationally hard** in the polynomial ring.

- An attacker sees `a(x)` and `b(x) = a(x)*s(x) + e(x)`
- Without `s(x)`, `b(x)` looks random (the noise `e(x)` hides the structure)
- The ring structure doesn't weaken security - Ring-LWE is as secure as LWE for appropriate parameters

### Why Encryption Looks Random

When you encrypt:

- `u(x) = r(x) * a(x)` - looks random (random linear combination in the ring)
- `v(x) = r(x) * b(x) + bit*(q/2)` - also looks random

An attacker can't tell which bit was encrypted because:

1. They don't know `s(x)`, so they can't compute `v(x) - u(x)*s(x)`
2. The noise `r(x) * e(x)` makes the ciphertext look random

---

## Key Differences from LWE

| Aspect | LWE | Ring-LWE |
|--------|-----|----------|
| **Structure** | Vectors and matrices | Polynomials in ring R_q |
| **Key size** | O(n²) for matrix A | O(n) for polynomial a(x) |
| **Operations** | Matrix-vector multiplication | Polynomial multiplication |
| **Efficiency** | Slower (O(n²) operations) | Faster (O(n log n) with FFT) |
| **Homomorphic ops** | Limited | Natural (polynomial operations) |
| **Bit encoding** | Scalar v | Constant term v[0] |

**Why Ring-LWE is More Efficient:**
- Polynomial multiplication can be done in O(n log n) using FFT/NTT (Number Theoretic Transform)
- Smaller key sizes: O(n) instead of O(n²)
- Natural support for homomorphic operations (adding/multiplying ciphertexts)

---

## Visual Intuition

Think of it like this:

```
Key Generation:
  a(x) (public) + s(x) (secret) → b(x) = a(x)*s(x) + e(x) (public, but looks random)

Encryption:
  bit → hide it in: v(x) = r(x)*b(x) + bit*(q/2)
        also compute: u(x) = r(x)*a(x)
  (u(x), v(x)) together look random

Decryption (only with secret s(x)):
  x(x) = v(x) - u(x)*s(x) = r(x)*e(x) + bit*(q/2)
  Since r(x)*e(x) is small, x[0] ≈ bit*(q/2)
  → Can recover the bit from constant term!
```

---

## Why the Noise Must Be Small

The noise `e(x)` serves two purposes:
1. **Security**: Makes `b(x) = a(x)*s(x) + e(x)` look random (hides the structure)
2. **Correctness**: Must be small enough that `r(x) * e(x)` doesn't flip the bit during decryption

If noise is too large, decryption fails. If noise is too small, security is compromised. This is the **noise-growth problem** in LWE schemes, and it's especially important for homomorphic operations.

---

## The Ring Structure: x^n ≡ -1

The ring `R_q = Z_q[x] / (x^n + 1)` has a special property:

- When multiplying polynomials, terms of degree ≥ n are reduced using `x^n = -1`
- Example: `x^(n+1) = x^n * x = -1 * x = -x`
- This makes the ring "wrap around" in a structured way

**Example with n=4:**
```
(x^2 + 1) * (x^2 + x) = x^4 + x^3 + x^2 + x
                      = (-1) + x^3 + x^2 + x  (since x^4 = -1)
                      = x^3 + x^2 + x - 1
```

This structure enables efficient polynomial multiplication and is key to Ring-LWE's efficiency.

---

## Summary

1. **Keygen**: Create a puzzle `(a(x), b(x) = a(x)*s(x) + e(x))` that looks random but has hidden structure
2. **Encrypt**: Hide your bit in the constant term: `(u(x) = r(x)*a(x), v(x) = r(x)*b(x) + bit*(q/2))`
3. **Decrypt**: Use the secret `s(x)` to "unmask": `x[0] = v[0] - u(x)*s(x)[0] ≈ bit*(q/2)`, then decode

The magic is that **only someone with `s(x)` can compute `v(x) - u(x)*s(x)`** and recover the bit from the constant term!

**Advantages of Ring-LWE:**
- More efficient than LWE (smaller keys, faster operations)
- Natural support for homomorphic encryption
- Same security guarantees as LWE for appropriate parameters
