# Rust BLS child key derivation (EIP2333, EIP2334)

This library is a forked version of [bls_key_derivation](https://crates.io/crates/bls_key_derivation), containing a straightforward interface to BLS12-381 child key derivation in complete compliance with [EIP2333](https://eips.ethereum.org/EIPS/eip-2333).

Since EIP2333 only proposes the hardened child key derivation, this library has also implemented a method of non-hardened child key derivation inspired by [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) to support the current application scenarios.

## Changes

Differences with the original library (<https://github.com/ChainSafe/rust-bls-derivation>) lie in the following:

1. removing the dependency on the unmaintained-for-over-6-years crate [rust-crypto](https://crates.io/crates/rust-crypto);
2. adding the active crate [curv-kzen](https://crates.io/crates/curv-kzen) to support non-hardened BLS child key derivation beyond EIP2333;
3. changing the lower limit of the seed entropy from 16 bytes to 32 bytes to be consistent with the current EIP2333 and [draft-irtf-cfrg-bls-signature-05](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05);
4. particularly modifying the function `hkdf_mod_r` in the following 5 parts to be in complete compliance with both EIP2333 and KeyGen in [Section 2.3 of draft-irtf-cfrg-bls-signature-05](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#name-keygen):
   1. IKM -> IMK || I20SP(0, 1);
   2. keyinfo -> keyinfo || I20SP(L, 2);
   3. salt -> H(salt);
   4. add a loop with the zero private key check;
   5. add an input parameter `key_info` to support user-customized key info strings instead of fixing as a default empty string "".

## Usage

Defined in the crate [`curv`](https://github.com/ZenGo-X/curv), `FE` is the scalar type in $G_1$ and $G_2$, with `GE1` and `GE2` as point types, respectively. The following generic type `T` should be either `GE1` or `GE2`.

### CKD hardened

private->private hardened child key derivation:

```
pub fn ckd_sk_hardened(parent_sk: &FE, index: u32) -> FE
```

private->private hardened child key derivation from a path:

```
pub fn derive_child_sk(parent_sk: FE, path_str: &str) -> FE
```

master private key derivation from a seed:

```
pub fn derive_master_sk(seed: &[u8]) -> Result<FE, String>
```

Get indexes from a string path following EIP2334 spec:

```
pub fn path_to_node(path_str: &str) -> Result<Vec<u32>, String>
```

### CKD non-hardened

private->private non-hardened child key derivation:

```
pub fn ckd_sk_norma::<T>(parent_sk: &FE, index: u32) -> FE
```

private->private non-hardened child key derivation from a path:

```
pub fn derive_child_sk_normal::<T>(parent_sk: FE, path_str: &str) -> FE
```

public->public non-hardened child key derivation:

```
pub fn ckd_pk_normal(parent_pk: &T, index: u32) -> T
```

public->public non-hardened child key derivation from a path:

```
pub fn derive_child_pk_normal(parent_pk: T, path_str: &str) -> T
```

Compute the scalar tweak added to this key to get a child key:

```
pub fn ckd_tweak_normal(parent_pk: &T, index: u32) -> FE
```

## Testing

run tests with:

```
cargo test
```
