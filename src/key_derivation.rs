// removed dependency on crate rust_crypto
use curv::{
    arithmetic::traits::*,
    elliptic::curves::{
        bls12_381::{
            g1::GE1,
            g2::GE2,
            scalar::{FieldScalar, FE},
        },
        ECPoint, ECScalar,
    },
    BigInt,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

const DIGEST_SIZE: usize = 32;
const NUM_DIGESTS: usize = 255;
const OUTPUT_SIZE: usize = DIGEST_SIZE * NUM_DIGESTS;

pub trait BLSCurve {}
impl BLSCurve for GE1 {}
impl BLSCurve for GE2 {}

fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    // let (_prk, hk) = Hkdf::<Sha256>::extract(Some(&salt[..]), &ikm); // same as next line
    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), ikm);
    hk.expand(&info, okm)
        .expect("48 is a valid length for Sha256 to output");
}

fn flip_bits(num: BigInt) -> BigInt {
    num ^ (BigInt::from(2).pow(256u32) - BigInt::from(1))
}

fn ikm_to_lamport_sk(ikm: &[u8], salt: &[u8], split_bytes: &mut [[u8; DIGEST_SIZE]; NUM_DIGESTS]) {
    let mut okm = [0u8; OUTPUT_SIZE];
    hkdf(salt, ikm, b"", &mut okm);
    for r in 0..NUM_DIGESTS {
        split_bytes[r].copy_from_slice(&okm[r * DIGEST_SIZE..(r + 1) * DIGEST_SIZE])
    }
}

fn parent_sk_to_lamport_pk(parent_sk: &FE, index: u32) -> Vec<u8> {
    let salt = index.to_be_bytes();
    let ikm = parent_sk.to_bigint().to_bytes();
    let mut lamport_0 = [[0u8; DIGEST_SIZE]; NUM_DIGESTS];
    ikm_to_lamport_sk(ikm.as_slice(), salt.as_slice(), &mut lamport_0);

    let not_ikm = flip_bits(parent_sk.to_bigint()).to_bytes();
    let mut lamport_1 = [[0u8; DIGEST_SIZE]; NUM_DIGESTS];
    ikm_to_lamport_sk(not_ikm.as_slice(), salt.as_slice(), &mut lamport_1);

    let mut combined = [[0u8; DIGEST_SIZE]; NUM_DIGESTS * 2];
    combined[..NUM_DIGESTS].clone_from_slice(&lamport_0[..NUM_DIGESTS]);
    combined[NUM_DIGESTS..NUM_DIGESTS * 2].clone_from_slice(&lamport_1[..NUM_DIGESTS]);

    let mut flattened_key = [0u8; OUTPUT_SIZE * 2];
    for i in 0..NUM_DIGESTS * 2 {
        let sha_slice = &Sha256::digest(&mut combined[i])[..];
        flattened_key[i * DIGEST_SIZE..(i + 1) * DIGEST_SIZE].clone_from_slice(sha_slice);
    }

    let cmp_pk = &Sha256::digest(&flattened_key)[..];
    cmp_pk.to_vec()
}

fn hkdf_mod_r(ikm: &[u8], key_info: &[u8]) -> FE {
    let mut okm: [u8; 48] = [0u8; 48];
    let mut sk: FE = ECScalar::zero();
    let key_info_combined = [key_info, &[0u8, 48u8]].concat();
    let ikm_combined = [ikm, &[0u8]].concat();
    let salt = &mut Sha256::digest(b"BLS-SIG-KEYGEN-SALT-")[..];
    while sk.is_zero() {
        hkdf(&salt, ikm_combined.as_ref(), &key_info_combined, &mut okm);
        sk = ECScalar::from_bigint(&BigInt::from_bytes(okm.as_ref()));
        let shadow_salt = &mut [0u8; 32];
        shadow_salt.copy_from_slice(&salt);
        salt.copy_from_slice(&Sha256::digest(shadow_salt)[..]);
    }
    sk
}

// private->private hardened child key derivation
pub fn ckd_sk_hardened(parent_sk: &FE, index: u32) -> FE {
    let lamp_pk = parent_sk_to_lamport_pk(parent_sk, index);
    hkdf_mod_r(lamp_pk.as_ref(), b"")
}

// private->private hardened child key derivation from a path
pub fn derive_child_sk(parent_sk: FE, path_str: &str) -> FE {
    let path: Vec<u32> = path_to_node(path_str).unwrap();
    let mut child_sk = parent_sk.clone();
    for ccnum in path.iter() {
        child_sk = ckd_sk_hardened(&child_sk, *ccnum);
    }
    child_sk
}

// private->private non-hardened child key derivation
pub fn ckd_sk_normal<
    T: BLSCurve + curv::elliptic::curves::ECPoint<Scalar = FieldScalar>,
>(
    parent_sk: &FE,
    index: u32,
) -> FE {
    let parent_pk: T = ECPoint::generator_mul(parent_sk);
    parent_sk.add(&ckd_tweak_normal(&parent_pk, index))
}

// private->private non-hardened child key derivation from a path
pub fn derive_child_sk_normal<
    T: BLSCurve + curv::elliptic::curves::ECPoint<Scalar = FieldScalar>,
>(
    parent_sk: FE,
    path_str: &str,
) -> FE {
    let path: Vec<u32> = path_to_node(path_str).unwrap();
    let mut child_sk = parent_sk.clone();
    for ccnum in path.iter() {
        child_sk = ckd_sk_normal::<T>(&child_sk, *ccnum);
    }
    child_sk
}

// public->public non-hardened child key derivation
pub fn ckd_pk_normal<
    T: BLSCurve + curv::elliptic::curves::ECPoint<Scalar = FieldScalar> + Copy,
>(
    parent_pk: &T,
    index: u32,
) -> T {
    let tweak_sk: FE = ckd_tweak_normal(parent_pk, index);
    parent_pk.add_point(&ECPoint::generator_mul(&tweak_sk))
}

// public->public non-hardened child key derivation from a path
pub fn derive_child_pk_normal<
    T: BLSCurve + curv::elliptic::curves::ECPoint<Scalar = FieldScalar> + Copy,
>(
    parent_pk: T,
    path_str: &str,
) -> T {
    let path: Vec<u32> = path_to_node(path_str).unwrap();
    let mut child_pk = parent_pk.clone();
    for ccnum in path.iter() {
        child_pk = ckd_pk_normal(&child_pk, *ccnum);
    }
    child_pk
}

// Compute the scalar tweak added to this key to get a child key
pub fn ckd_tweak_normal<
    T: BLSCurve + curv::elliptic::curves::ECPoint<Scalar = FieldScalar>,
>(
    parent_pk: &T,
    index: u32,
) -> FE {
    let salt = index.to_be_bytes();
    let binding = parent_pk.serialize_compressed();
    let ikm = binding.as_slice();
    let combined = [ikm, &salt[..]].concat();
    ECScalar::from_bigint(&BigInt::from_bytes(&Sha256::digest(&combined)[..]))
}

// master private key derivation from a seed
pub fn derive_master_sk(seed: &[u8]) -> Result<FE, String> {
    if seed.len() < 32 {
        return Err("seed must be greater than or equal to 32 bytes".to_string());
    }
    Ok(hkdf_mod_r(seed, b""))
}

// Get indexes from a string path following EIP2334 spec
pub fn path_to_node(path_str: &str) -> Result<Vec<u32>, String> {
    let mut path: Vec<&str> = path_str.split('/').collect();
    let m = path.remove(0);
    if m != "m" {
        return Err(format!("First value must be m, got {}", m));
    }
    let mut ret: Vec<u32> = vec![];
    for value in path {
        match value.parse::<u32>() {
            Ok(v) => ret.push(v),
            Err(_) => return Err(format!("could not parse value: {}", value)),
        }
    }
    Ok(ret)
}

#[cfg(test)]
mod test {
    use super::*;

    struct TestVector {
        seed: &'static str,
        master_sk: &'static str,
        child_index: &'static str,
        child_sk: &'static str,
    }

    #[test]
    fn test_ckd_hardened() {
        // test vectors from EIP2333 (in hex/BigInt/BigInt/BigInt)
        let test_vectors = vec!(
            TestVector{
                seed : "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                master_sk : "6083874454709270928345386274498605044986640685124978867557563392430687146096",
                child_index : "0",
                child_sk : "20397789859736650942317412262472558107875392172444076792671091975210932703118",
            },
            TestVector{
                seed: "0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
                master_sk: "27580842291869792442942448775674722299803720648445448686099262467207037398656",
                child_index: "4294967295",
                child_sk: "29358610794459428860402234341874281240803786294062035874021252734817515685787",
            },
            TestVector{
                seed: "3141592653589793238462643383279502884197169399375105820974944592",
                master_sk: "29757020647961307431480504535336562678282505419141012933316116377660817309383",
                child_index: "3141592653",
                child_sk: "25457201688850691947727629385191704516744796114925897962676248250929345014287",
            },
            TestVector{
                seed: "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
                master_sk: "19022158461524446591288038168518313374041767046816487870552872741050760015818",
                child_index: "42",
                child_sk: "31372231650479070279774297061823572166496564838472787488249775572789064611981",
            }
        );
        for t in test_vectors.iter() {
            let seed = hex::decode(t.seed).expect("invalid seed format");
            let master_sk: FE =
                ECScalar::from_bigint(&BigInt::from_str_radix(t.master_sk, 10).unwrap());
            let child_index = u32::from_str_radix(t.child_index, 10).unwrap();
            let child_sk: FE = ECScalar::from_bigint(&BigInt::from_str_radix(t.child_sk, 10).unwrap());
    
            let derived_master_sk: FE = derive_master_sk(seed.as_ref()).unwrap();
            assert_eq!(derived_master_sk, master_sk);
    
            let derived_sk: FE = ckd_sk_hardened(&master_sk, child_index);
            assert_eq!(derived_sk, child_sk);
        }
    }

    #[test]
    fn test_ckd_normal() {
        // test path parsing
        let mut invalid_path = path_to_node("m/a/3s/1726/0");
        invalid_path.expect_err("This path should be invalid");
        invalid_path = path_to_node("1/2");
        invalid_path.expect_err("Path must include a m");
        invalid_path = path_to_node("m");
        assert_eq!(invalid_path.unwrap(), vec![]);

        // test non-hardened child key derivation
        let seed: [u8; 37] = [
            1, 50, 6, 244, 24, 199, 1, 25, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
            18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        ];
        let derived_master_sk: FE = derive_master_sk(&seed).unwrap();
        let derived_master_pk: GE2 = ECPoint::generator_mul(&derived_master_sk);
        let derived_child_sk: FE = ckd_sk_normal::<GE2>(&derived_master_sk, 42u32);
        let derived_child_pk: GE2 = ckd_pk_normal(&derived_master_pk, 42u32);
        assert_eq!(derived_child_pk, ECPoint::generator_mul(&derived_child_sk));
        println!("child sk and pk match!");
        let derived_grandchild_sk: FE = ckd_sk_normal::<GE2>(&derived_child_sk, 12142u32);
        let derived_grandchild_pk: GE2 = ckd_pk_normal(&derived_child_pk, 12142u32);
        assert_eq!(
            derived_grandchild_pk,
            ECPoint::generator_mul(&derived_grandchild_sk),
        );
        let derived_greatgrandchild_sk: FE = ckd_sk_normal::<GE2>(&derived_grandchild_sk, 3141592653u32);
        let derived_greatgrandchild_pk: GE2 = ckd_pk_normal(&derived_grandchild_pk, 3141592653u32);
        assert_eq!(
            derived_greatgrandchild_pk,
            ECPoint::generator_mul(&derived_greatgrandchild_sk),
        );
    
        assert_eq!(derive_child_sk_normal::<GE2>(derived_master_sk, "m/42/12142/3141592653"), derived_greatgrandchild_sk);
        assert_eq!(derive_child_pk_normal(derived_master_pk, "m/42/12142/3141592653"), derived_greatgrandchild_pk);
    }
}
