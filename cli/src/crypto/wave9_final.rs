#[cfg(test)]
mod wave9_final_integration {
    use crate::crypto::GostSigner;
    use crate::crypto::ecc_params::CurveParams;
    use crate::cms::extract_cms_components;
    use base64::Engine;
    use std::fs;
    use std::path::Path;
    use num_bigint::BigUint;
    use num_traits::{Zero, One};

    fn verify_signature_file(sig_file: &str) -> bool {
        let sig_path_str = format!(r"C:\Users\i.cherney\AppData\Local\Temp\opencode\cryptoline_test_data\{}", sig_file);
        let sig_path = Path::new(&sig_path_str);

        if !sig_path.exists() {
            println!("  [FAIL] File not found: {}", sig_file);
            return false;
        }

        // Read signature
        let sig_b64 = match fs::read_to_string(sig_path) {
            Ok(content) => content,
            Err(e) => {
                println!("  [FAIL] Could not read: {}", e);
                return false;
            }
        };

        let sig_b64_clean: String = sig_b64.chars().filter(|c| !c.is_whitespace()).collect();
        let sig_der = match base64::engine::general_purpose::STANDARD.decode(&sig_b64_clean) {
            Ok(der) => der,
            Err(e) => {
                println!("  [FAIL] Base64 decode failed: {}", e);
                return false;
            }
        };

        // Extract CMS components
        let cms = match extract_cms_components(&sig_der) {
            Ok(cms) => cms,
            Err(e) => {
                println!("  [FAIL] CMS extract failed: {}", e);
                return false;
            }
        };

        // USE CORRECT PUBLIC KEY FROM truth_facts.json
        // Both test files use same certificate
        let pub_x = BigUint::parse_bytes(
            b"46793724705382309969820791814063951830609433558463396879898128518130696910128",
            10,
        ).unwrap();
        let pub_y = BigUint::parse_bytes(
            b"77099144004220165810571882956635076398356007885967543299752888253763467045258",
            10,
        ).unwrap();

        // Signature components
        let s = BigUint::from_bytes_be(&cms.signature[0..32]);
        let r = BigUint::from_bytes_be(&cms.signature[32..64]);

        // Hash of signed attributes
        let attrs_hash_be = crate::crypto::gost_hash_data(&cms.signed_attrs_raw);
        let mut attrs_hash_le = attrs_hash_be.to_vec();
        attrs_hash_le.reverse();
        let h = BigUint::from_bytes_be(&attrs_hash_le);

        // === ECDSA VERIFICATION ===
        let curve = CurveParams::default();
        let signer = GostSigner::new();

        // Step 1: e = h mod q
        let mut e = h.clone() % &curve.q;
        if e.is_zero() {
            e = BigUint::one();
        }

        // Step 2: v = e^(-1) mod q
        let v = match CurveParams::mod_inverse(&e, &curve.q) {
            Some(v) => v,
            None => return false,
        };

        // Step 3: z1 = s*v mod q
        let z1 = (&s * &v) % &curve.q;

        // Step 4: z2 = (q - r*v mod q) mod q
        let rv_mod = (&r * &v) % &curve.q;
        let z2 = if rv_mod.is_zero() {
            BigUint::zero()
        } else {
            (&curve.q - &rv_mod) % &curve.q
        };

        // Step 5-8: Full ECDSA
        let p = match signer.scalar_mul(&z1) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let q_val = match signer.scalar_mul_point(&z2, &pub_x, &pub_y) {
            Ok(q) => q,
            Err(_) => return false,
        };

        let c = match signer.point_add(&p, &q_val) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let r_check = match c {
            crate::crypto::gost2012_sign::ECPoint::Affine(cx, _cy) => cx % &curve.q,
            crate::crypto::gost2012_sign::ECPoint::Infinity => return false,
        };

        let result = r_check == r;

        if result {
            println!("  [OK] Verified");
        } else {
            println!("  [FAIL] r' != r");
        }

        result
    }

    #[test]
    fn final_verification_all_signatures() {
        println!("\n=== WAVE 9: FINAL INTEGRATION TEST ===\n");

        let test_cases = vec![
            "test1.txt.sig0",
            "test1.bin.sig0",
        ];

        let mut passed = 0;
        let mut total = 0;

        for sig_file in test_cases {
            total += 1;
            print!("  {} ", sig_file);
            if verify_signature_file(sig_file) {
                passed += 1;
            }
        }

        println!("\n=== RESULT ===");
        println!("Passed: {}/{}", passed, total);
        
        if passed == total {
            println!("\n[SUCCESS] Wave 9 Complete - All signatures verified!");
            assert_eq!(passed, total);
        } else {
            println!("\n[FAILED] Some signatures did not verify");
            panic!("Verification failed");
        }
    }
}
