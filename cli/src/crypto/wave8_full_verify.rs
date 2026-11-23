#[cfg(test)]
mod wave8_full_verification {
    use crate::crypto::ecc_params::CurveParams;
    use crate::crypto::gost_hash_data;
    use crate::crypto::GostSigner;
    use crate::cms::extract_cms_components;
    use base64::Engine;
    use std::fs;
    use std::path::Path;
    use num_bigint::BigUint;
    use num_traits::{Zero, One};

    #[test]
    fn full_ecdsa_verification() {
        let sig_path = Path::new(
            r"C:\Users\i.cherney\AppData\Local\Temp\opencode\cryptoline_test_data\test1.txt.sig0",
        );

        if !sig_path.exists() {
            println!("test1.txt.sig0 not found");
            return;
        }

        let sig_b64 = fs::read_to_string(sig_path).expect("read sig");
        let sig_b64_clean: String = sig_b64.chars().filter(|c| !c.is_whitespace()).collect();
        let sig_der = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64_clean)
            .expect("decode base64");

        let cms = extract_cms_components(&sig_der).expect("extract cms");

        // Signature (r, s in BE format)
        let s = BigUint::from_bytes_be(&cms.signature[0..32]);
        let r = BigUint::from_bytes_be(&cms.signature[32..64]);

        // Hash of signed attributes
        let attrs_hash_be = gost_hash_data(&cms.signed_attrs_raw);
        let mut attrs_hash_le = attrs_hash_be.to_vec();
        attrs_hash_le.reverse();
        let h = BigUint::from_bytes_be(&attrs_hash_le);

        // Use hardcoded values (from Python wave7_reference.py)
        // These are CORRECT values (already converted from LE to BE)
        let pub_x = BigUint::parse_bytes(
            b"46793724705382309969820791814063951830609433558463396879898128518130696910128",
            10,
        ).unwrap();
        let pub_y = BigUint::parse_bytes(
            b"77099144004220165810571882956635076398356007885967543299752888253763467045258",
            10,
        ).unwrap();

        let curve = CurveParams::default();
        let signer = GostSigner::new();

        println!("\n=== WAVE 8: FULL ECDSA VERIFICATION ===\n");

        // Step 1: e = h mod q
        let mut e = h.clone() % &curve.q;
        if e.is_zero() {
            e = BigUint::one();
        }
        println!("Step 1: e = h mod q = {}", e);

        // Step 2: v = e^(-1) mod q
        let v = CurveParams::mod_inverse(&e, &curve.q).expect("v inverse");
        println!("Step 2: v = e^(-1) mod q = {}", v);

        // Step 3: z1 = s*v mod q
        let z1 = (&s * &v) % &curve.q;
        println!("Step 3: z1 = s*v mod q = {}", z1);

        // Step 4: z2 = (q - r*v mod q) mod q
        let rv_mod = (&r * &v) % &curve.q;
        let z2 = if rv_mod.is_zero() {
            BigUint::zero()
        } else {
            (&curve.q - &rv_mod) % &curve.q
        };
        println!("Step 4: z2 = (q - r*v mod q) mod q = {}", z2);

        // Step 5: P = z1*G
        println!("\nStep 5: Computing P = z1*G...");
        let p = signer.scalar_mul(&z1).expect("P = z1*G");
        let (px, py) = match &p {
            crate::crypto::gost2012_sign::ECPoint::Affine(x, y) => {
                println!("  P.x = {}", x);
                println!("  P.y = {}", y);
                (x.clone(), y.clone())
            }
            crate::crypto::gost2012_sign::ECPoint::Infinity => {
                println!("  ERROR: P = Infinity!");
                panic!("P should not be Infinity");
            }
        };

        // Step 6: Q' = z2*Qpub
        println!("\nStep 6: Computing Q' = z2*Q...");
        let q = signer.scalar_mul_point(&z2, &pub_x, &pub_y).expect("Q = z2*Qpub");
        let (qx, qy) = match &q {
            crate::crypto::gost2012_sign::ECPoint::Affine(x, y) => {
                println!("  Q'.x = {}", x);
                println!("  Q'.y = {}", y);
                (x.clone(), y.clone())
            }
            crate::crypto::gost2012_sign::ECPoint::Infinity => {
                println!("  Q' = Infinity");
                (BigUint::zero(), BigUint::zero())
            }
        };

        // Step 7: C = P + Q'
        println!("\nStep 7: Computing C = P + Q'...");
        let c = signer.point_add(&p, &q).expect("C = P + Q");
        let cx = match &c {
            crate::crypto::gost2012_sign::ECPoint::Affine(x, _y) => {
                println!("  C.x = {}", x);
                x.clone()
            }
            crate::crypto::gost2012_sign::ECPoint::Infinity => {
                println!("  C = Infinity (ERROR!)");
                panic!("C should not be Infinity");
            }
        };

        // Step 8: r' = C.x mod q
        let r_check = cx.clone() % &curve.q;
        println!("\nStep 8: r' = C.x mod q = {}", r_check);

        // Verification result
        println!("\n=== VERIFICATION RESULT ===");
        println!("r (from signature) = {}", r);
        println!("r' (computed)      = {}", r_check);
        println!("MATCH: {}", r_check == r);

        if r_check == r {
            println!("\n✅ SIGNATURE VERIFICATION SUCCESS!");
            assert_eq!(r_check, r, "Signature verification failed");
        } else {
            println!("\n❌ SIGNATURE VERIFICATION FAILED!");
            println!("Difference: {}", 
                if r_check > r { r_check - r } else { r - r_check }
            );
            panic!("Signature does not match!");
        }
    }
}
