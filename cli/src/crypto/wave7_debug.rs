#[cfg(test)]
mod wave7_point_arithmetic {
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
    fn debug_point_arithmetic() {
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

        // Extract public key
        let pub_key = if let Some(ref cert) = cms.certificate {
            extract_pub_key_from_cert(cert)
        } else {
            None
        };

        if pub_key.is_none() {
            println!("Could not extract public key");
            return;
        }

        let pub_key = pub_key.unwrap();
        let pub_x = BigUint::from_bytes_le(&pub_key[0..32]);
        let pub_y = BigUint::from_bytes_le(&pub_key[32..64]);

        // Signature
        let s = BigUint::from_bytes_be(&cms.signature[0..32]);
        let r = BigUint::from_bytes_be(&cms.signature[32..64]);

        // Hash
        let attrs_hash_be = gost_hash_data(&cms.signed_attrs_raw);
        let mut attrs_hash_le = attrs_hash_be.to_vec();
        attrs_hash_le.reverse();
        let h = BigUint::from_bytes_be(&attrs_hash_le);

        let curve = CurveParams::default();
        let signer = GostSigner::new();

        println!("\n=== WAVE 7: POINT ARITHMETIC DEBUG ===\n");

        // Вычисляем e, v, z1, z2 (они идеальны)
        let mut e = h.clone() % &curve.q;
        if e.is_zero() {
            e = BigUint::one();
        }
        let v = CurveParams::mod_inverse(&e, &curve.q).expect("v inverse");
        let z1 = (&s * &v) % &curve.q;
        let rv_mod = (&r * &v) % &curve.q;
        let z2 = if rv_mod.is_zero() {
            BigUint::zero()
        } else {
            (&curve.q - &rv_mod) % &curve.q
        };

        println!("Скалярные значения (все идеальны):");
        println!("  z1 = {}", z1);
        println!("  z2 = {}", z2);

        // Вычисляем P = z1*G
        println!("\nВычисляем P = z1*G:");
        let p = signer.scalar_mul(&z1).expect("P = z1*G");
        match &p {
            crate::crypto::gost2012_sign::ECPoint::Affine(px, py) => {
                println!("  P.x = {}", px);
                println!("  P.y = {}", py);
            }
            crate::crypto::gost2012_sign::ECPoint::Infinity => {
                println!("  P = Infinity (ошибка!)");
            }
        }

        // Вычисляем Q = z2*Qpub
        println!("\nВычисляем Q = z2*Qpub:");
        let q = signer.scalar_mul_point(&z2, &pub_x, &pub_y).expect("Q = z2*Qpub");
        match &q {
            crate::crypto::gost2012_sign::ECPoint::Affine(qx, qy) => {
                println!("  Q.x = {}", qx);
                println!("  Q.y = {}", qy);
            }
            crate::crypto::gost2012_sign::ECPoint::Infinity => {
                println!("  Q = Infinity");
            }
        }

        // Вычисляем C = P + Q
        println!("\nВычисляем C = P + Q:");
        let c = signer.point_add(&p, &q).expect("C = P + Q");
        match &c {
            crate::crypto::gost2012_sign::ECPoint::Affine(cx, cy) => {
                println!("  C.x = {}", cx);
                println!("  C.y = {}", cy);
                
                // Проверяем r' = C.x mod q
                let r_check = cx % &curve.q;
                println!("\nРезультат:");
                println!("  r_check = C.x mod q = {}", r_check);
                println!("  r (expected) = {}", r);
                println!("  Match: {}", r_check == r);
                
                if r_check != r {
                    println!("\n❌ ОШИБКА: r_check != r");
                    println!("Разница: {}", if r_check > r { r_check.clone() - r.clone() } else { r.clone() - r_check.clone() });
                }
            }
            crate::crypto::gost2012_sign::ECPoint::Infinity => {
                println!("  C = Infinity (очень странно!)");
            }
        }

        println!("\n=== EXPECTED FROM PYTHON ===");
        println!("После запуска wave7_reference.py получите ожидаемые координаты P, Q, C");
    }

    fn extract_pub_key_from_cert(cert: &[u8]) -> Option<Vec<u8>> {
        let mut pos = 0;
        while pos + 68 <= cert.len() {
            if cert[pos] == 0x03 {
                let len_byte = cert[pos + 1];
                if len_byte == 0x43 || len_byte == 67 {
                    let start = pos + 2;
                    if cert[start] == 0x00 && cert[start + 1] == 0x04 {
                        return Some(cert[start + 2..start + 66].to_vec());
                    }
                }
            }
            pos += 1;
        }
        None
    }
}
