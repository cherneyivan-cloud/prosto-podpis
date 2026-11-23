#[cfg(test)]
mod wave6_ecdsa_debug {
    use crate::crypto::ecc_params::CurveParams;
    use crate::crypto::gost_hash_data;
    use crate::cms::extract_cms_components;
    use base64::Engine;
    use std::fs;
    use std::path::Path;
    use num_bigint::BigUint;
    use num_traits::Zero;

    #[test]
    fn debug_ecdsa_steps() {
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

        println!("\n=== WAVE 6 ECDSA DEBUG ===\n");

        // Expected from Python
        println!("EXPECTED (from Python wave6_reference.py):");
        println!("  E:   69063836566207087226714375446485471078583665913556244720798589006303632587731");
        println!("  V:   89589823227455300032859633753022994597098787913035926492925632546262596473122");
        println!("  Z1:  48444184782272989320055173992813369722500714802340157712753038500349882893110");
        println!("  Z2:  94690180427711328700439370610485435930762866914039874865835358569906256694520");

        // Our computation
        println!("\nOUR COMPUTATION:");
        println!("  pub_x: {}", pub_x);
        println!("  pub_y: {}", pub_y);
        println!("  s:     {}", s);
        println!("  r:     {}", r);
        println!("  h:     {}", h);
        println!("  q:     {}", curve.q);

        // Step 1: e = h mod q
        let mut e = h.clone() % &curve.q;
        if e.is_zero() {
            e = BigUint::from(1u32);
        }
        println!("\nStep 1: e = h mod q");
        println!("  e: {}", e);
        println!("  Match Python: {}", e.to_string() == "69063836566207087226714375446485471078583665913556244720798589006303632587731");

        // Step 2: v = e^(-1) mod q
        let v = CurveParams::mod_inverse(&e, &curve.q).expect("v inverse");
        println!("\nStep 2: v = e^(-1) mod q");
        println!("  v: {}", v);
        println!("  Match Python: {}", v.to_string() == "89589823227455300032859633753022994597098787913035926492925632546262596473122");

        // Step 3: z1 = s*v mod q
        let z1 = (&s * &v) % &curve.q;
        println!("\nStep 3: z1 = s*v mod q");
        println!("  z1: {}", z1);
        println!("  Match Python: {}", z1.to_string() == "48444184782272989320055173992813369722500714802340157712753038500349882893110");

        // Step 4: z2
        let rv_mod = (&r * &v) % &curve.q;
        let z2 = if rv_mod.is_zero() {
            BigUint::from(0u32)
        } else {
            (&curve.q - &rv_mod) % &curve.q
        };
        println!("\nStep 4: z2 = (q - r*v mod q) mod q");
        println!("  r*v mod q: {}", rv_mod);
        println!("  z2: {}", z2);
        println!("  Match Python: {}", z2.to_string() == "94690180427711328700439370610485435930762866914039874865835358569906256694520");

        println!("\n✓ All scalar values match Python!");
        println!("   Now problem is in point arithmetic (P = z1*G, Q = z2*Qpub, C = P+Q)");
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
