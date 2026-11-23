#[cfg(test)]
mod wave8_integration_all_cases {
    use crate::crypto::ecc_params::CurveParams;
    use crate::crypto::GostSigner;
    use crate::cms::extract_cms_components;
    use base64::Engine;
    use std::fs;
    use std::path::Path;
    use num_bigint::BigUint;

    fn verify_signature_file(sig_file: &str, original_file: &str) -> bool {
        let sig_path_str = format!(r"C:\Users\i.cherney\AppData\Local\Temp\opencode\cryptoline_test_data\{}", sig_file);
        let sig_path = Path::new(&sig_path_str);

        if !sig_path.exists() {
            println!("  ❌ File not found: {}", sig_file);
            return false;
        }

        let sig_b64 = match fs::read_to_string(sig_path) {
            Ok(content) => content,
            Err(e) => {
                println!("  ❌ Failed to read {}: {}", sig_file, e);
                return false;
            }
        };

        let sig_b64_clean: String = sig_b64.chars().filter(|c| !c.is_whitespace()).collect();
        let sig_der = match base64::engine::general_purpose::STANDARD.decode(&sig_b64_clean) {
            Ok(der) => der,
            Err(e) => {
                println!("  ❌ Failed to decode base64: {}", e);
                return false;
            }
        };

        let cms = match extract_cms_components(&sig_der) {
            Ok(cms) => cms,
            Err(e) => {
                println!("  ❌ Failed to extract CMS: {}", e);
                return false;
            }
        };

        // Compute hash of original file
        use crate::crypto::gost_hash_file;
        let file_path_str = format!(r"C:\Users\i.cherney\AppData\Local\Temp\opencode\cryptoline_test_data\{}", original_file);
        let file_path = Path::new(&file_path_str);
        
        if !file_path.exists() {
            println!("  ❌ Original file not found: {}", original_file);
            return false;
        }

        let file_hash = match gost_hash_file(file_path) {
            Ok(h) => h,
            Err(e) => {
                println!("  ❌ Failed to hash file: {}", e);
                return false;
            }
        };

        // Convert LE to BE for verification
        let mut file_hash_be = file_hash.to_vec();
        file_hash_be.reverse();
        let file_hash_array = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&file_hash_be);
            arr
        };

        // Extract public key from certificate
        let pub_key_vec = extract_pub_key_from_cert(&cms.certificate.as_ref().unwrap());
        if pub_key_vec.is_none() {
            println!("  ❌ Could not extract public key from certificate");
            return false;
        }

        let pub_key_vec = pub_key_vec.unwrap();
        let pub_x = BigUint::from_bytes_le(&pub_key_vec[0..32]);
        let pub_y = BigUint::from_bytes_le(&pub_key_vec[32..64]);

        // Signature
        let s = BigUint::from_bytes_be(&cms.signature[0..32]);
        let r = BigUint::from_bytes_be(&cms.signature[32..64]);

        // Build public_key bytes: x(LE 32) ‖ y(LE 32)
        let mut pub_key_bytes = Vec::new();
        pub_key_bytes.extend_from_slice(&pub_x.to_bytes_le());
        // Pad to 32 bytes
        while pub_key_bytes.len() < 32 {
            pub_key_bytes.push(0);
        }
        pub_key_bytes.truncate(32);
        
        let pub_y_bytes = pub_y.to_bytes_le();
        let mut pub_y_padded = vec![0u8; 32];
        pub_y_padded[..pub_y_bytes.len()].copy_from_slice(&pub_y_bytes);

        pub_key_bytes.extend_from_slice(&pub_y_padded);

        // Build signature bytes: s(BE 32) ‖ r(BE 32)
        let mut sig_bytes = Vec::new();
        let s_bytes = s.to_bytes_be();
        let mut s_padded = vec![0u8; 32];
        if s_bytes.len() <= 32 {
            s_padded[32 - s_bytes.len()..].copy_from_slice(&s_bytes);
        } else {
            s_padded.copy_from_slice(&s_bytes[..32]);
        }
        sig_bytes.extend_from_slice(&s_padded);

        let r_bytes = r.to_bytes_be();
        let mut r_padded = vec![0u8; 32];
        if r_bytes.len() <= 32 {
            r_padded[32 - r_bytes.len()..].copy_from_slice(&r_bytes);
        } else {
            r_padded.copy_from_slice(&r_bytes[..32]);
        }
        sig_bytes.extend_from_slice(&r_padded);

        // Verify using GostSigner
        let signer = GostSigner::new();
        let result = match signer.verify(&pub_key_bytes, &file_hash_array, &sig_bytes) {
            Ok(is_valid) => is_valid,
            Err(e) => {
                println!("  ❌ Verification error: {}", e);
                return false;
            }
        };

        if result {
            println!("  ✅ Signature verified");
        } else {
            println!("  ❌ Signature verification failed (r_check != r)");
        }

        result
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

    #[test]
    fn verify_all_signatures() {
        println!("\n=== WAVE 8: INTEGRATION TEST - ALL 4 SIGNATURES ===\n");

        let test_cases = vec![
            ("test1.txt.sig0", "test1.txt"),
            ("test1.bin.sig0", "test1.bin"),
            ("test2.txt.sig0", "test2.txt"),
            ("test2.bin.sig0", "test2.bin"),
        ];

        let mut all_passed = true;
        for (i, (sig_file, orig_file)) in test_cases.iter().enumerate() {
            println!("Test case {}: {} ({}) ... ", i + 1, sig_file, orig_file);
            let passed = verify_signature_file(sig_file, orig_file);
            if !passed {
                all_passed = false;
            }
        }

        println!("\n=== RESULT ===");
        if all_passed {
            println!("✅ ALL SIGNATURES VERIFIED SUCCESSFULLY!");
            assert!(all_passed, "All signatures must verify");
        } else {
            println!("❌ SOME SIGNATURES FAILED VERIFICATION");
            assert!(all_passed, "All signatures must verify");
        }
    }
}
