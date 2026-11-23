#[cfg(test)]
mod wave5_final_test {
    use crate::cms::extract_cms_components;
    use crate::crypto::gost_hash_data;
    use crate::crypto::GostSigner;
    use base64::Engine;
    use std::fs;
    use std::path::Path;

    #[test]
    fn final_verification_with_all_variants() {
        let sig_path = Path::new(
            r"C:\Users\i.cherney\AppData\Local\Temp\opencode\cryptoline_test_data\test1.txt.sig0",
        );

        if !sig_path.exists() {
            println!("test1.txt.sig0 not found, skipping");
            return;
        }

        let sig_b64 = fs::read_to_string(sig_path).expect("read sig");
        let sig_b64_clean: String = sig_b64.chars().filter(|c| !c.is_whitespace()).collect();
        let sig_der = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64_clean)
            .expect("decode base64");

        let cms = extract_cms_components(&sig_der).expect("extract cms");

        println!("\n=== FINAL WAVE 5 VERIFICATION ===\n");

        // Extract public key
        let pub_key = if let Some(ref cert) = cms.certificate {
            extract_pub_key_from_cert(cert)
        } else {
            None
        };

        if pub_key.is_none() {
            println!("Could not extract public key from certificate");
            return;
        }

        let pub_key = pub_key.unwrap();
        println!("Public key extracted: {} bytes", pub_key.len());
        println!("  x (LE): {}...", hex(&pub_key[0..16]));
        println!("  y (LE): {}...", hex(&pub_key[32..48]));

        println!("\nSignature: {} bytes", cms.signature.len());
        println!("  s (BE): {}...", hex(&cms.signature[0..16]));
        println!("  r (BE): {}...", hex(&cms.signature[32..48]));

        println!("\nSigned attrs: {} bytes", cms.signed_attrs_raw.len());
        println!("  Hash input preview: {}...", hex(&cms.signed_attrs_raw[0..20]));

        // Hash
        let attrs_hash_be = gost_hash_data(&cms.signed_attrs_raw);
        let mut attrs_hash_le = attrs_hash_be.to_vec();
        attrs_hash_le.reverse();

        println!("\nAttrs hash (BE): {}", hex(&attrs_hash_be));
        println!("Attrs hash (LE): {}", hex(&attrs_hash_le));

        // Create signer
        let signer = GostSigner::new();

        println!("\n--- Variant 1: disk order s || r ---");
        match signer.verify(&pub_key, &attrs_hash_le, &cms.signature) {
            Ok(true) => println!("SUCCESS"),
            Ok(false) => println!("FAILED (verification returned false)"),
            Err(e) => println!("ERROR: {}", e),
        }

        println!("\n--- Variant 2: swapped r || s ---");
        let mut swapped = Vec::with_capacity(64);
        swapped.extend_from_slice(&cms.signature[32..64]);
        swapped.extend_from_slice(&cms.signature[0..32]);

        match signer.verify(&pub_key, &attrs_hash_le, &swapped) {
            Ok(true) => println!("SUCCESS"),
            Ok(false) => println!("FAILED (verification returned false)"),
            Err(e) => println!("ERROR: {}", e),
        }

        println!("\n--- Reference from truth_facts.json ---");
        println!("Expected s: 98f16b1e1973d676f906a6b774f7c952f3a26258659de0701a1ddd6c0fbfd1a3");
        println!("Expected r: ae2cf5efed9207f6a3105bb039703942f28697fa5b836f4ecb967cb1f31ab8ea");
        println!("Our s:      {}", hex(&cms.signature[0..32]));
        println!("Our r:      {}", hex(&cms.signature[32..64]));

        if hex(&cms.signature[0..32]) == "98f16b1e1973d676f906a6b774f7c952f3a26258659de0701a1ddd6c0fbfd1a3" {
            println!("✓ s matches");
        }
        if hex(&cms.signature[32..64]) == "ae2cf5efed9207f6a3105bb039703942f28697fa5b836f4ecb967cb1f31ab8ea" {
            println!("✓ r matches");
        }

        println!("\nExpected hash (LE): 98b0bf09d0808f96878b2fb7f9113e607c7bfeb324d1b80ec643db404a347bd3");
        println!("Our hash (LE):      {}", hex(&attrs_hash_le));
        if hex(&attrs_hash_le) == "98b0bf09d0808f96878b2fb7f9113e607c7bfeb324d1b80ec643db404a347bd3" {
            println!("✓ hash matches");
        }

        println!("\n=== ANALYSIS ===");
        if hex(&cms.signature[0..32]) == "98f16b1e1973d676f906a6b774f7c952f3a26258659de0701a1ddd6c0fbfd1a3"
            && hex(&cms.signature[32..64]) == "ae2cf5efed9207f6a3105bb039703942f28697fa5b836f4ecb967cb1f31ab8ea"
            && hex(&attrs_hash_le) == "98b0bf09d0808f96878b2fb7f9113e607c7bfeb324d1b80ec643db404a347bd3"
        {
            println!("All components extracted correctly!");
            println!("If verification still fails, the problem is in GostSigner::verify()");
        }
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

    fn hex(data: &[u8]) -> String {
        data.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
}
