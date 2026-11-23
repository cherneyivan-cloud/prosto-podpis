#[cfg(test)]
mod wave5_debug_tests {
    use crate::cms::extract_cms_components;
    use crate::crypto::gost_hash_data;
    use crate::crypto::GostSigner;
    use base64::Engine;
    use std::fs;
    use std::path::Path;

    #[test]
    fn debug_signature_verification() {
        let sig_path = Path::new(
            r"C:\Users\i.cherney\AppData\Local\Temp\opencode\cryptoline_test_data\test1.txt.sig0",
        );

        if !sig_path.exists() {
            eprintln!("test1.txt.sig0 not found");
            return;
        }

        let sig_b64 = fs::read_to_string(sig_path).expect("Failed to read sig file");
        let sig_b64_clean: String = sig_b64.chars().filter(|c| !c.is_whitespace()).collect();
        let sig_der = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64_clean)
            .expect("Failed to decode Base64");

        let cms = extract_cms_components(&sig_der).expect("Failed to extract CMS");

        println!("\n=== DEBUG: Signature Verification ===\n");

        // Extract signature components
        println!("Signature octets (64 bytes):");
        println!("  First 32 (s?): {}", hex(&cms.signature[0..32]));
        println!("  Last 32 (r?):  {}", hex(&cms.signature[32..64]));

        // Try both orderings
        println!("\nTrying verification with different orderings:\n");

        // Original: s || r
        {
            let mut attrs_hash = gost_hash_data(&cms.signed_attrs_raw).to_vec();
            attrs_hash.reverse();
            println!("Order 1: signature as s(BE 32) || r(BE 32)");
            println!("  Attrs hash (LE): {}", hex(&attrs_hash));

            if let Some(ref pk) = cms.certificate.as_ref()
                .and_then(|cert| extract_pub_key_from_cert(cert))
            {
                println!("  Pub key (64 bytes): {}", hex(&pk[0..32]));
                let signer = GostSigner::new();
                match signer.verify(pk, &attrs_hash, &cms.signature) {
                    Ok(true) => println!("  ✅ Verification SUCCESS"),
                    Ok(false) => println!("  ❌ Verification FAILED"),
                    Err(e) => println!("  ⚠️  Error: {}", e),
                }
            }
        }

        // Order 2: signature as r(BE 32) || s(BE 32) (CORRECT for verification!)
        {
            // According to verify_truth.py line 92-95:
            // sig octets on disk: s || r
            // but verify() expects: r || s
            let mut reversed_sig = Vec::with_capacity(64);
            reversed_sig.extend_from_slice(&cms.signature[32..64]);  // r
            reversed_sig.extend_from_slice(&cms.signature[0..32]);   // s

            let mut attrs_hash = gost_hash_data(&cms.signed_attrs_raw).to_vec();
            attrs_hash.reverse();

            println!("\nOrder 2: signature as r(BE 32) || s(BE 32) (disk order reversed)");
            println!("  Disk order: s(BE) || r(BE)");
            println!("  Verify order: r(BE) || s(BE)");
            println!("  Reversed sig first 32: {}", hex(&reversed_sig[0..32]));

            if let Some(ref pk) = cms.certificate.as_ref()
                .and_then(|cert| extract_pub_key_from_cert(cert))
            {
                let signer = GostSigner::new();
                match signer.verify(pk, &attrs_hash, &reversed_sig) {
                    Ok(true) => println!("  ✅ Verification SUCCESS!"),
                    Ok(false) => println!("  ❌ Verification FAILED"),
                    Err(e) => println!("  ⚠️  Error: {}", e),
                }
            }
        }

        // Try without reversing hash
        {
            let attrs_hash = gost_hash_data(&cms.signed_attrs_raw);
            println!("\nOrder 3: hash NOT reversed (BE)");
            println!("  Attrs hash (BE): {}", hex(&attrs_hash));

            if let Some(ref pk) = cms.certificate.as_ref()
                .and_then(|cert| extract_pub_key_from_cert(cert))
            {
                let signer = GostSigner::new();
                match signer.verify(pk, &attrs_hash, &cms.signature) {
                    Ok(true) => println!("  ✅ Verification SUCCESS"),
                    Ok(false) => println!("  ❌ Verification FAILED"),
                    Err(e) => println!("  ⚠️  Error: {}", e),
                }
            }
        }

        println!("\n=== Expected from truth_facts ===");
        println!("  s = 98f16b1e1973d676f906a6b774f7c952f3a26258659de0701a1ddd6c0fbfd1a3");
        println!("  r = ae2cf5efed9207f6a3105bb039703942f28697fa5b836f4ecb967cb1f31ab8ea");
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
