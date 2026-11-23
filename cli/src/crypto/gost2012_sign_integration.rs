#[cfg(test)]
mod integration_tests {
    use crate::crypto::GostSigner;
    use std::fs;
    use std::path::Path;

    #[test]
    #[ignore]  // Wave 4: Requires proper CMS parsing to extract signed attributes
    fn verify_real_signatures_from_truth_facts() {
        let truth_path = Path::new(
            r"C:\opencode\taxcom\cryptoline_analysis\truth_facts.json",
        );

        if !truth_path.exists() {
            eprintln!("truth_facts.json not found");
            return;
        }

        let _content = fs::read_to_string(truth_path)
            .expect("Failed to read truth_facts.json");

        // NOTE: Full signature verification requires:
        // 1. Extract signed attributes from CMS/DER structure
        // 2. Compute Streebog256(0x31 || attributes_without_tag_length)
        // 3. Reverse to little-endian (for ГОСТ convention)
        // 4. Use THAT as the digest for verification
        //
        // truth_facts.json only contains:
        // - message_digest: hash of file content (not used for signature verification!)
        // - signature_octets: s(BE 32) || r(BE 32) from DER
        //
        // Full integration test must parse the .sig file (DER) directly.
        // See: verify_truth.py for the correct flow.
        
        eprintln!(
            "Integration test disabled for Wave 4.\n\
             Reason: Signature verification requires hash of signed attributes,\n\
             not file content hash.\n\
             See verify_truth.py for correct verification flow.\n\
             TODO: Implement full CMS parser in Wave 5"
        );
    }
}

