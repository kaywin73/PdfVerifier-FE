mod parser;
mod hashing;
mod client;
mod ber_util;

use base64::{engine::general_purpose, Engine as _};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <pdf_path> [backend_url]", args[0]);
        std::process::exit(1);
    }

    let pdf_path = &args[1];
    let backend_url = args.get(2).cloned();

    println!("Parsing PDF: {}", pdf_path);
    let extraction_result = parser::extract_signatures(pdf_path)?;

    if extraction_result.signatures.is_empty() {
        println!("No signatures found in the document.");
        return Ok(());
    }

    let dss_payload = extraction_result.dss.map(|dss| client::DssPayload {
        certs: dss.certs.iter().map(|c| general_purpose::STANDARD.encode(c)).collect(),
        ocsps: dss.ocsps.iter().map(|o| general_purpose::STANDARD.encode(o)).collect(),
        crls: dss.crls.iter().map(|c| general_purpose::STANDARD.encode(c)).collect(),
    });

    let mut request_payload = client::VerifyRequest {
        signers: Vec::new(),
        dss: dss_payload,
    };

    for sig in extraction_result.signatures {
        println!("Found signature: {}", sig.name);
        
        let signer_hashes = hashing::compute_hashes_for_cms(&sig.cms_bytes, &sig.signed_content)?;

        for signer_hash in signer_hashes {
            let payload = client::SignerPayload {
                id: signer_hash.signer_id,
                cms_bytes_base64: general_purpose::STANDARD.encode(&sig.cms_bytes),
                document_hash_base64: general_purpose::STANDARD.encode(&signer_hash.document_hash),
                hash_algorithm_oid: signer_hash.digest_alg_oid,
                mdp_permission: sig.mdp_permission,
                is_integrity_ok: signer_hash.is_integrity_ok,
            };
            request_payload.signers.push(payload);
        }
    }

    if let Some(url) = backend_url {
        println!("Sending verification request to backend...");
        let response = client::verify_signatures(&url, &request_payload).await?;
        
        println!("Verification response:\n{}", response);
    } else {
        println!("No backend URL specified. Printing payload JSON for debugging:\n");
        let json_output = serde_json::to_string_pretty(&request_payload)?;
        println!("{}", json_output);
    }

    Ok(())
}
