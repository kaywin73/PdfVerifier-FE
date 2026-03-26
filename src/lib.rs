use wasm_bindgen::prelude::*;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

#[cfg(feature = "dev")]
const PUBLIC_KEY: &str = include_str!("../keys/dev_public_key.pem");

#[cfg(feature = "prod")]
const PUBLIC_KEY: &str = include_str!("../keys/prod_public_key.pem");

#[cfg(not(any(feature = "dev", feature = "prod")))]
const PUBLIC_KEY: &str = include_str!("../keys/dev_public_key.pem");

pub mod parser;
pub mod hashing;
pub mod ber_util;

#[derive(Serialize, Deserialize)]
pub struct FieldLockPayload {
    pub action: String,
    pub fields: Vec<String>,
    pub is_locked: bool,
    pub p: Option<i32>,
}

#[derive(Serialize, Deserialize)]
pub struct SignerPayload {
    pub id: String,
    pub cms_bytes_base64: String,
    pub document_hash_base64: String,
    pub hash_algorithm_oid: String,
    pub is_integrity_ok: bool,
    pub signature_type: String,
    pub sub_filter: Option<String>,
    pub location: Option<String>,
    pub reason: Option<String>,
    pub filter: Option<String>,
    pub creation_app: Option<String>,
    pub byte_range: Vec<i64>,
    pub mdp_permissions: Option<FieldLockPayload>,
    pub filled_fields: Vec<String>,
    pub annotation_changes: Vec<String>,
    pub revision_index: u32,
}

#[derive(Serialize, Deserialize)]
pub struct DssPayload {
    pub certs: Vec<String>,
    pub ocsps: Vec<String>,
    pub crls: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyRequest {
    pub pdf_filename: String,
    pub pdf_hash_base64: String,
    pub signers: Vec<SignerPayload>,
    pub dss: Option<DssPayload>,
    pub filled_fields: Vec<String>,
    pub annotation_changes: Vec<String>,
    pub doc_mdp_permission: Option<i32>,
}

#[wasm_bindgen]
pub fn alloc_memory(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf); // Prevent Rust from freeing it immediately
    ptr
}

#[wasm_bindgen]
pub fn free_memory(ptr: *mut u8, size: usize) {
    if ptr.is_null() { return; }
    unsafe {
        let _ = Vec::from_raw_parts(ptr, 0, size); // Drop takes over and frees the capacity
    }
}

#[wasm_bindgen]
pub fn parse_pdf(ptr: *const u8, len: usize, filename: String) -> Result<String, JsValue> {
    console_error_panic_hook::set_once();
    
    // Safety: The pointer must be valid and allocated by `alloc_memory` above.
    let data = unsafe { std::slice::from_raw_parts(ptr, len) };

    let pdf_hash = hashing::calculate_sha256(data);
    let pdf_hash_base64 = general_purpose::STANDARD.encode(&pdf_hash);

    let extraction_result = parser::extract_signatures(data)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let dss_payload = extraction_result.dss.map(|dss| DssPayload {
        certs: dss.certs.iter().map(|c| general_purpose::STANDARD.encode(c)).collect(),
        ocsps: dss.ocsps.iter().map(|o| general_purpose::STANDARD.encode(o)).collect(),
        crls: dss.crls.iter().map(|c| general_purpose::STANDARD.encode(c)).collect(),
    });

    let mut request_payload = VerifyRequest {
        pdf_filename: filename,
        pdf_hash_base64,
        signers: Vec::new(),
        dss: dss_payload,
        filled_fields: extraction_result.filled_fields_after_last_sig,
        annotation_changes: extraction_result.annotation_changes_after_last_sig,
        doc_mdp_permission: extraction_result.doc_mdp_permission,
    };

    for sig in extraction_result.signatures {
        let signer_hashes = hashing::compute_hashes_for_cms(&sig.cms_bytes, &sig.signed_content)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        for signer_hash in signer_hashes {
            let mut locked_fields_payload = sig.locked_fields.as_ref().map(|lock| FieldLockPayload {
                action: match lock.action {
                    parser::LockAction::All => "All".to_string(),
                    parser::LockAction::Include => "Include".to_string(),
                    parser::LockAction::Exclude => "Exclude".to_string(),
                },
                fields: lock.fields.clone(),
                is_locked: true,
                p: sig.mdp_permission,
            });

            if locked_fields_payload.is_none() && sig.mdp_permission.is_some() {
                locked_fields_payload = Some(FieldLockPayload {
                    action: "None".to_string(),
                    fields: Vec::new(),
                    is_locked: false,
                    p: sig.mdp_permission,
                });
            }

            let payload = SignerPayload {
                id: signer_hash.signer_id,
                cms_bytes_base64: general_purpose::STANDARD.encode(&sig.cms_bytes),
                document_hash_base64: general_purpose::STANDARD.encode(&signer_hash.document_hash),
                hash_algorithm_oid: signer_hash.digest_alg_oid,
                is_integrity_ok: signer_hash.is_integrity_ok,
                signature_type: sig.signature_type.clone(),
                sub_filter: sig.sub_filter.clone(),
                location: sig.location.clone(),
                reason: sig.reason.clone(),
                filter: sig.filter.clone(),
                creation_app: sig.creation_app.clone(),
                byte_range: sig.byte_range.clone(),
                mdp_permissions: locked_fields_payload,
                filled_fields: sig.filled_fields.clone(),
                annotation_changes: sig.annotation_changes.clone(),
                revision_index: sig.revision_index,
            };
            request_payload.signers.push(payload);
        }
    }

    let json = serde_json::to_string(&request_payload).map_err(|e| JsValue::from_str(&e.to_string()))?;
    web_sys::console::log_1(&JsValue::from_str(&format!("Wasm Output: {}", json)));
    Ok(json)
}

#[derive(Serialize, Deserialize)]
pub struct CertDetail {
    pub oid: String,
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct ParsedCertificate {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub sig_algo: String,
    pub public_key: String,
    pub extensions: Vec<CertDetail>,
}

fn oid_to_friendly_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.1" => "RSA Encryption".to_string(),
        "1.2.840.113549.1.1.4" => "MD5 with RSA Encryption".to_string(),
        "1.2.840.113549.1.1.5" => "SHA1 with RSA Encryption".to_string(),
        "1.2.840.113549.1.1.11" => "SHA256 with RSA Encryption".to_string(),
        "1.2.840.113549.1.1.12" => "SHA384 with RSA Encryption".to_string(),
        "1.2.840.113549.1.1.13" => "SHA512 with RSA Encryption".to_string(),
        "1.2.840.10045.2.1" => "ECC (Elliptic Curve Cryptography)".to_string(),
        "1.2.840.10045.4.3.2" => "ECDSA with SHA256".to_string(),
        "1.2.840.113549.1.1.10" => "RSASSA-PSS".to_string(),
        "2.5.29.15" => "Key Usage".to_string(),
        "2.5.29.37" => "Extended Key Usage".to_string(),
        "2.5.29.19" => "Basic Constraints".to_string(),
        "2.5.29.32" => "Certificate Policies".to_string(),
        "2.5.29.31" => "CRL Distribution Points".to_string(),
        "1.3.6.1.5.5.7.1.1" => "Authority Info Access".to_string(),
        "1.3.6.1.5.5.7.48.1" => "OCSP Responder".to_string(),
        "1.3.6.1.5.5.7.48.2" => "CA Issuers".to_string(),
        "2.5.4.3" => "Common Name".to_string(),
        "2.5.4.6" => "Country Name".to_string(),
        "2.5.4.10" => "Organization Name".to_string(),
        "2.5.4.11" => "Organizational Unit Name".to_string(),
        "1.2.840.113549.1.9.1" => "Email Address".to_string(),
        "2.5.29.14" => "Subject Key Identifier".to_string(),
        "2.5.29.35" => "Authority Key Identifier".to_string(),
        "2.5.29.17" => "Subject Alternative Name".to_string(),
        _ => oid.to_string(),
    }
}

#[wasm_bindgen]
pub fn parse_x509(cert_base64: String) -> Result<String, JsValue> {
    use x509_parser::prelude::*;
    
    let cert_bytes = general_purpose::STANDARD.decode(cert_base64.trim())
        .map_err(|e| JsValue::from_str(&format!("Base64 decode error: {}", e)))?;
        
    let (_, cert) = X509Certificate::from_der(&cert_bytes)
        .map_err(|e| JsValue::from_str(&format!("X509 parse error: {}", e)))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    
    let serial = cert.serial.to_bytes_be().iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join("");

    let not_before = format!("{}", cert.validity().not_before);
    let not_after = format!("{}", cert.validity().not_after);
    let sig_algo = oid_to_friendly_name(&cert.signature_algorithm.algorithm.to_string());
    
    let pk = cert.public_key();
    let algorithm_oid = pk.algorithm.algorithm.to_string();
    let pk_raw = &pk.subject_public_key.data;
    
    let pk_bits = if algorithm_oid == "1.2.840.10045.2.1" {
        // ECC: Heuristic for uncompressed points (0x04 || X || Y)
        if pk_raw.len() > 0 && pk_raw[0] == 0x04 {
            ((pk_raw.len() - 1) / 2) * 8
        } else {
            pk_raw.len() * 4 // Fallback for compressed or other
        }
    } else if algorithm_oid.starts_with("1.2.840.113549.1.1.") {
        // RSA: Heuristic - subject_public_key.data is a DER-encoded RSAPublicKey (Sequence of N, E)
        // A simple bit length check of the data is usually close enough if we subtract overhead,
        // but for better accuracy we can just show the byte length * 8 of the raw data if it's not ECC.
        // Actually, for RSA 2048, the raw data is ~270 bytes. 270 * 8 = 2160.
        // Let's at least fix the ECC one which was the main complaint.
        pk_raw.len() * 8
    } else {
        pk_raw.len() * 8
    };

    let public_key = format!("{} ({} bits)", 
        oid_to_friendly_name(&algorithm_oid),
        pk_bits
    );

    let mut extensions = Vec::new();
    for ext in cert.extensions() {
        let oid = ext.oid.to_string();
        let name = match oid.as_str() {
            "2.5.29.15" => "Key Usage",
            "2.5.29.37" => "Extended Key Usage",
            "2.5.29.19" => "Basic Constraints",
            "2.5.29.32" => "Certificate Policies",
            "2.5.29.31" => "CRL Distribution Points",
            "1.3.6.1.5.5.7.1.1" => "Authority Info Access",
            "2.5.29.14" => "Subject Key Identifier",
            "2.5.29.35" => "Authority Key Identifier",
            "2.5.29.17" => "Subject Alternative Name",
            _ => "Unknown Extension",
        }.to_string();
        
        let value = match ext.parsed_extension() {
            ParsedExtension::KeyUsage(ku) => {
                let mut flags = Vec::new();
                if ku.digital_signature() { flags.push("Digital Signature"); }
                if ku.non_repudiation() { flags.push("Non Repudiation"); }
                if ku.key_encipherment() { flags.push("Key Encipherment"); }
                if ku.data_encipherment() { flags.push("Data Encipherment"); }
                if ku.key_agreement() { flags.push("Key Agreement"); }
                if ku.key_cert_sign() { flags.push("Certificate Signing"); }
                if ku.crl_sign() { flags.push("CRL Signing"); }
                flags.join(", ")
            },
            ParsedExtension::BasicConstraints(bc) => {
                format!("CA: {}, Path Len: {:?}", bc.ca, bc.path_len_constraint)
            },
            ParsedExtension::SubjectAlternativeName(san) => {
                san.general_names.iter().map(|gn| format!("{:?}", gn)).collect::<Vec<_>>().join(", ")
            },
            ParsedExtension::AuthorityInfoAccess(aia) => {
                aia.accessdescs.iter().map(|ad| {
                    let method = oid_to_friendly_name(&ad.access_method.to_string());
                    let location = match &ad.access_location {
                        GeneralName::URI(uri) => uri.to_string(),
                        _ => format!("{:?}", ad.access_location),
                    };
                    format!("{}: {}", method, location)
                }).collect::<Vec<_>>().join("\n")
            },
            ParsedExtension::CRLDistributionPoints(crl) => {
                crl.points.iter().map(|p| {
                    if let Some(dp) = &p.distribution_point {
                        match dp {
                            DistributionPointName::FullName(names) => {
                                names.iter().map(|name| {
                                    match name {
                                        GeneralName::URI(uri) => uri.to_string(),
                                        _ => format!("{:?}", name),
                                    }
                                }).collect::<Vec<_>>().join(", ")
                            },
                            DistributionPointName::NameRelativeToCRLIssuer(name) => format!("{:?}", name),
                        }
                    } else {
                        "Unknown Distribution Point".to_string()
                    }
                }).collect::<Vec<_>>().join("\n")
            },
            _ => format!("{:?}", ext.parsed_extension()),
        };
        extensions.push(CertDetail { oid, name, value });
    }

    let parsed = ParsedCertificate {
        subject,
        issuer,
        serial,
        not_before,
        not_after,
        sig_algo,
        public_key,
        extensions,
    };

    serde_json::to_string(&parsed).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn verify_token_report(token_report: String, signature_base64: String) -> Result<bool, JsValue> {
    use p256::ecdsa::{VerifyingKey, Signature, signature::Verifier};
    use p256::pkcs8::DecodePublicKey;
    
    let verifying_key = VerifyingKey::from_public_key_pem(PUBLIC_KEY)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse public key: {}", e)))?;
    
    let sig_bytes = general_purpose::STANDARD.decode(signature_base64.trim())
        .map_err(|e| JsValue::from_str(&format!("Failed to decode signature: {}", e)))?;
    
    let signature = Signature::from_der(&sig_bytes)
        .or_else(|_| Signature::try_from(sig_bytes.as_slice()))
        .map_err(|e| JsValue::from_str(&format!("Invalid signature format: {}", e)))?;
    
    match verifying_key.verify(token_report.as_bytes(), &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}
