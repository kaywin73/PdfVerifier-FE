use wasm_bindgen::prelude::*;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

pub mod parser;
pub mod hashing;
pub mod ber_util;

#[derive(Serialize, Deserialize)]
pub struct FieldLockPayload {
    pub action: String,
    pub fields: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SignerPayload {
    pub id: String,
    pub cms_bytes_base64: String,
    pub document_hash_base64: String,
    pub hash_algorithm_oid: String,
    pub mdp_permission: Option<i32>,
    pub is_integrity_ok: bool,
    pub signature_type: String,
    pub sub_filter: Option<String>,
    pub locked_fields: Option<FieldLockPayload>,
    pub filled_fields: Vec<String>,
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
    pub signers: Vec<SignerPayload>,
    pub dss: Option<DssPayload>,
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
pub fn parse_pdf(ptr: *const u8, len: usize) -> Result<String, JsValue> {
    console_error_panic_hook::set_once();
    
    // Safety: The pointer must be valid and allocated by `alloc_memory` above.
    let data = unsafe { std::slice::from_raw_parts(ptr, len) };

    let extraction_result = parser::extract_signatures(data)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let dss_payload = extraction_result.dss.map(|dss| DssPayload {
        certs: dss.certs.iter().map(|c| general_purpose::STANDARD.encode(c)).collect(),
        ocsps: dss.ocsps.iter().map(|o| general_purpose::STANDARD.encode(o)).collect(),
        crls: dss.crls.iter().map(|c| general_purpose::STANDARD.encode(c)).collect(),
    });

    let mut request_payload = VerifyRequest {
        signers: Vec::new(),
        dss: dss_payload,
        doc_mdp_permission: extraction_result.doc_mdp_permission,
    };

    for sig in extraction_result.signatures {
        let signer_hashes = hashing::compute_hashes_for_cms(&sig.cms_bytes, &sig.signed_content)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        for signer_hash in signer_hashes {
            let locked_fields_payload = sig.locked_fields.as_ref().map(|lock| FieldLockPayload {
                action: match lock.action {
                    parser::LockAction::All => "All".to_string(),
                    parser::LockAction::Include => "Include".to_string(),
                    parser::LockAction::Exclude => "Exclude".to_string(),
                },
                fields: lock.fields.clone(),
            });

            let payload = SignerPayload {
                id: signer_hash.signer_id,
                cms_bytes_base64: general_purpose::STANDARD.encode(&sig.cms_bytes),
                document_hash_base64: general_purpose::STANDARD.encode(&signer_hash.document_hash),
                hash_algorithm_oid: signer_hash.digest_alg_oid,
                mdp_permission: sig.mdp_permission,
                is_integrity_ok: signer_hash.is_integrity_ok,
                signature_type: sig.signature_type.clone(),
                sub_filter: sig.sub_filter.clone(),
                locked_fields: locked_fields_payload,
                filled_fields: sig.filled_fields.clone(),
                revision_index: sig.revision_index,
            };
            request_payload.signers.push(payload);
        }
    }

    let json = serde_json::to_string(&request_payload).map_err(|e| JsValue::from_str(&e.to_string()))?;
    web_sys::console::log_1(&JsValue::from_str(&format!("Wasm Output: {}", json)));
    Ok(json)
}
