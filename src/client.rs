use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub signers: Vec<SignerPayload>,
    pub dss: Option<DssPayload>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignerPayload {
    pub id: String,
    pub cms_bytes_base64: String,
    pub document_hash_base64: String,
    pub hash_algorithm_oid: String,
    pub mdp_permission: Option<i32>,
    pub is_integrity_ok: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DssPayload {
    pub certs: Vec<String>,
    pub ocsps: Vec<String>,
    pub crls: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct VerifyResponse {
    pub status: String,
    pub signatures: Vec<SignatureDetails>,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct SignatureDetails {
    // Add fields matching the Java backend VerifierResponse here later
}

pub async fn verify_signatures(backend_url: &str, request_payload: &VerifyRequest) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    
    let res = client.post(backend_url)
        .json(request_payload)
        .send()
        .await?;

    if res.status().is_success() {
        let text = res.text().await?;
        Ok(text)
    } else {
        Err(format!("Backend error: {}", res.status()).into())
    }
}
