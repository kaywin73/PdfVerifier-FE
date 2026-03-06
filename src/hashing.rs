use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::{Decode, Encode};
use sha2::{Sha256, Sha384, Sha512, Digest};
use sha3::{Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256, digest::{Update, ExtendableOutput, XofReader}};
use crate::ber_util;

pub const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
pub const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
pub const OID_SHA3_256: &str = "2.16.840.1.101.3.4.3.10";
pub const OID_SHA3_384: &str = "2.16.840.1.101.3.4.3.11";
pub const OID_SHA3_512: &str = "2.16.840.1.101.3.4.3.12";
pub const OID_SHAKE128: &str = "2.16.840.1.101.3.4.2.11";
pub const OID_SHAKE256: &str = "2.16.840.1.101.3.4.2.12";

#[derive(Debug)]
pub struct SignerHashInfo {
    pub signer_id: String,
    pub digest_alg_oid: String,
    pub document_hash: Vec<u8>,
    pub is_integrity_ok: bool,
}

pub fn compute_hashes_for_cms(cms_bytes: &[u8], signed_content: &[u8]) -> Result<Vec<SignerHashInfo>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();

    // PDF signature Contents are often padded with trailing null bytes.
    let mut end = cms_bytes.len();
    while end > 0 && cms_bytes[end - 1] == 0 {
        end -= 1;
    }
    let trimmed_cms_bytes = &cms_bytes[..end];
    
    // Debug info
    eprintln!("CMS bytes length: {}, Trimmed: {}", cms_bytes.len(), trimmed_cms_bytes.len());

    let mut cms_der_buffer = Vec::new();
    let content_info_res = ContentInfo::from_der(trimmed_cms_bytes);

    let content_info = match content_info_res {
        Ok(ci) => ci,
        Err(e) => {
            eprintln!("Initial DER decode failed: {:?}. Attempting BER-to-DER fallback...", e);
            cms_der_buffer = crate::ber_util::convert_ber_to_der(cms_bytes)?;
            eprintln!("BER-to-DER successful, new length: {}", cms_der_buffer.len());
            std::fs::write("original_ber.bin", cms_bytes).unwrap_or(());
            std::fs::write("converted_der.bin", &cms_der_buffer).unwrap_or(());
            ContentInfo::from_der(&cms_der_buffer)
                .map_err(|e2| format!("ASN.1 DER decode error (after BER conversion): {:?}", e2))?
        }
    };

    let signed_data_any = &content_info.content;
    let signed_data_bytes = signed_data_any.to_der()
        .map_err(|e| format!("ASN.1 DER encode error (inner): {:?}", e))?;
    let signed_data = SignedData::from_der(&signed_data_bytes)
        .map_err(|e| format!("ASN.1 DER decode error (SignedData): {:?}", e))?;

    for signer_info in signed_data.signer_infos.0.as_slice().iter() {
        let digest_alg_oid = signer_info.digest_alg.oid.to_string();
        let signer_id = format_sid(&signer_info.sid);
        let document_hash = hash_document(signed_content, &digest_alg_oid)?;

        let mut is_integrity_ok = false;
        if let Some(signed_attrs) = &signer_info.signed_attrs {
            for attr in signed_attrs.iter() {
                if attr.oid.to_string() == "1.2.840.113549.1.9.4" {
                    for val in attr.values.iter() {
                        if let Ok(octet_string) = val.decode_as::<der::asn1::OctetString>() {
                            if octet_string.as_bytes() == &document_hash[..] {
                                is_integrity_ok = true;
                            }
                        }
                    }
                }
            }
        }

        results.push(SignerHashInfo {
            signer_id,
            digest_alg_oid,
            document_hash,
            is_integrity_ok,
        });
    }

    Ok(results)
}

fn format_sid(sid: &SignerIdentifier) -> String {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => {
            let serial = hex::encode(ias.serial_number.as_bytes());
            
            let mut issuer_parts = Vec::new();
            for rdn in ias.issuer.0.iter() {
                for atv in rdn.0.iter() {
                    let oid_str = atv.oid.to_string();
                    let label = match oid_str.as_str() {
                        "2.5.4.3" => "CN",
                        "2.5.4.6" => "C",
                        "2.5.4.7" => "L",
                        "2.5.4.8" => "ST",
                        "2.5.4.10" => "O",
                        "2.5.4.11" => "OU",
                        _ => &oid_str,
                    };

                    let val_str = if let Ok(s) = atv.value.decode_as::<der::asn1::Utf8StringRef>() {
                        s.as_str().to_string()
                    } else if let Ok(s) = atv.value.decode_as::<der::asn1::PrintableStringRef>() {
                        s.as_str().to_string()
                    } else if let Ok(s) = atv.value.decode_as::<der::asn1::Ia5StringRef>() {
                        s.as_str().to_string()
                    } else {
                        format!("{:?}", atv.value)
                    };

                    issuer_parts.push(format!("{}={}", label, val_str));
                }
            }

            let issuer_str = if issuer_parts.is_empty() {
                format!("{:?}", ias.issuer)
            } else {
                issuer_parts.join(", ")
            };

            format!("Issuer: [{}], Serial: [{}]", issuer_str, serial)
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            format!("SKI: {}", hex::encode(ski.0.as_bytes()))
        }
    }
}

fn hash_document(content: &[u8], oid: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match oid {
        OID_SHA256 => Ok(Sha256::digest(content).to_vec()),
        OID_SHA384 => Ok(Sha384::digest(content).to_vec()),
        OID_SHA512 => Ok(Sha512::digest(content).to_vec()),
        OID_SHA3_256 => Ok(Sha3_256::digest(content).to_vec()),
        OID_SHA3_384 => Ok(Sha3_384::digest(content).to_vec()),
        OID_SHA3_512 => Ok(Sha3_512::digest(content).to_vec()),
        OID_SHAKE128 => {
            let mut hasher = Shake128::default();
            hasher.update(content);
            let mut reader = hasher.finalize_xof();
            let mut result = [0u8; 32];
            reader.read(&mut result);
            Ok(result.to_vec())
        }
        OID_SHAKE256 => {
            let mut hasher = Shake256::default();
            hasher.update(content);
            let mut reader = hasher.finalize_xof();
            let mut result = [0u8; 64];
            reader.read(&mut result);
            Ok(result.to_vec())
        }
        _ => Err(format!("Unsupported digest algorithm OID: {}", oid).into()),
    }
}
