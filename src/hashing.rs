use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use asn1_rs::{FromBer, FromDer};
use der::{Decode, Encode};
use sha2::{Sha224, Sha256, Sha384, Sha512, Digest};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256, digest::{Update, ExtendableOutput, XofReader}};
use md5::Md5;
use sha1::Sha1;


pub const OID_MD5: &str = "1.2.840.113549.2.5";
pub const OID_SHA1: &str = "1.3.14.3.2.26";
pub const OID_SHA224: &str = "2.16.840.1.101.3.4.2.4";
pub const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
pub const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
pub const OID_SHA3_224: &str = "2.16.840.1.101.3.4.2.7";
pub const OID_SHA3_256: &str = "2.16.840.1.101.3.4.2.8";
pub const OID_SHA3_384: &str = "2.16.840.1.101.3.4.2.9";
pub const OID_SHA3_512: &str = "2.16.840.1.101.3.4.2.10";
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

    // 1. Cleanup and Discovery phase:
    // Precision Seek: Scan for CMS OIDs (1.2.840.113549.1.7.x)
    // 1.2.840.113549.1.7.2 (signedData) = 06 09 2A 86 48 86 F7 0D 01 07 02
    // 1.2.840.113549.1.7.1 (data) = 06 09 2A 86 48 86 F7 0D 01 07 01
    let signed_data_oid = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
    let data_oid = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
    let mut start = 0;
    let mut found_oid = false;
    
    for i in 0..(cms_bytes.len().saturating_sub(11)) {
        if &cms_bytes[i..i+11] == &signed_data_oid || &cms_bytes[i..i+11] == &data_oid {
            // Found OID. Look back for the preceding SEQUENCE (0x30) or OCTET STRING (0x04/0x24) tag.
            for j in 2..=12 {
                if i >= j {
                    let tag = cms_bytes[i-j];
                    if tag == 0x30 || tag == 0x04 || tag == 0x24 {
                        start = i - j;
                        found_oid = true;
                        break;
                    }
                }
            }
            if found_oid { break; }
        }
    }

    if !found_oid {
        // Fallback: Aggressively seek the first valid ASN.1 start tag
        start = 0;
        while start < cms_bytes.len() && 
              cms_bytes[start] != 0x30 && 
              cms_bytes[start] != 0x04 && 
              cms_bytes[start] != 0x24 {
            start += 1;
        }
    }
    
    if start >= cms_bytes.len() {
        return Err(format!("No valid ASN.1 start tag (0x30, 0x04, or 0x24) found. Buffer prefix: {:02X?}", 
                           &cms_bytes[..std::cmp::min(cms_bytes.len(), 32)]).into());
    }

    let working_bytes = &cms_bytes[start..];

    // Add extreme padding (8192 zeros = 4096 levels of EOC markers) for discovery
    let mut discover_buffer = working_bytes.to_vec();
    discover_buffer.extend_from_slice(&[0; 8192]);

    let working_cms = if let Ok((rem, any)) = asn1_rs::Any::from_ber(&discover_buffer) {
        let consumed = discover_buffer.len() - rem.len();
        let extent = &discover_buffer[..consumed];
        
        if any.header.tag() == asn1_rs::Tag::OctetString {
            // Unwrapping logic
            eprintln!("Detected OCTET STRING-wrapped CMS (tag: 0x{:02X}). Unwrapping...", extent[0]);
            if any.header.is_constructed() {
                // If constructed, use ber_util fix to flatten it (using 8192-byte padding internally)
                if let Ok(der) = crate::ber_util::convert_ber_to_der(extent) {
                    if let Ok((_, der_any)) = asn1_rs::Any::from_der(&der) {
                        der_any.data.to_vec()
                    } else {
                        extent.to_vec()
                    }
                } else {
                    extent.to_vec()
                }
            } else {
                any.data.to_vec()
            }
        } else {
            extent.to_vec()
        }
    } else {
        // Fallback: If discovery failed, use the seeked bytes directly
        working_bytes.to_vec()
    };

    let content_info = if let Ok(ci) = ContentInfo::from_der(&working_cms) {
        ci
    } else {
        eprintln!("Initial DER decode failed. Attempting BER-to-DER fallback...");
        let cms_der_buffer = crate::ber_util::convert_ber_to_der(&working_cms)?;
        eprintln!("BER-to-DER successful, new length: {}", cms_der_buffer.len());
        std::fs::write("original_ber.bin", &working_cms).unwrap_or(());
        std::fs::write("converted_der.bin", &cms_der_buffer).unwrap_or(());
        ContentInfo::from_der(&cms_der_buffer)
            .map_err(|e2| format!("ASN.1 DER decode error (after BER conversion): {:?}", e2))?
    };

    let signed_data_any = &content_info.content;
    let signed_data_bytes = signed_data_any.to_der()
        .map_err(|e| format!("ASN.1 DER encode error (inner): {:?}", e))?;
    let signed_data = SignedData::from_der(&signed_data_bytes)
        .map_err(|e| format!("ASN.1 DER decode error (SignedData): {:?}", e))?;

    for signer_info in signed_data.signer_infos.0.as_slice().iter() {
        let mut digest_alg_oid = signer_info.digest_alg.oid.to_string();
        let signer_id = format_sid(&signer_info.sid);
        let mut document_hash = hash_document(signed_content, &digest_alg_oid)?;

        let mut is_integrity_ok = false;
        
        // 1. Standard CMS check: Message Digest attribute in signed_attrs
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

        // 2. RFC 3161 Timestamp check: Document hash is in TSTInfo.messageImprint.hashedMessage
        if signed_data.encap_content_info.econtent_type.to_string() == "1.2.840.113549.1.9.16.1.4" {
            if let Some(econtent) = &signed_data.encap_content_info.econtent {
                if let Ok(econtent_bytes) = econtent.to_der() {
                    // Try to extract the OID from TSTInfo to re-hash if necessary
                    // RFC 3161 TSTInfo: SEQUENCE { version ... messageImprint MessageImprint ... }
                    // MessageImprint: SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
                    
                    // Simple heuristic: if we find the document_hash in the econtent, we are good.
                    if econtent_bytes.windows(document_hash.len()).any(|w| w == &document_hash[..]) {
                        is_integrity_ok = true;
                    } else {
                        // Mismatch! Let's see if there's a different hash algorithm in the econtent.
                        // We check common OIDs as defined in this file.
                        for test_oid_str in &[OID_SHA1, OID_SHA256, OID_SHA384, OID_SHA512] {
                            if let Ok(oid) = der::asn1::ObjectIdentifier::new(test_oid_str) {
                                if let Ok(oid_der) = oid.to_der() {
                                    if econtent_bytes.windows(oid_der.len()).any(|w| w == &oid_der[..]) {
                                        // Found a potential OID. Try to hash with it.
                                        if let Ok(alt_hash) = hash_document(signed_content, test_oid_str) {
                                            if econtent_bytes.windows(alt_hash.len()).any(|w| w == &alt_hash[..]) {
                                                document_hash = alt_hash;
                                                digest_alg_oid = test_oid_str.to_string();
                                                is_integrity_ok = true;
                                                break;
                                            }
                                        }
                                    }
                                }
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
        OID_MD5 => Ok(Md5::digest(content).to_vec()),
        OID_SHA1 => Ok(Sha1::digest(content).to_vec()),
        OID_SHA224 => Ok(Sha224::digest(content).to_vec()),
        OID_SHA256 => Ok(Sha256::digest(content).to_vec()),
        OID_SHA384 => Ok(Sha384::digest(content).to_vec()),
        OID_SHA512 => Ok(Sha512::digest(content).to_vec()),
        OID_SHA3_224 => Ok(Sha3_224::digest(content).to_vec()),
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
pub fn calculate_sha256(content: &[u8]) -> Vec<u8> {
    Sha256::digest(content).to_vec()
}

pub fn calculate_sha1(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    Digest::update(&mut hasher, data);
    hasher.finalize().to_vec()
}

pub fn calculate_md5(data: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
    Digest::update(&mut hasher, data);
    hasher.finalize().to_vec()
}
