use lopdf::{Document, Object, Dictionary};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug)]
pub struct ExtractedSignature {
    pub name: String,
    pub cms_bytes: Vec<u8>,
    pub signed_content: Vec<u8>,
    pub mdp_permission: Option<i32>,
}

#[derive(Debug)]
pub struct DssData {
    pub certs: Vec<Vec<u8>>,
    pub ocsps: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
}

pub struct ExtractionResult {
    pub signatures: Vec<ExtractedSignature>,
    pub dss: Option<DssData>,
}

pub fn extract_signatures<P: AsRef<Path>>(pdf_path: P) -> Result<ExtractionResult, Box<dyn std::error::Error>> {
    let mut file = File::open(pdf_path.as_ref())?;
    let mut raw_bytes = Vec::new();
    file.read_to_end(&mut raw_bytes)?;

    let doc = Document::load_mem(&raw_bytes).map_err(|e| format!("PDF parse error: {:?}", e))?;
    let mut signatures = Vec::new();

    let dss = extract_dss(&doc);

    for object in doc.objects.values() {
        if let Object::Dictionary(dict) = object {
            let type_name = dict.get(b"Type").and_then(|o| o.as_name()).unwrap_or(&[][..]);
            let is_sig = type_name == b"Sig";
            
            if is_sig {
                if let Ok(Object::Array(byte_range_array)) = dict.get(b"ByteRange") {
                    let mut byte_range = Vec::new();
                    for val in byte_range_array {
                        if let Object::Integer(i) = val {
                            byte_range.push(*i as usize);
                        }
                    }

                    if byte_range.len() == 4 {
                        let offset1 = byte_range[0];
                        let len1 = byte_range[1];
                        let offset2 = byte_range[2];
                        let len2 = byte_range[3];

                        let mut signed_content = Vec::new();
                        signed_content.extend_from_slice(&raw_bytes[offset1..offset1 + len1]);
                        signed_content.extend_from_slice(&raw_bytes[offset2..offset2 + len2]);

                        if let Ok(Object::String(contents, _)) = dict.get(b"Contents") {
                            let cms_bytes = contents.clone();
                            
                            let name = match dict.get(b"Name").and_then(|o| o.as_str()) {
                                Ok(s) => String::from_utf8_lossy(s).into_owned(),
                                Err(_) => "Unknown".to_string(),
                            };

                            let mdp_permission = extract_mdp_permission(&doc, dict);

                            signatures.push(ExtractedSignature {
                                name,
                                cms_bytes,
                                signed_content,
                                mdp_permission,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(ExtractionResult { signatures, dss })
}

fn extract_dss(doc: &Document) -> Option<DssData> {
    let root = doc.catalog().ok()?;
    
    let dss_obj = root.get(b"DSS").ok()?;
    let dss_dict = match dss_obj {
        Object::Dictionary(dict) => Some(dict),
        Object::Reference(id) => doc.get_object(*id).ok()?.as_dict().ok(),
        _ => None,
    }?;

    let mut certs = Vec::new();
    let mut ocsps = Vec::new();
    let mut crls = Vec::new();

    if let Ok(Object::Array(certs_array)) = dss_dict.get(b"Certs") {
        for obj_ref in certs_array {
            if let Some(stream_bytes) = get_stream_bytes(doc, obj_ref) {
                certs.push(stream_bytes);
            }
        }
    }

    if let Ok(Object::Array(ocsps_array)) = dss_dict.get(b"OCSPs") {
        for obj_ref in ocsps_array {
            if let Some(stream_bytes) = get_stream_bytes(doc, obj_ref) {
                ocsps.push(stream_bytes);
            }
        }
    }

    if let Ok(Object::Array(crls_array)) = dss_dict.get(b"CRLs") {
        for obj_ref in crls_array {
            if let Some(stream_bytes) = get_stream_bytes(doc, obj_ref) {
                crls.push(stream_bytes);
            }
        }
    }

    if certs.is_empty() && ocsps.is_empty() && crls.is_empty() {
        None
    } else {
        Some(DssData { certs, ocsps, crls })
    }
}

fn get_stream_bytes(doc: &Document, obj: &Object) -> Option<Vec<u8>> {
    let reference = obj.as_reference().ok()?;
    let stream = doc.get_object(reference).ok()?.as_stream().ok()?;
    Some(stream.content.clone())
}

fn extract_mdp_permission(_doc: &Document, sig_dict: &Dictionary) -> Option<i32> {
    if let Ok(Object::Array(ref_array)) = sig_dict.get(b"Reference") {
        for ref_obj in ref_array {
            if let Ok(ref_dict) = ref_obj.as_dict() {
                let is_doc_mdp = match ref_dict.get(b"TransformMethod").and_then(|o| o.as_name()) {
                    Ok(n) => n == b"DocMDP",
                    Err(_) => false,
                };
                
                if is_doc_mdp {
                    if let Ok(params) = ref_dict.get(b"TransformParams").and_then(|o| o.as_dict()) {
                        if let Ok(Object::Integer(p)) = params.get(b"P") {
                            return Some(*p as i32);
                        }
                    }
                }
            }
        }
    }
    None
}
