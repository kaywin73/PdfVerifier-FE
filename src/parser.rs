use lopdf::{Document, Object, Dictionary};

#[derive(Debug)]
pub struct ExtractedSignature {
    pub name: String,
    pub cms_bytes: Vec<u8>,
    pub signed_content: Vec<u8>,
    pub mdp_permission: Option<i32>,
    pub signature_type: String,
    pub sub_filter: Option<String>,
    pub location: Option<String>,
    pub reason: Option<String>,
    pub filter: Option<String>,
    pub creation_app: Option<String>,
    pub byte_range: Vec<i64>,
    pub locked_fields: Option<FieldLock>,
    pub filled_fields: Vec<String>,
    pub annotation_changes: Vec<String>,
    pub revision_index: u32,
    pub byte_range_start: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockAction {
    All,
    Include,
    Exclude,
}

#[derive(Debug, Clone)]
pub struct FieldLock {
    pub action: LockAction,
    pub fields: Vec<String>,
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
    pub doc_mdp_permission: Option<i32>,
    pub filled_fields_after_last_sig: Vec<String>,
    pub annotation_changes_after_last_sig: Vec<String>,
}

pub fn extract_signatures(raw_bytes: &[u8]) -> Result<ExtractionResult, Box<dyn std::error::Error>> {
    let doc = Document::load_mem(raw_bytes).map_err(|e| format!("PDF parse error: {:?}", e))?;
    let mut signatures = Vec::new();

    let dss = extract_dss(&doc);
    let doc_mdp_permission = extract_doc_mdp_permission(&doc);

    let mut annot_to_page = std::collections::HashMap::new();
    let pages = doc.get_pages();
    for (page_num, page_id) in pages {
        if let Ok(Object::Dictionary(page_dict)) = doc.get_object(page_id) {
            if let Ok(Object::Array(annots)) = page_dict.get(b"Annots") {
                for annot_ref in annots {
                    if let Ok(id) = annot_ref.as_reference() {
                        annot_to_page.insert(id, page_num);
                    }
                }
            } else if let Ok(Object::Reference(annots_id)) = page_dict.get(b"Annots") {
                if let Ok(annots) = doc.get_object(*annots_id).and_then(|o| o.as_array()) {
                    for annot_ref in annots {
                        if let Ok(id) = annot_ref.as_reference() {
                            annot_to_page.insert(id, page_num);
                        }
                    }
                }
            }
        }
    }

    for object in doc.objects.values() {
        if let Object::Dictionary(dict) = object {
            let type_name = dict.get(b"Type").and_then(|o| o.as_name()).unwrap_or(&[][..]);
            let is_sig = type_name == b"Sig" || type_name == b"DocTimeStamp";
            
            if is_sig {
                if let Ok(Object::Array(byte_range_array)) = dict.get(b"ByteRange") {
                    let mut byte_range = Vec::new();
                    for val in byte_range_array {
                        if let Object::Integer(i) = val {
                            byte_range.push(*i);
                        }
                    }

                    if byte_range.len() == 4 {
                        let offset1 = byte_range[0] as usize;
                        let len1 = byte_range[1] as usize;
                        let offset2 = byte_range[2] as usize;
                        let len2 = byte_range[3] as usize;

                        let mut signed_content = Vec::new();
                        signed_content.extend_from_slice(&raw_bytes[offset1..offset1 + len1]);
                        signed_content.extend_from_slice(&raw_bytes[offset2..offset2 + len2]);

                        if let Ok(Object::String(contents, _)) = dict.get(b"Contents") {
                            let cms_bytes = contents.clone();
                            
                            let name = match dict.get(b"Name").and_then(|o| o.as_str()) {
                                Ok(s) => String::from_utf8_lossy(s).into_owned(),
                                Err(_) => "Unknown".to_string(),
                            };

                            let signature_type = String::from_utf8_lossy(type_name).into_owned();
                            let sub_filter = dict.get(b"SubFilter")
                                .and_then(|o| o.as_name())
                                .ok()
                                .map(|n| String::from_utf8_lossy(n).into_owned());

                            let location = dict.get(b"Location")
                                .and_then(|o| o.as_str())
                                .ok()
                                .map(|s| String::from_utf8_lossy(s).into_owned());

                            let reason = dict.get(b"Reason")
                                .and_then(|o| o.as_str())
                                .ok()
                                .map(|s| String::from_utf8_lossy(s).into_owned());

                            let filter = dict.get(b"Filter")
                                .and_then(|o| o.as_name())
                                .ok()
                                .map(|n| String::from_utf8_lossy(n).into_owned());

                            let mut creation_app = None;
                            if let Ok(prop_build) = dict.get(b"Prop_Build").and_then(|o| o.as_dict()) {
                                if let Ok(app_dict) = prop_build.get(b"App").and_then(|o| o.as_dict()) {
                                    creation_app = app_dict.get(b"REFull")
                                        .or_else(|_| app_dict.get(b"Name"))
                                        .ok()
                                        .and_then(|o| o.as_str().ok())
                                        .map(|s| String::from_utf8_lossy(s).into_owned());
                                }
                            }

                            let mdp_permission = extract_mdp_permission(&doc, dict);
                            
                            // 1. Try FieldMDP transform first
                            let mut locked_fields = extract_field_mdp_lock(&doc, dict);
                            
                            let mut sig_obj_id = None;
                            for (id, obj) in &doc.objects {
                                if let Object::Dictionary(d) = obj {
                                    let v_dict_opt = match d.get(b"V") {
                                        Ok(Object::Reference(ref_id)) => doc.get_object(*ref_id).ok().and_then(|o| o.as_dict().ok()),
                                        Ok(Object::Dictionary(dict)) => Some(dict),
                                        _ => None,
                                    };
                                    if let Some(v_dict) = v_dict_opt {
                                        if let Ok(Object::Array(vr)) = v_dict.get(b"ByteRange") {
                                            let is_match = vr.iter().enumerate().all(|(i, val)| {
                                                if let Object::Integer(v) = val {
                                                    byte_range.get(i).map_or(false, |&b| b == *v)
                                                } else {
                                                    false
                                                }
                                            });
                                            if is_match {
                                                sig_obj_id = Some(*id);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }

                            // 2. If no FieldMDP, try parent signature field's /Lock dictionary
                            if locked_fields.is_none() {
                                if let Some(id) = sig_obj_id {
                                    if let Some(parent_dict) = doc.get_object(id).ok().and_then(|o| o.as_dict().ok()) {
                                        locked_fields = extract_lock_dict(parent_dict);
                                    }
                                }
                            }

                            // 3. Extract modifications (fields and annotations)
                            let mut filled_fields = Vec::new();
                            let mut annotation_changes = Vec::new();
                            let incremental_end = offset2 + len2;
                            let mut eofs_found = 0;
                            let mut incremental_start = 0;
                            let eof_marker = b"%%EOF";
                            
                            let mut i = incremental_end.saturating_sub(eof_marker.len());
                            while i > 0 {
                                if &raw_bytes[i..i + eof_marker.len()] == eof_marker {
                                    eofs_found += 1;
                                    if eofs_found == 2 {
                                        incremental_start = i + eof_marker.len();
                                        break;
                                    }
                                }
                                i -= 1;
                            }

                            let update_bytes = if incremental_start < incremental_end && incremental_end <= raw_bytes.len() {
                                &raw_bytes[incremental_start..incremental_end]
                            } else {
                                &[]
                            };

                            for (id, obj) in &doc.objects {
                                if let Object::Dictionary(f_dict) = obj {
                                    if let Some(s_id) = sig_obj_id {
                                        if *id == s_id {
                                            continue;
                                        }
                                    }

                                    if let Ok(t_obj) = f_dict.get(b"T") {
                                        let obj_marker = format!("{} {} obj", id.0, id.1);
                                        let marker_bytes = obj_marker.as_bytes();
                                        
                                        let is_modified = update_bytes.windows(marker_bytes.len()).any(|w| w == marker_bytes);
                                        
                                        if is_modified {
                                            let is_sig_field = f_dict.get(b"FT").and_then(|o| o.as_name()).map(|n| n == b"Sig").unwrap_or(false);
                                            if !is_sig_field {
                                                if let Ok(t_obj) = f_dict.get(b"T") {
                                                    let field_name = match t_obj {
                                                        Object::String(s, _) => String::from_utf8_lossy(s).into_owned(),
                                                        _ => "Unknown".to_string(),
                                                    };
                                                    
                                                    let page_info = if let Some(page_num) = annot_to_page.get(id) {
                                                        format!(" on page {}", page_num)
                                                    } else {
                                                        "".to_string()
                                                    };
                                                    
                                                    filled_fields.push(format!("Field {}{}", field_name, page_info));
                                                } else if let Some(page_num) = annot_to_page.get(id) {
                                                    // Detection case for Non-Field Annotations (highlights, sticky notes, etc.)
                                                    let subtype = f_dict.get(b"Subtype")
                                                        .and_then(|o| o.as_name())
                                                        .map(|n| String::from_utf8_lossy(n).into_owned())
                                                        .unwrap_or("Unknown".to_string());
                                                    
                                                    annotation_changes.push(format!("{} Annotation on page {}", subtype, page_num));
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // 4. Record the byte range start for chronological sorting later
                            let byte_range_start = len1;

                            signatures.push(ExtractedSignature {
                                name,
                                cms_bytes,
                                signed_content,
                                mdp_permission,
                                signature_type,
                                sub_filter,
                                location,
                                reason,
                                filter,
                                creation_app,
                                byte_range,
                                locked_fields,
                                filled_fields,
                                annotation_changes,
                                revision_index: 0,
                                byte_range_start,
                            });
                        }
                    }
                }
            }
        }
    }

    // Assign revision indices based on the chronological order of the signatures in the file
    signatures.sort_by_key(|s| s.byte_range_start);
    for (i, sig) in signatures.iter_mut().enumerate() {
        sig.revision_index = (i + 1) as u32;
    }

    // 5. Detect changes after the last signature
    let mut filled_fields_after_last_sig = Vec::new();
    let mut annotation_changes_after_last_sig = Vec::new();

    if let Some(last_sig) = signatures.last() {
        let last_offset = last_sig.byte_range[2] as usize + last_sig.byte_range[3] as usize;
        if last_offset < raw_bytes.len() {
            let final_update_bytes = &raw_bytes[last_offset..];
            
            for (id, obj) in &doc.objects {
                if let Object::Dictionary(f_dict) = obj {
                    let obj_marker = format!("{} {} obj", id.0, id.1);
                    let marker_bytes = obj_marker.as_bytes();
                    
                    if final_update_bytes.windows(marker_bytes.len()).any(|w| w == marker_bytes) {
                        if let Ok(t_obj) = f_dict.get(b"T") {
                             let field_name = match t_obj {
                                Object::String(s, _) => String::from_utf8_lossy(s).into_owned(),
                                _ => "Unknown".to_string(),
                            };
                            filled_fields_after_last_sig.push(field_name);
                        } else if let Some(page_num) = annot_to_page.get(id) {
                            let subtype = f_dict.get(b"Subtype")
                                .and_then(|o| o.as_name())
                                .map(|n| String::from_utf8_lossy(n).into_owned())
                                .unwrap_or("Unknown".to_string());
                            annotation_changes_after_last_sig.push(format!("{} Annotation on page {}", subtype, page_num));
                        }
                    }
                }
            }
        }
    }

    Ok(ExtractionResult { 
        signatures, 
        dss, 
        doc_mdp_permission,
        filled_fields_after_last_sig,
        annotation_changes_after_last_sig
    })
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

fn extract_mdp_permission(doc: &Document, sig_dict: &Dictionary) -> Option<i32> {
    let refs = match sig_dict.get(b"Reference") {
        Ok(Object::Array(arr)) => Some(arr.clone()),
        Ok(Object::Reference(id)) => doc.get_object(*id).ok().and_then(|o| {
            if let Ok(arr) = o.as_array() {
                Some(arr.clone())
            } else if let Ok(dict) = o.as_dict() {
                Some(vec![Object::Dictionary(dict.clone())])
            } else {
                None
            }
        }),
        Ok(Object::Dictionary(d)) => Some(vec![Object::Dictionary(d.clone())]),
        _ => None,
    };

    if let Some(ref_array) = refs {
        for ref_obj in ref_array {
            let ref_dict = match ref_obj {
                Object::Dictionary(ref d) => Some(d),
                Object::Reference(id) => doc.get_object(id).ok().and_then(|o| o.as_dict().ok()),
                _ => None,
            };

            if let Some(d) = ref_dict {
                let is_doc_mdp = match d.get(b"TransformMethod").and_then(|o| o.as_name()) {
                    Ok(n) => n == b"DocMDP",
                    Err(_) => false,
                };
                
                if is_doc_mdp {
                    if let Ok(params) = d.get(b"TransformParams").and_then(|o| o.as_dict()) {
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

fn extract_doc_mdp_permission(doc: &Document) -> Option<i32> {
    let root = doc.catalog().ok()?;
    
    // Catalog -> /Perms
    let perms_obj = root.get(b"Perms").ok()?;
    let perms_dict = match perms_obj {
        Object::Dictionary(dict) => Some(dict),
        Object::Reference(id) => doc.get_object(*id).ok()?.as_dict().ok(),
        _ => None,
    }?;

    // Perms -> /DocMDP
    let doc_mdp_sig_ref = perms_dict.get(b"DocMDP").ok()?;
    let doc_mdp_sig_dict = match doc_mdp_sig_ref {
        Object::Dictionary(dict) => Some(dict),
        Object::Reference(id) => doc.get_object(*id).ok()?.as_dict().ok(),
        _ => None,
    }?;

    extract_mdp_permission(doc, doc_mdp_sig_dict)
}

fn extract_lock_dict(field_dict: &Dictionary) -> Option<FieldLock> {
    if let Ok(Object::Dictionary(lock_dict)) = field_dict.get(b"Lock") {
        let action = match lock_dict.get(b"Action").and_then(|o| o.as_name()) {
            Ok(b"All") => LockAction::All,
            Ok(b"Include") => LockAction::Include,
            Ok(b"Exclude") => LockAction::Exclude,
            _ => LockAction::All,
        };
        
        let mut fields = Vec::new();
        if let Ok(Object::Array(fields_array)) = lock_dict.get(b"Fields") {
            for f in fields_array {
                if let Ok(s) = f.as_str() {
                    fields.push(String::from_utf8_lossy(s).into_owned());
                }
            }
        }
        return Some(FieldLock { action, fields });
    }
    None
}

fn extract_field_mdp_lock(doc: &Document, sig_dict: &Dictionary) -> Option<FieldLock> {
    let refs = match sig_dict.get(b"Reference") {
        Ok(Object::Array(arr)) => Some(arr.clone()),
        Ok(Object::Reference(id)) => doc.get_object(*id).ok().and_then(|o| {
            if let Ok(arr) = o.as_array() {
                Some(arr.clone())
            } else if let Ok(dict) = o.as_dict() {
                Some(vec![Object::Dictionary(dict.clone())])
            } else {
                None
            }
        }),
        Ok(Object::Dictionary(d)) => Some(vec![Object::Dictionary(d.clone())]),
        _ => None,
    };

    if let Some(ref_array) = refs {
        for ref_obj in ref_array {
            let ref_dict = match ref_obj {
                Object::Dictionary(ref d) => Some(d),
                Object::Reference(id) => doc.get_object(id).ok().and_then(|o| o.as_dict().ok()),
                _ => None,
            };

            if let Some(d) = ref_dict {
                let is_field_mdp = match d.get(b"TransformMethod").and_then(|o| o.as_name()) {
                    Ok(n) => n == b"FieldMDP",
                    Err(_) => false,
                };
                
                if is_field_mdp {
                    if let Ok(params) = d.get(b"TransformParams").and_then(|o| o.as_dict()) {
                        let action = match params.get(b"Action").and_then(|o| o.as_name()) {
                            Ok(b"All") => LockAction::All,
                            Ok(b"Include") => LockAction::Include,
                            Ok(b"Exclude") => LockAction::Exclude,
                            _ => LockAction::All,
                        };
                        
                        let mut fields = Vec::new();
                        if let Ok(Object::Array(fields_array)) = params.get(b"Fields") {
                            for f in fields_array {
                                if let Ok(s) = f.as_str() {
                                    fields.push(String::from_utf8_lossy(s).into_owned());
                                }
                            }
                        }
                        
                        return Some(FieldLock { action, fields });
                    }
                }
            }
        }
    }
    None
}
