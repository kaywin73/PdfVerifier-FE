use asn1_rs::{Any, Header, Length, FromBer, FromDer, ToDer, Tag};

/// Recursively converts BER-encoded data (including indefinite lengths) to strict DER.
pub fn convert_ber_to_der(ber_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Add extreme padding (8192 zeros = 4096 levels of EOC markers possible)
    // This handles even the most complex, dirty, or truncated signatures.
    let mut padded_cms = ber_bytes.to_vec();
    padded_cms.extend_from_slice(&[0; 8192]);

    let (_, any) = Any::from_ber(&padded_cms)
        .map_err(|e| format!("ASN.1 BER decode error: {:?}. Buffer len: {}, Start: {:02X?}", 
                             e, padded_cms.len(), &padded_cms[..std::cmp::min(padded_cms.len(), 32)]))?;
    
    rec_to_der(&any)
}

fn rec_to_der(any: &Any) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let tag = any.header.tag();
    let class = any.header.class();

    if any.header.is_constructed() {
        let mut children_der: Vec<Vec<u8>> = Vec::new();
        let mut remaining = any.data;
        
        while !remaining.is_empty() {
            // Check for End-of-Content (EOC) marker [0, 0]
            if remaining.len() >= 2 && remaining[0] == 0 && remaining[1] == 0 {
                // End-of-Content (EOC) marker
                break;
            }
            
            let (rem, child) = Any::from_ber(remaining)
                .map_err(|e| format!("Nested BER decode error: {:?}", e))?;
            remaining = rem;
            
            children_der.push(rec_to_der(&child)?);
        }

        // DER requires SET components to be sorted by their encoded value
        // CMS uses ContextSpecific(0) and ContextSpecific(1) for implicitly tagged SET OFs
        let is_set = tag == Tag::Set 
            || (any.header.class() == class && (tag.0 == 0 || tag.0 == 1));

        if is_set {
            children_der.sort();
            children_der.dedup();
        }

        // Special handling for Constructed Strings (OCTET STRING, BIT STRING)
        // In DER, these MUST be primitive. We concatenate the data of all children.
        if class == asn1_rs::Class::Universal && (tag == Tag::OctetString || tag == Tag::BitString) {
            let mut combined_data = Vec::new();
            for child_der in children_der {
                if let Ok((_, child_any)) = Any::from_der(&child_der) {
                    combined_data.extend_from_slice(child_any.data);
                }
            }
            let header = Header::new(class, false, tag, Length::Definite(combined_data.len()));
            let mut out = header.to_der_vec().map_err(|e| format!("String DER encode error: {:?}", e))?;
            out.extend_from_slice(&combined_data);
            return Ok(out);
        }
        
        // Flatten non-string constructed children (Sequences, Sets, Context-Specific)
        let flat_children: Vec<u8> = children_der.into_iter().flatten().collect();

        let mut out = Vec::new();
        let header = Header::new(class, true, tag, Length::Definite(flat_children.len()));
        
        let header_der = header.to_der_vec().map_err(|e| format!("Header DER encode error: {:?}", e))?;
        out.extend_from_slice(&header_der);
        out.extend_from_slice(&flat_children);
        Ok(out)
    } else {
        // Primitive type, use definite length re-encoding. 
        // We must rebuild the header to ensure it's Length::Definite, otherwise to_der_vec preserves the Indefinite header.
        let mut out = Vec::new();
        let data = if any.header.length() == Length::Indefinite && any.data.len() >= 2 && any.data[any.data.len()-2..] == [0, 0] {
            &any.data[..any.data.len()-2]
        } else {
            any.data
        };
        let header = Header::new(any.header.class(), any.header.is_constructed(), any.header.tag(), Length::Definite(data.len()));
        let header_der = header.to_der_vec().map_err(|e| format!("Primitive Header DER encode error: {:?}", e))?;
        out.extend_from_slice(&header_der);
        out.extend_from_slice(data);
        Ok(out)
    }
}
