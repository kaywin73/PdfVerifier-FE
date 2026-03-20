use asn1_rs::{Any, Header, Length, FromBer, ToDer, Tag};

/// Recursively converts BER-encoded data (including indefinite lengths) to strict DER.
pub fn convert_ber_to_der(ber_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Add extra padding as BER indefinite length requires EOC markers which might be truncated in PDFs
    let mut padded_cms = ber_bytes.to_vec();
    padded_cms.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);

    let (_, any) = Any::from_ber(&padded_cms)
        .map_err(|e| format!("ASN.1 BER decode error: {:?}", e))?;
    
    rec_to_der(&any)
}

fn rec_to_der(any: &Any) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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
        // (e.g. certificates, crls, signedAttrs, unsignedAttrs)
        let is_set = any.header.tag() == Tag::Set 
            || (any.header.class() == asn1_rs::Class::ContextSpecific && (any.header.tag().0 == 0 || any.header.tag().0 == 1));

        if is_set {
            children_der.sort();
            children_der.dedup();
        }
        
        // Flatten children
        let flat_children: Vec<u8> = children_der.into_iter().flatten().collect();

        let mut out = Vec::new();
        // In asn1-rs, Length::Definite usually takes the length as a u32 or usize depending on version.
        // We use flat_children.len().
        let header = Header::new(any.header.class(), any.header.is_constructed(), any.header.tag(), Length::Definite(flat_children.len()));
        
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
