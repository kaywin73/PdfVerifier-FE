use std::env;
use std::fs;

fn parse_len(data: &[u8], offset: &mut usize) -> Option<u32> {
    if *offset >= data.len() { return None; }
    let b = data[*offset];
    *offset += 1;
    if b < 0x80 {
        return Some(b as u32);
    }
    if b == 0x80 {
        return Some(0xffff_ffff); // Indefinite
    }
    let num_bytes = (b & 0x7F) as usize;
    if *offset + num_bytes > data.len() { return None; }
    let mut len = 0u32;
    for _ in 0..num_bytes {
        len = (len << 8) | (data[*offset] as u32);
        *offset += 1;
    }
    Some(len)
}

fn walk(data: &[u8], offset: &mut usize, depth: usize, max_end: usize) {
    while *offset < max_end && *offset < data.len() {
        let start = *offset;
        let tag = data[*offset];
        *offset += 1;
        // handle high tag number if needed, skipping for simple check
        if (tag & 0x1F) == 0x1F {
            while data[*offset] & 0x80 != 0 { *offset += 1; }
            *offset += 1;
        }
        
        let len_offset = *offset;
        let len = parse_len(data, offset);
        
        match len {
            Some(0xffff_ffff) => {
                println!("{:pad$}Tag: {:02x} at {} has INDEFINITE LENGTH!", "", tag, start, pad=depth*2);
                let mut eoc_found = false;
                while *offset < data.len()-1 {
                    if data[*offset] == 0 && data[*offset+1] == 0 {
                        eoc_found = true;
                        *offset += 2;
                        break;
                    }
                    walk(data, offset, depth + 1, data.len());
                }
            }
            Some(l) => {
                let is_constructed = (tag & 0x20) != 0;
                println!("{:pad$}Tag: {:02x} at {} has Definite Length: {}", "", tag, start, l, pad=depth*2);
                if is_constructed && l > 0 {
                    let child_end = *offset + l as usize;
                    walk(data, offset, depth + 1, child_end);
                } else {
                    *offset += l as usize;
                }
            }
            None => {
                println!("{:pad$}Unexpected EOF at {}", "", start, pad=depth*2);
                break;
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let data = fs::read(&args[1]).unwrap();
    let mut offset = 0;
    println!("File size: {}", data.len());
    walk(&data, &mut offset, 0, data.len());
}
