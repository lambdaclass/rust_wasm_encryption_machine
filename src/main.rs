use std::{fs::File, io::{Read, Write}};

mod api;
use api::*;

const SPACE: u8 = b' ';
const NEWLINE: u8 = b'\n';
const CARRIAGE_RETURN: u8 = b'\r';

// Each PPM image consists of the following:
//      A "magic number" for identifying the file type. A ppm image's magic number is the two characters "P6".
//      Whitespace (blanks, TABs, CRs, LFs).
//      A width, formatted as ASCII characters in decimal.
//      Whitespace.
//      A height, again in ASCII decimal.
//      Whitespace.
//      The maximum color value (Maxval), again in ASCII decimal. Must be less than 65536 and more than zero.
//      A single whitespace character (usually a newline).
//      A raster of Height rows, in order from top to bottom. Each row consists of Width pixels, in order from left to right. Each pixel is a triplet of red, green, and blue samples, in that order. Each sample is represented in pure binary by either 1 or 2 bytes. If the Maxval is less than 256, it is 1 byte. Otherwise, it is 2 bytes. The most significant byte is first. 

struct PpmHeader {
    magic_number: [u8; 2],
    width: usize,
    height: usize,
    max_color_value: u8,
}

impl PpmHeader {
    pub fn read_from(file_data: &[u8]) -> (PpmHeader, usize) {
        println!("DEBUG: {:?} (header)", &file_data[..15]);
        
        println!("DEBUG: {:?} (magic number)", &[file_data[0], file_data[1]]);
        let magic_number = [file_data[0], file_data[1]];
        // 1 byte of whitespace
        let mut i = next_until(3, &[SPACE, CARRIAGE_RETURN, NEWLINE], &file_data);
        println!("DEBUG: {:?} (width)", &file_data[3..i]);
        let width = atoi::atoi::<usize>(&file_data[3..i]).unwrap();
        // 1 byte of whitespace
        i += 1;
        let mut j = next_until(i, &[SPACE, CARRIAGE_RETURN, NEWLINE], &file_data);
        println!("DEBUG: {:?} (height)", &file_data[i..j]);
        let height = atoi::atoi::<usize>(&file_data[i..j]).unwrap();
        // 1 byte of whitespace
        i = j+1;
        j = next_until(i, &[SPACE, CARRIAGE_RETURN, NEWLINE], &file_data);
        println!("DEBUG: {:?} (max_color_value)", &file_data[i..j]);
        let max_color_value = atoi::atoi::<u8>(&file_data[i..j]).unwrap();
        // 1 byte of whitespace
        (
            PpmHeader {
                magic_number, width, height, max_color_value,
            },
            j+1
        )
    }
}

// Starting from data[usize] searches for the first occurrence of to
fn next_until(from: usize, to: &[u8], data: &[u8]) -> usize {
    let mut i = from;
    while i < data.len() {
        if to.contains(&data[i]) {
            return i;
        }
        i += 1;
    }
    return i;
}

fn read_ppm_image(buffer: &[u8]) -> (PpmHeader, Vec<u8>) {
    let (header, skip) = PpmHeader::read_from(buffer);
    let image_data = buffer[skip..].iter().copied().filter(|c| *c != SPACE).collect::<Vec<u8>>();
    (header, image_data)
}

fn encrypt_ppm_image(image_data: &[u8], public_key: &rsa::RsaPublicKey) -> Vec<u8> {
    // for each chunk we will get 128 bytes
    // take 32 byte chunks, get 128 bytes => x4 image size
    let encrypted_image = image_data
        .chunks(32)
        .flat_map(|chunk| {
            _encrypt(&public_key, chunk).unwrap()
        })
        .collect::<Vec<u8>>();

    encrypted_image
}

fn decrypt_ppm_image(image_data: &[u8], private_key: &rsa::RsaPrivateKey) -> Vec<u8> {
    let decrypted_image = image_data
        .chunks(128)
        .flat_map(|chunk| {
            _decrypt(&private_key, chunk).unwrap()
        })
        .collect::<Vec<u8>>();
    
    decrypted_image
}

fn build_image_buffer(header: PpmHeader, encrypted_image: Vec<u8>) -> Vec<u8> {
    let header_width = (2 * header.width).to_string();
    let header_height = (2 * header.height).to_string();
    let header_max_color_value = header.max_color_value.to_string();
    
    let mut resulting_buffer: Vec<u8> = vec![
        header.magic_number[0], header.magic_number[1], NEWLINE
    ];

    for c in header_width.chars() {
        resulting_buffer.push(c as u8);
    }
    resulting_buffer.push(SPACE);

    for c in header_height.chars() {
        resulting_buffer.push(c as u8);
    }
    resulting_buffer.push(NEWLINE);

    for c in header_max_color_value.chars() {
        resulting_buffer.push(c as u8);
    }
    resulting_buffer.push(NEWLINE);
        
    for byte in encrypted_image {
        resulting_buffer.push(byte);
    }

    resulting_buffer
}

fn main() {
    println!("DEBUG: Opening file");
    let mut file = File::open("src/image.ppm").unwrap();

    println!("DEBUG: Reading file");
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();

    println!("DEBUG: Parsing data");
    let (header, image_data) = read_ppm_image(&data);

    println!("DEBUG: Generating keys");
    let keys: RSAKeyPair = generate_key_pair(2048).unwrap();

    println!("DEBUG: Encrypting data");
    let encrypted_image = encrypt_ppm_image(&image_data, &keys.public_key);

    println!("DEBUG: Building buffer");
    let resulting_buffer = build_image_buffer(header, encrypted_image);
        
    println!("DEBUG: Writing file");
    // Save file raw data in a txt file
    let mut file = File::create("src/encrypted_image.ppm").unwrap();
    file.write_all(&resulting_buffer[..=resulting_buffer.len()-1]).unwrap();

    /**************************************************************************/

    println!("DEBUG: Opening encrypted file");
    let mut file = File::open("src/encrypted_image.ppm").unwrap();

    println!("DEBUG: Reading encrypted file");
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();

    println!("DEBUG: Parsing encrypted data");
    let (header, image_data) = read_ppm_image(&data);

    println!("DEBUG: Decrypting data");
    let decrypted_image = decrypt_ppm_image(&image_data, &keys.private_key);

    println!("DEBUG: Building decrypted buffer");
    let decrypted_buffer = build_image_buffer(header, decrypted_image);

    println!("DEBUG: Writing decrypted file");
    // Save file raw data in a txt file
    let mut file = File::create("src/decrypted_image.ppm").unwrap();
    file.write_all(&decrypted_buffer[..=decrypted_buffer.len()-1]).unwrap();
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    #[test]
    fn only_header_ppm() {
        let mut file = File::open("tests/assets/only_header_3_digit_width_3_digit_height.ppm").unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let (header, _) = super::PpmHeader::read_from(&data);

        assert_eq!(header.magic_number, [b'P', b'6']);
        assert_eq!(header.width, 640);
        assert_eq!(header.height, 426);
        assert_eq!(header.max_color_value, 255);
    }

    #[test]
    #[ignore = "Not Implemented"]
    fn input_image_data_is_not_equal_to_encrypted_image_data() {

    }

    #[test]
    #[ignore = "Not Implemented"]
    fn encrypted_image_data_is_not_equal_to_decrypted_image_data() {

    }

    #[test]
    #[ignore = "Not Implemented"]
    fn encrypted_image_data_is_equal_to_decrypted_image_data() {

    }
}
