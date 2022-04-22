use rsa::{RsaPrivateKey, RsaPublicKey, PaddingScheme, PublicKey};
use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize)]
struct RSAKeyPair {
    public_key: RsaPublicKey,
    private_key: RsaPrivateKey,
}

#[wasm_bindgen]
pub fn generate_key_pair(bits: usize) -> String {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    let key_pair = RSAKeyPair {private_key, public_key};
    serde_json::to_string(&key_pair).unwrap()
}

#[wasm_bindgen]
pub fn encrypt(public_key: &str, data: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let public_key: RsaPublicKey = serde_json::from_str(public_key).unwrap();
    public_key.encrypt(&mut rng, PaddingScheme::PKCS1v15Encrypt, &data).unwrap()
}

#[wasm_bindgen]
pub fn decrypt(private_key: &str, data: &[u8]) -> Vec<u8> {
    let private_key: RsaPrivateKey = serde_json::from_str(private_key).unwrap();
    private_key.decrypt(PaddingScheme::PKCS1v15Encrypt, data).expect("Failed to decrypt")
}


#[wasm_bindgen]
pub fn sign(private_key: &str, data: &[u8]) -> Vec<u8> {
    let private_key: RsaPrivateKey = serde_json::from_str(private_key).unwrap();
    private_key.sign(PaddingScheme::PKCS1v15Encrypt, &data).unwrap()
} 

// TODO: Verify signature
#[wasm_bindgen]
pub fn verify_sign(public_key: &str, data: &[u8], signature: &[u8]) -> bool {
    let public_key: RsaPublicKey = serde_json::from_str(public_key).unwrap();
    public_key.verify(PaddingScheme::PKCS1v15Encrypt, data, &signature).is_ok()
}

// Called when the wasm module is instantiated
#[wasm_bindgen(start)]
pub fn main() -> Result<(), JsValue> {
    // Use `web_sys`'s global `window` function to get a handle on the global
    // window object.
    let window = web_sys::window().expect("no global `window` exists");
    let document = window.document().expect("should have a document on window");
    let body = document.body().expect("document should have a body");

    // Manufacture the element we're gonna append
    let val = document.create_element("p")?;
    val.set_inner_html("Hello from Rust!");

    body.append_child(&val)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    // TODO: Make some tests
}
