use rsa::{RsaPublicKey, RsaPrivateKey};
use wasm_bindgen::{prelude::*, JsCast};

mod api;
use api::*;

#[wasm_bindgen]
pub fn generate_key_pair_str(bits: usize) -> Result<String, JsError> {
    if let Ok(key_pair) = generate_key_pair(bits) {
        match serde_json::to_string(&key_pair) {
            Ok(key_pair_str) => Ok(key_pair_str),
            Err(err) => Err(JsError::from(err)),
        }
    } else {
        Err(JsError::new("Failed to generate key pair"))
    }   
}

#[wasm_bindgen]
pub fn encrypt(public_key: &str, data: &[u8]) -> Result<Vec<u8>, JsError> {
    let public_key: RsaPublicKey = serde_json::from_str(&public_key).unwrap();
    let encrypted = _encrypt(&public_key, data)?;
    Ok(encrypted)
}

#[wasm_bindgen]
pub fn decrypt(private_key: &str, data: &[u8]) -> Result<Vec<u8>, JsError> {
    let private_key : RsaPrivateKey = serde_json::from_str(&private_key).unwrap();
    let decripted = _decrypt(&private_key, data)?;
    Ok(decripted)
}

#[wasm_bindgen]
pub fn sign(private_key: &str, data: &[u8]) -> Result<Vec<u8>, JsError> {
    let private_key : RsaPrivateKey = serde_json::from_str(&private_key).unwrap();
    let signature = _sign(&private_key, data)?;
    Ok(signature)
} 

#[wasm_bindgen]
pub fn verify_sign(public_key: &str, data: &[u8], signature: &[u8]) -> bool {
    let public_key : RsaPublicKey = serde_json::from_str(&public_key).unwrap();
    _verify_sign(&public_key, data, signature).is_ok()
}



// Called when the wasm module is instantiated
#[wasm_bindgen(start)]
pub fn main() -> Result<(), JsValue> {
    Ok(())
}

#[cfg(test)]
mod wasm_tests {
    // TODO: make tests
    // #[wasm_bindgen_test]
}
