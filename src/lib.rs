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
    // Use `web_sys`'s global `window` function to get a handle on the global
    // window object.
    let window = web_sys::window().expect("no global `window` exists");
    let document = window.document().expect("should have a document on window");
    let body = document.body().expect("document should have a body");

    // Key Pair Initialization
    // TODO: remove unwrap
    let pk_pair = generate_key_pair(1024).unwrap();
    web_sys::console::log_1(&"key pair generated".into());

    // Manufacture the element we're gonna append
    let val = document.create_element("p")?;
    val.set_inner_html("Welcome to the Encryption Machine");

    let rsa_text_encrypt = document.create_element("p")?;
    rsa_text_encrypt.set_inner_html("RSA ENCRYPT ->");
    rsa_text_encrypt.set_class_name("rsa");
    let rsa_text_decrypt = document.create_element("p")?;
    rsa_text_decrypt.set_inner_html("RSA DECRYPT ->");
    rsa_text_decrypt.set_class_name("rsa");
    let div_inputs = document.create_element("div")?;
    // Create textbox for input
    let input_textbox = document.create_element("textarea")?;
    // Create textbox for encrypted input
    let encrypted_textbox = document.create_element("textarea")?;
    // Create textbox for decrypted input
    let decrypted_textbox = document.create_element("textarea")?;
    decrypted_textbox.set_class_name("result");


    input_textbox.set_attribute("placeholder", "Enter message...")?;
    input_textbox.set_attribute("maxlength", "117")?;
    encrypted_textbox.set_attribute("placeholder", "Encrypted Message")?;
    encrypted_textbox.set_attribute("readonly", "")?;
    decrypted_textbox.set_attribute("placeholder", "Decrypted Message")?;
    decrypted_textbox.set_attribute("readonly", "")?;

    // Add event listeners
    let inbx = input_textbox.clone().dyn_into::<web_sys::HtmlTextAreaElement>()?;
    let encinbx = encrypted_textbox.clone().dyn_into::<web_sys::HtmlTextAreaElement>()?;
    let decinbx = decrypted_textbox.clone().dyn_into::<web_sys::HtmlTextAreaElement>()?;
    let handler = Closure::wrap(Box::new(move |_: web_sys::InputEvent| {
        let hash_input = inbx.value();
        web_sys::console::log_1(&"changed".into());

        // TODO: remove unwrap
        let hashed_input = _encrypt(&pk_pair.public_key, hash_input.as_bytes()).unwrap();      
        let hashed_input = base64::encode(hashed_input);
        
        let decrypted_input = base64::decode(hashed_input.clone()).unwrap();
        let decrypted_input = _decrypt(&pk_pair.private_key, &decrypted_input).unwrap();
        encinbx.set_value(&hashed_input);
        decinbx.set_value(&String::from_utf8_lossy(&decrypted_input));
    }) as Box<dyn FnMut(_)>);
    input_textbox.add_event_listener_with_callback("input", handler.as_ref().unchecked_ref())?;
    handler.forget();

    // Append to DOM
    body.append_child(&val)?;
    body.append_child(&div_inputs)?;
    div_inputs.append_child(&input_textbox)?;
    div_inputs.append_child(&rsa_text_encrypt)?;
    div_inputs.append_child(&encrypted_textbox)?;
    div_inputs.append_child(&rsa_text_decrypt)?;
    div_inputs.append_child(&decrypted_textbox)?;
    
    Ok(())
}

#[cfg(test)]
mod wasm_tests {
    // TODO: make tests
    // #[wasm_bindgen_test]
}
