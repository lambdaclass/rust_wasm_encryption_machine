use rsa::{errors::Error, PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct RSAKeyPair {
    pub public_key: RsaPublicKey,
    pub private_key: RsaPrivateKey,
}

pub fn _encrypt(public_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut rng = rand::thread_rng();
    public_key.encrypt(&mut rng, PaddingScheme::new_pkcs1v15_encrypt(), data)
}

pub fn _decrypt(private_key: &RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>, Error> {
    private_key.decrypt(PaddingScheme::new_pkcs1v15_encrypt(), data)
}

pub fn _sign(private_key: &RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>, Error> {
    private_key.sign(PaddingScheme::new_pkcs1v15_sign(None), data)
}

pub fn _verify_sign(public_key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> Result<(), Error> {
    public_key.verify(PaddingScheme::new_pkcs1v15_sign(None), data, signature)
}

pub fn generate_key_pair(bits: usize) -> Result<RSAKeyPair, Error> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);
    Ok(RSAKeyPair {
        private_key,
        public_key,
    })
}

#[cfg(test)]
mod api_tests {
    use crate::{generate_key_pair, RSAKeyPair, _decrypt, _encrypt, _sign, _verify_sign};

    fn setup_test() -> (RSAKeyPair, &'static [u8]) {
        let keys: RSAKeyPair = generate_key_pair(2048).unwrap();
        let message = "secret";

        (keys, message.as_bytes())
    }

    #[test]
    fn test01_a_message_can_be_decrypted_with_a_the_private_key_associated_with_the_public_key_that_encrypted_it(
    ) {
        let (keys, message): (RSAKeyPair, &'static [u8]) = setup_test();
        let encrypted_message = _encrypt(&keys.public_key, message).unwrap();

        let decrypted = _decrypt(&keys.private_key, &encrypted_message).unwrap();

        assert_eq!(message, decrypted.as_slice());
    }

    #[test]
    fn test02_a_message_cannot_be_decrypted_with_a_private_key_that_is_not_associated_with_the_public_key_that_encrypted_it(
    ) {
        let (keys, message): (RSAKeyPair, &'static [u8]) = setup_test();
        let (keys_2, _): (RSAKeyPair, &'static [u8]) = setup_test();
        let encrypted_message = _encrypt(&keys.public_key, message).unwrap();

        let decrypted = _decrypt(&keys_2.private_key, &encrypted_message);

        assert!(decrypted.is_err());
    }

    #[test]
    fn test03_messages_signed_with_a_private_key_can_be_verified_with_the_corresponding_public_key()
    {
        let (keys, message): (RSAKeyPair, &'static [u8]) = setup_test();
        let signed_message = _sign(&keys.private_key, message).unwrap();

        let verified = _verify_sign(&keys.public_key, message, &signed_message);

        assert!(verified.is_ok());
    }

    #[test]
    fn test04_messages_signed_with_a_private_key_cannot_be_verified_with_any_public_keys() {
        let (keys, message): (RSAKeyPair, &'static [u8]) = setup_test();
        let (keys_2, _): (RSAKeyPair, &'static [u8]) = setup_test();
        let signed_message = _sign(&keys.private_key, message).unwrap();

        let verified = _verify_sign(&keys_2.public_key, message, &signed_message);

        assert!(verified.is_err());
    }
}
