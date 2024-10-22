use ark_serialize::CanonicalSerialize;
use eigen_crypto_bls::BlsKeyPair;
pub struct SignerEigen {
    key: String,
}

impl SignerEigen {
    pub fn new(key: String) -> Self {
        return SignerEigen { key };
    }
    pub fn sign(&self, message: &[u8]) -> String {
        let bls_key_pair = BlsKeyPair::new(self.key.clone()).expect("Invalid BLS private key");
        let signature = bls_key_pair.sign_message(message);
        let mut signature_bytes = Vec::new();
        signature
            .g1_point()
            .g1()
            .serialize_uncompressed(&mut signature_bytes)
            .unwrap();
        return hex::encode(&signature_bytes);
    }
}
