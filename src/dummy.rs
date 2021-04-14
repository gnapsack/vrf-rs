//! Sample module implementing a __dummy__ (to be used as example) Verifiable Random Function (VRF)
use crate::VRF;
use failure::Error;

pub struct DummyVRF;

/// The size (in bytes) of a secret key
pub const SECRET_KEY_SIZE: usize = 32;

/// The size (in bytes) of a serialized public key.
pub const PUBLIC_KEY_SIZE: usize = 33;

/// The type of the secret key
pub type SecretKey<'a> = &'a [u8; SECRET_KEY_SIZE];

/// The type of the public key
pub type PublicKey<'a> = &'a [u8; PUBLIC_KEY_SIZE];

impl<'a> VRF<PublicKey<'a>, SecretKey<'a>> for DummyVRF {
    type Error = Error;

    // Generate proof from key pair and message
    fn prove(&mut self, _x: SecretKey, _alpha: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![0])
    }

    // Verify proof given public key, proof and message
    fn verify(&mut self, _y: PublicKey, _pi: &[u8], _alpha: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![0])
    }
    
    fn precompute(&mut self, y: PublicKey, pi: &[u8], alpha: &[u8]) -> Result<[Vec<u8>; 6], Self::Error> {
        Ok([vec![0], vec![0], vec![0], vec![0], vec![0], vec![0]])
    }
    
    fn expand(&mut self, pi: &[u8]) -> Result<[Vec<u8>; 4], Self::Error> {
        Ok([vec![0], vec![0], vec![0], vec![0]])
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_prove() {
        let x = [0; 32];
        let alpha = [0, 0, 0];

        let proof = DummyVRF.prove(&x, &alpha);
        assert_eq!(proof.unwrap(), vec![0]);
    }

    #[test]
    fn test_verify() {
        let y = [0; 33];
        let pi = [0];
        let alpha = [0, 0, 0];

        assert_eq!(DummyVRF.verify(&y, &pi, &alpha).unwrap(), vec![0]);
    }
    #[test]
    fn test_precompute() {
        let y = [0; 33];
        let pi = [0];
        let alpha = [0, 0, 0];

        assert_eq!(DummyVRF.precompute(&y, &pi, &alpha).unwrap(), [vec![0], vec![0], vec![0], vec![0], vec![0], vec![0]]);
    }
    #[test]
    fn test_expand() {
        let pi = [0; 108];
        assert_eq!(DummyVRF.expand(&pi).unwrap(), [vec![0], vec![0], vec![0], vec![0]]);
    }
}
