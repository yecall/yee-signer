// Copyright (C) 2019 Yee Foundation.
//
// This file is part of YeeChain.
//
// YeeChain is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// YeeChain is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with YeeChain.  If not, see <https://www.gnu.org/licenses/>.

pub mod ffi;
pub mod jni;

use schnorrkel::{PublicKey, MiniSecretKey, ExpansionMode, SecretKey};
use schnorrkel::Keypair as SrKeyPair;

pub struct KeyPair(SrKeyPair);

pub struct Verifier(PublicKey);

pub type SignerResult<T> = Result<T, String>;

pub const PUBLIC_KEY_LEN: usize = 32;

pub const SECRET_KEY_LEN: usize = 64;

pub const SIGNATURE_LENGTH: usize = 64;

impl KeyPair {
	pub fn from_mini_secret_key(bytes: &[u8]) -> SignerResult<Self> {
		let key = MiniSecretKey::from_bytes(bytes).map_err(|_| "invalid mini secret key")?;
		let key_pair = key.expand_to_keypair(ExpansionMode::Ed25519);
		Ok(Self(key_pair))
	}

	pub fn from_secret_key(bytes: &[u8]) -> SignerResult<Self> {
		let key = SecretKey::from_bytes(bytes).map_err(|_| "invalid secret key")?;
		let key_pair = SrKeyPair::from(key);
		Ok(Self(key_pair))
	}

	pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
		self.0.public.to_bytes()
	}

	pub fn secret_key(&self) -> [u8; SECRET_KEY_LEN] {
		self.0.secret.to_bytes()
	}

	pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LENGTH] {
		let signature = self.0.sign_simple(&[], &message);
		signature.to_bytes()
	}
}

impl Verifier {
	pub fn from_public_key(bytes: &[u8]) -> SignerResult<Self> {
		let public_key = PublicKey::from_bytes(bytes).map_err(|_| "invalid public key")?;
		let verifier = Verifier(public_key);
		Ok(verifier)
	}

	pub fn verify(&self, signature: &[u8], message: &[u8]) -> SignerResult<()> {
		let signature = schnorrkel::Signature::from_bytes(&signature).map_err(|_| "invalid signature")?;

		let result = self.0
			.verify_simple(&[], &message, &signature)
			.map_err(|_| "invalid signature")?;

		Ok(result)
	}
}


#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_from_mini_secret_key() {
		let mini_secret_key = hex::decode("579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43ae").unwrap();

		let key_pair = KeyPair::from_mini_secret_key(&mini_secret_key).unwrap();

		let public_key = key_pair.public_key();

		assert_eq!(hex::encode(&public_key), "4ef0125fab173ceb93ce4c2a97e6824396240101b9c7220e3fd63e3a2282cf20");

		let secret_key = key_pair.secret_key();

		assert_eq!(hex::encode(&secret_key[..]), "bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b");
	}

	#[test]
	fn test_from_secret_key() {
		let secret_key = hex::decode("bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b").unwrap();

		let key_pair = KeyPair::from_secret_key(&secret_key).unwrap();

		let public_key = key_pair.public_key();

		assert_eq!(hex::encode(&public_key), "4ef0125fab173ceb93ce4c2a97e6824396240101b9c7220e3fd63e3a2282cf20");

		let secret_key = key_pair.secret_key();

		assert_eq!(hex::encode(&secret_key[..]), "bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b");
	}

	#[test]
	fn test_sign_verify() {
		let mini_secret_key = hex::decode("579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43ae").unwrap();

		let key_pair = KeyPair::from_mini_secret_key(&mini_secret_key).unwrap();

		let message = vec![1, 2, 3];
		let signature = key_pair.sign(&message);

		let verifier = Verifier::from_public_key(&key_pair.public_key()).unwrap();
		verifier.verify(&signature, &message).unwrap();
	}
}
