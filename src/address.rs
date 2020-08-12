// Copyright 2019, 2020 Wingchain
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bech32::FromBase32;
use bech32::ToBase32;

use crate::external::Vec;
use crate::external::{String, ToString};
use crate::tx::types::Public;
use crate::{SignerResult, PUBLIC_KEY_LEN};

pub fn address_encode(public_key: &[u8], hrp: &str) -> SignerResult<String> {
	validate_hrp(hrp)?;
	validate_public_key(public_key)?;
	let buf = public_key.to_base32();

	let hrp_str: String = hrp.into();
	let address = bech32::encode(&hrp_str, buf).map_err(|_| "bech32 encode error")?;
	Ok(address)
}

pub fn address_decode(address: &str) -> SignerResult<(Public, String)> {
	let (hrp, buf) = bech32::decode(address).map_err(|_| "bech32 decode failed")?;
	validate_hrp(&hrp)?;
	let buf = Vec::from_base32(&buf).map_err(|_| "bech32 decode error")?;
	validate_public_key(&buf)?;
	let mut res = [0u8; PUBLIC_KEY_LEN];
	res.as_mut().copy_from_slice(&buf);

	Ok((res, hrp))
}

fn validate_hrp(hrp: &str) -> SignerResult<()> {
	if hrp == "yee" || hrp == "tyee" {
		Ok(())
	} else {
		Err("invalid address hrp".to_string())
	}
}

fn validate_public_key(public_key: &[u8]) -> SignerResult<()> {
	if public_key.len() != PUBLIC_KEY_LEN {
		Err("invalid public length".to_string())
	} else {
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_address_encode() {
		let public =
			hex::decode("0001020304050607080900010203040506070809000102030405060708090001")
				.unwrap();

		let address = address_encode(&public, "yee").unwrap();

		assert_eq!(
			address,
			"yee1qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsz6e3hh".to_string()
		);

		let address = address_encode(&public, "tyee").unwrap();

		assert_eq!(
			address,
			"tyee1qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqs0a78ky".to_string()
		);
	}

	#[test]
	fn test_address_decode() {
		let address = "yee1qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsz6e3hh";

		let (public_key, hrp) = address_decode(address).unwrap();

		assert_eq!(
			public_key.to_vec(),
			hex::decode("0001020304050607080900010203040506070809000102030405060708090001")
				.unwrap()
		);

		assert_eq!(hrp, "yee".to_string());
	}

	#[test]
	fn test_address_encode_failed() {
		let public =
			hex::decode("000102030405060708090001020304050607080900010203040506070809000102")
				.unwrap();

		let result = address_encode(&public, "yee");

		assert_eq!(result, Err("invalid public length".to_string()));
	}

	#[test]
	fn test_address_decode_failed() {
		let address = "abc1qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsdsk2fh";

		let result = address_decode(address);

		assert_eq!(result, Err("invalid address hrp".to_string()));
	}
}
