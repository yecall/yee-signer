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

use parity_codec::{Compact, Decode, Encode, Input, Output};
use serde::{Deserialize, Serialize};
use serde::export::fmt::Debug;

use crate::{PUBLIC_KEY_LEN, SECRET_KEY_LEN, SIGNATURE_LENGTH};
pub use crate::tx::call::Call;
use crate::tx::serde::SerdeHex;

pub const ADDRESS_LEN: usize = 33;
pub const HASH_LEN: usize = 32;

pub type Public = [u8; PUBLIC_KEY_LEN];
pub type Signature = [u8; SIGNATURE_LENGTH];
pub type Secret = [u8; SECRET_KEY_LEN];
pub type Nonce = u64;
pub type Hash = [u8; HASH_LEN];
pub type BlockNumber = u64;

pub type Key = Bytes;

pub type KeyValue = (Bytes, Bytes);

#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
pub struct AuthorityId(#[serde(with = "SerdeHex")] pub Public);

#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
pub struct AccountId(#[serde(with = "SerdeHex")] pub Public);

#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
pub struct Bytes(#[serde(with = "SerdeHex")] pub Vec<u8>);

#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
pub struct SerdeHash(#[serde(with = "SerdeHex")] pub [u8; 32]);

#[derive(Clone, Serialize, Deserialize)]
pub struct Address(#[serde(with = "SerdeHex")] pub [u8; ADDRESS_LEN]);

impl Debug for Address {
	fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
		write!(f, "Address({:?})", self.0.to_vec())
	}
}

pub struct Transaction {
	pub signature: Option<(Address, Signature, Compact<Nonce>, Era)>,
	pub call: Call,
}

pub fn address_from_public(public_key: &[u8]) -> Address {
	let mut address = [0; ADDRESS_LEN];
	address[0] = 0xff;
	(&mut address[1..]).copy_from_slice(public_key);
	Address(address)
}

pub type Period = u64;
pub type Phase = u64;

#[derive(Debug, PartialEq)]
pub enum Era {
	Immortal,
	Mortal(Period, Phase),
}

impl Era {
	pub fn mortal(period: u64, current: u64) -> Self {
		let period = period.checked_next_power_of_two()
			.unwrap_or(1 << 16)
			.max(4)
			.min(1 << 16);
		let phase = current % period;
		let quantize_factor = (period >> 12).max(1);
		let quantized_phase = phase / quantize_factor * quantize_factor;

		Era::Mortal(period, quantized_phase)
	}

	pub fn immortal() -> Self {
		Era::Immortal
	}

	pub fn is_immortal(&self) -> bool {
		match self {
			Era::Immortal => true,
			_ => false,
		}
	}

	pub fn birth(self, current: u64) -> u64 {
		match self {
			Era::Immortal => 0,
			Era::Mortal(period, phase) => (current.max(phase) - phase) / period * period + phase,
		}
	}

	pub fn death(self, current: u64) -> u64 {
		match self {
			Era::Immortal => u64::max_value(),
			Era::Mortal(period, _) => self.birth(current) + period,
		}
	}
}

impl Encode for Era {
	fn encode_to<T: Output>(&self, output: &mut T) {
		match self {
			Era::Immortal => output.push_byte(0),
			Era::Mortal(period, phase) => {
				let quantize_factor = (*period as u64 >> 12).max(1);
				let encoded = (period.trailing_zeros() - 1).max(1).min(15) as u16 | ((phase / quantize_factor) << 4) as u16;
				output.push(&encoded);
			}
		}
	}
}

impl Decode for Era {
	fn decode<I: Input>(input: &mut I) -> Option<Self> {
		let first = input.read_byte()?;
		if first == 0 {
			Some(Era::Immortal)
		} else {
			let encoded = first as u64 + ((input.read_byte()? as u64) << 8);
			let period = 2 << (encoded % (1 << 4));
			let quantize_factor = (period >> 12).max(1);
			let phase = (encoded >> 4) * quantize_factor;
			if period >= 4 && phase < period {
				Some(Era::Mortal(period, phase))
			} else {
				None
			}
		}
	}
}

impl Encode for Address {
	fn encode_to<W: Output>(&self, dest: &mut W) {
		for item in self.0.iter() {
			dest.push_byte(*item);
		}
	}
}

impl Decode for Address {
	fn decode<I: Input>(input: &mut I) -> Option<Self> {
		let mut buffer = [0u8; ADDRESS_LEN];
		let len = input.read(&mut buffer);
		match len {
			ADDRESS_LEN => Some(Address(buffer)),
			_ => None,
		}
	}
}

const TRANSACTION_VERSION: u8 = 1;

impl Encode for Transaction {
	fn encode_to<W: Output>(&self, dest: &mut W) {
		let mut buffer = Vec::new();
		match self.signature.as_ref() {
			Some(signature) => {
				buffer.push_byte(TRANSACTION_VERSION | 0b1000_0000);
				signature.encode_to(&mut buffer);
			}
			None => {
				buffer.push_byte(TRANSACTION_VERSION & 0b0111_1111);
			}
		}
		self.call.encode_to(&mut buffer);
		buffer.encode_to(dest);
	}
}

impl Decode for Transaction {
	fn decode<I: Input>(input: &mut I) -> Option<Self> {
		let _length_do_not_remove_me_see_above: Vec<()> = Decode::decode(input)?;

		let version = input.read_byte()?;

		let is_signed = version & 0b1000_0000 != 0;
		let version = version & 0b0111_1111;
		if version != TRANSACTION_VERSION {
			return None;
		}

		Some(Transaction {
			signature: if is_signed { Some(Decode::decode(input)?) } else { None },
			call: Decode::decode(input)?,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_address() {
		let public = vec![1u8; PUBLIC_KEY_LEN];
		let address = address_from_public(&public);
		assert_eq!(address.0.to_vec(), vec![255u8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
	}

	#[test]
	fn test_address_encode() {
		let public = vec![1u8; PUBLIC_KEY_LEN];
		let address = address_from_public(&public);
		assert_eq!(address.encode(), address.0.to_vec());
	}

	#[test]
	fn test_era() {
		let a = vec![213u8, 2];
		let era = Era::decode(&mut &a[..]).unwrap();
		assert_eq!(era, Era::Mortal(64, 45));
	}

	#[test]
	fn test_era2() {
		for i in 1..100000 {
			let era = Era::mortal(64, i);
			assert_eq!(era.birth(i), i);
		}
	}
}
