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

use serde::export::fmt::Display;
use serde::{Deserializer, Serializer};

use crate::external::String;
use crate::external::ToOwned;
use crate::external::Vec;

pub trait SerdeHex: Sized {
	type Error: Display;

	fn into_bytes(&self) -> Result<Vec<u8>, Self::Error>;

	fn from_bytes(src: &[u8]) -> Result<Self, Self::Error>;

	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		use serde::ser::Error;
		let bytes = self.into_bytes().map_err(S::Error::custom)?;

		impl_serde::serialize::serialize(bytes.as_slice(), serializer)
	}

	/// Attempt to deserialize a hexadecimal string into an instance of `Self`.
	fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		use serde::de::Error;

		let bytes = impl_serde::serialize::deserialize(deserializer)?;

		Self::from_bytes(bytes.as_slice()).map_err(D::Error::custom)
	}
}

impl SerdeHex for [u8; 33] {
	type Error = String;

	fn into_bytes(&self) -> Result<Vec<u8>, Self::Error> {
		Ok(self.to_vec())
	}

	fn from_bytes(src: &[u8]) -> Result<Self, Self::Error> {
		let mut v = [0u8; 33];
		v.copy_from_slice(src);
		Ok(v)
	}
}

impl SerdeHex for [u8; 32] {
	type Error = String;

	fn into_bytes(&self) -> Result<Vec<u8>, Self::Error> {
		Ok(self.to_vec())
	}

	fn from_bytes(src: &[u8]) -> Result<Self, Self::Error> {
		let mut v = [0u8; 32];
		v.copy_from_slice(src);
		Ok(v)
	}
}

impl SerdeHex for Vec<u8> {
	type Error = String;

	fn into_bytes(&self) -> Result<Vec<u8>, Self::Error> {
		Ok(self.to_owned())
	}

	fn from_bytes(src: &[u8]) -> Result<Self, Self::Error> {
		Ok(src.to_vec())
	}
}
