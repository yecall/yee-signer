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


use parity_codec::{Compact, Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::tx::serde::SerdeHex;
use crate::tx::types::{Address, Public};

pub const BALANCE: u8 = 0x04;
pub const TRANSFER: u8 = 0x00;

pub const CRFG: u8 = 0x06;
pub const FORCE_UPDATE_AUTHORITIES: u8 = 0x01;

pub const SUDO: u8 = 0x0b;
pub const SUDO_SUDO: u8 = 0x00;
pub const SUDO_SET_KEY: u8 = 0x01;

#[derive(Encode, Decode, Clone, Serialize, Deserialize)]
pub struct AuthorityId(#[serde(with="SerdeHex")] pub Public);

#[derive(Encode, Decode, Clone, Serialize, Deserialize)]
pub struct BalanceTransferParams {
	pub dest: Address,
	pub value: Compact<u128>,
}

#[derive(Encode, Decode, Clone, Serialize, Deserialize)]
pub struct CrfgForceUpdateAuthoritiesParams {
	pub authorities: Vec<(AuthorityId, u64)>,
	pub median: u64,
}

#[derive(Encode, Decode, Clone, Serialize, Deserialize)]
pub struct SudoSudoParams<Call> {
	pub proposal: Call,
}

#[derive(Encode, Decode, Clone, Serialize, Deserialize)]
pub struct SudoSetKeyParams {
	pub addresses: Vec<Address>,
}
