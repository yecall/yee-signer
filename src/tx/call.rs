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


use std::fmt;

use parity_codec::{Compact, Decode, Encode};
use serde::{de, Deserialize, Deserializer, ser::SerializeStruct, Serialize, Serializer};
use serde::de::{MapAccess, SeqAccess, Unexpected, Visitor};

use crate::tx::types::{AccountId, Address, AuthorityId, BlockNumber, Bytes, Key, KeyValue, SerdeHash};

#[derive(Encode, Decode, Clone, Debug)]
pub enum Call {
	Timestamp(timestamp::Call),
	Consensus(consensus::Call),
	Pow(pow::Call),
	Indices(indices::Call),
	Balances(balances::Call),
	Sharding(sharding::Call),
	Crfg(crfg::Call),
	FinalityTracker(finality_tracker::Call),
	Assets(assets::Call),
	Relay(relay::Call),
	Storage(storage::Call),
	Sudo(sudo::Call),
}

impl Serialize for Call {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer {
		match self {
			Call::Timestamp(call) => {
				match call {
					timestamp::Call::Set(call) => serialize_call(serializer, timestamp::MODULE, timestamp::SET, call),
				}
			}
			Call::Consensus(call) => {
				match call {
					consensus::Call::ReportMisbehavior(call) => serialize_call(serializer, consensus::MODULE, consensus::REPORT_MISBEHAVIOR, call),
					consensus::Call::NoteOffline(call) => serialize_call(serializer, consensus::MODULE, consensus::NOTE_OFFLINE, call),
					consensus::Call::Remark(call) => serialize_call(serializer, consensus::MODULE, consensus::REMARK, call),
					consensus::Call::SetHeapPages(call) => serialize_call(serializer, consensus::MODULE, consensus::SET_HEAP_PAGES, call),
					consensus::Call::SetCode(call) => serialize_call(serializer, consensus::MODULE, consensus::SET_CODE, call),
					consensus::Call::SetStorage(call) => serialize_call(serializer, consensus::MODULE, consensus::SET_STORAGE, call),
					consensus::Call::KillStorage(call) => serialize_call(serializer, consensus::MODULE, consensus::KILL_STORAGE, call),
				}
			}
			Call::Pow(call) => {
				match call {
					pow::Call::SetPowInfo(call) => serialize_call(serializer, pow::MODULE, pow::SET_POW_INFO, call),
				}
			}
			Call::Indices(_call) => {
				unreachable!()
			}
			Call::Balances(call) => {
				match call {
					balances::Call::Transfer(call) => serialize_call(serializer, balances::MODULE, balances::TRANSFER, call),
					balances::Call::SetBalance(call) => serialize_call(serializer, balances::MODULE, balances::SET_BALANCE, call),
				}
			}
			Call::Sharding(call) => {
				match call {
					sharding::Call::SetShardInfo(call) => serialize_call(serializer, sharding::MODULE, sharding::SET_SHARD_INFO, call),
				}
			}
			Call::Crfg(call) => {
				match call {
					crfg::Call::UpdateAuthorities(call) => serialize_call(serializer, crfg::MODULE, crfg::UPDATE_AUTHORITIES, call),
					crfg::Call::ForceUpdateAuthorities(call) => serialize_call(serializer, crfg::MODULE, crfg::FORCE_UPDATE_AUTHORITIES, call),
				}
			}
			Call::FinalityTracker(call) => {
				match call {
					finality_tracker::Call::WriteFinalizedLog(call) => serialize_call(serializer, finality_tracker::MODULE, finality_tracker::WRITE_FINALIZED_LOG, call),
				}
			}
			Call::Assets(call) => {
				match call {
					assets::Call::Issue(call) => serialize_call(serializer, assets::MODULE, assets::ISSUE, call),
					assets::Call::Transfer(call) => serialize_call(serializer, assets::MODULE, assets::TRANSFER, call),
				}
			}
			Call::Relay(call) => {
				match call {
					relay::Call::Transfer(call) => serialize_call(serializer, relay::MODULE, relay::TRANSFER, call),
				}
			}
			Call::Storage(call) => {
				match call {
					storage::Call::Store(call) => serialize_call(serializer, storage::MODULE, storage::STORE, call),
				}
			}
			Call::Sudo(call) => {
				match call {
					sudo::Call::Sudo(call) => serialize_call(serializer, sudo::MODULE, sudo::SUDO, call),
					sudo::Call::SetKey(call) => serialize_call(serializer, sudo::MODULE, sudo::SET_KEY, call),
				}
			}
		}
	}
}

impl<'de> Deserialize<'de> for Call {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
		where
			D: Deserializer<'de> {
		enum Field { Module, Method, Params };
		impl<'de> Deserialize<'de> for Field {
			fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
				where
					D: Deserializer<'de>,
			{
				struct FieldVisitor;

				impl<'de> Visitor<'de> for FieldVisitor {
					type Value = Field;

					fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
						formatter.write_str("`module`, `method` or `params`")
					}

					fn visit_str<E>(self, value: &str) -> Result<Field, E>
						where
							E: de::Error,
					{
						match value {
							"module" => Ok(Field::Module),
							"method" => Ok(Field::Method),
							"params" => Ok(Field::Params),
							_ => Err(de::Error::unknown_field(value, FIELDS)),
						}
					}
				}

				deserializer.deserialize_identifier(FieldVisitor)
			}
		}

		struct CallVisitor;

		impl<'de> Visitor<'de> for CallVisitor {
			type Value = Call;

			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				formatter.write_str("struct Call")
			}

			fn visit_seq<V>(self, mut seq: V) -> Result<Call, V::Error>
				where
					V: SeqAccess<'de>,
			{
				let module: u8 = seq.next_element()?
					.ok_or_else(|| de::Error::invalid_length(0, &self))?;
				let method: u8 = seq.next_element()?
					.ok_or_else(|| de::Error::invalid_length(1, &self))?;
				let call = match module {
					timestamp::MODULE => {
						match method {
							timestamp::SET => {
								Call::Timestamp(timestamp::Call::Set(seq_next_element(seq, &self)?))
							}
							unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
						}
					}
					consensus::MODULE => {
						match method {
							consensus::REPORT_MISBEHAVIOR => {
								Call::Consensus(consensus::Call::ReportMisbehavior(seq_next_element(seq, &self)?))
							}
							consensus::NOTE_OFFLINE => {
								Call::Consensus(consensus::Call::NoteOffline(seq_next_element(seq, &self)?))
							}
							consensus::REMARK => {
								Call::Consensus(consensus::Call::Remark(seq_next_element(seq, &self)?))
							}
							consensus::SET_HEAP_PAGES => {
								Call::Consensus(consensus::Call::SetHeapPages(seq_next_element(seq, &self)?))
							}
							consensus::SET_CODE => {
								Call::Consensus(consensus::Call::SetCode(seq_next_element(seq, &self)?))
							}
							consensus::SET_STORAGE => {
								Call::Consensus(consensus::Call::SetStorage(seq_next_element(seq, &self)?))
							}
							consensus::KILL_STORAGE => {
								Call::Consensus(consensus::Call::KillStorage(seq_next_element(seq, &self)?))
							}
							unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
						}
					}
					pow::MODULE => {
						match method {
							pow::SET_POW_INFO => {
								Call::Pow(pow::Call::SetPowInfo(seq_next_element(seq, &self)?))
							}
							unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
						}
					}
					indices::MODULE => {
						return Err(de::Error::invalid_value(Unexpected::Unsigned(indices::MODULE as u64), &self));
					}
					balances::MODULE => {
						match method {
							balances::TRANSFER => {
								Call::Balances(balances::Call::Transfer(seq_next_element(seq, &self)?))
							}
							balances::SET_BALANCE => {
								Call::Balances(balances::Call::SetBalance(seq_next_element(seq, &self)?))
							}
							unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
						}
					}
					sharding::MODULE => {
						match method {
							sharding::SET_SHARD_INFO => {
								Call::Sharding(sharding::Call::SetShardInfo(seq_next_element(seq, &self)?))
							}
							unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
						}
					}
					crfg::MODULE => {
						match method {
							crfg::UPDATE_AUTHORITIES => {
								Call::Crfg(crfg::Call::UpdateAuthorities(seq_next_element(seq, &self)?))
							}
							crfg::FORCE_UPDATE_AUTHORITIES => {
								Call::Crfg(crfg::Call::ForceUpdateAuthorities(seq_next_element(seq, &self)?))
							}
							unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
						}
					}
					finality_tracker::MODULE => {
						match method {
							finality_tracker::WRITE_FINALIZED_LOG => {
								Call::FinalityTracker(finality_tracker::Call::WriteFinalizedLog(seq_next_element(seq, &self)?))
							}
							unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
						}
					}
					assets::MODULE => {
						match method {
							assets::ISSUE => {
								Call::Assets(assets::Call::Issue(seq_next_element(seq, &self)?))
							}
							assets::TRANSFER => {
								Call::Assets(assets::Call::Transfer(seq_next_element(seq, &self)?))
							}
							unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
						}
					}
					relay::MODULE => {
						match method {
							relay::TRANSFER => {
								Call::Relay(relay::Call::Transfer(seq_next_element(seq, &self)?))
							}
							unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
						}
					}
					storage::MODULE => {
						match method {
							storage::STORE => {
								Call::Storage(storage::Call::Store(seq_next_element(seq, &self)?))
							}
							unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
						}
					}
					sudo::MODULE => {
						match method {
							sudo::SUDO => {
								Call::Sudo(sudo::Call::Sudo(seq_next_element(seq, &self)?))
							}
							sudo::SET_KEY => {
								Call::Sudo(sudo::Call::SetKey(seq_next_element(seq, &self)?))
							}
							unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
						}
					}
					unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
				};
				Ok(call)
			}

			fn visit_map<V>(self, mut map: V) -> Result<Call, V::Error>
				where
					V: MapAccess<'de>,
			{
				let mut module = None;
				let mut method = None;
				let mut call = None;
				while let Some(key) = map.next_key()? {
					match key {
						Field::Module => {
							if module.is_some() {
								return Err(de::Error::duplicate_field("module"));
							}
							module = Some(map.next_value()?);
						}
						Field::Method => {
							if method.is_some() {
								return Err(de::Error::duplicate_field("method"));
							}
							method = Some(map.next_value()?);
						}
						Field::Params => {
							if call.is_some() {
								return Err(de::Error::duplicate_field("params"));
							}
							let module = module.ok_or(de::Error::custom("module first"))?;
							let method = method.ok_or(de::Error::custom("method first"))?;
							call = Some(match module {
								timestamp::MODULE => {
									match method {
										timestamp::SET => {
											Call::Timestamp(timestamp::Call::Set(map.next_value()?))
										}
										unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
									}
								}
								consensus::MODULE => {
									match method {
										consensus::REPORT_MISBEHAVIOR => {
											Call::Consensus(consensus::Call::ReportMisbehavior(map.next_value()?))
										}
										consensus::NOTE_OFFLINE => {
											Call::Consensus(consensus::Call::NoteOffline(map.next_value()?))
										}
										consensus::REMARK => {
											Call::Consensus(consensus::Call::Remark(map.next_value()?))
										}
										consensus::SET_HEAP_PAGES => {
											Call::Consensus(consensus::Call::SetHeapPages(map.next_value()?))
										}
										consensus::SET_CODE => {
											Call::Consensus(consensus::Call::SetCode(map.next_value()?))
										}
										consensus::SET_STORAGE => {
											Call::Consensus(consensus::Call::SetStorage(map.next_value()?))
										}
										consensus::KILL_STORAGE => {
											Call::Consensus(consensus::Call::KillStorage(map.next_value()?))
										}
										unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
									}
								}
								pow::MODULE => {
									match method {
										pow::SET_POW_INFO => {
											Call::Pow(pow::Call::SetPowInfo(map.next_value()?))
										}
										unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
									}
								}
								indices::MODULE => {
									return Err(de::Error::invalid_value(Unexpected::Unsigned(indices::MODULE as u64), &self));
								}
								balances::MODULE => {
									match method {
										balances::TRANSFER => {
											Call::Balances(balances::Call::Transfer(map.next_value()?))
										}
										balances::SET_BALANCE => {
											Call::Balances(balances::Call::SetBalance(map.next_value()?))
										}
										unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
									}
								}
								sharding::MODULE => {
									match method {
										sharding::SET_SHARD_INFO => {
											Call::Sharding(sharding::Call::SetShardInfo(map.next_value()?))
										}
										unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
									}
								}
								crfg::MODULE => {
									match method {
										crfg::UPDATE_AUTHORITIES => {
											Call::Crfg(crfg::Call::UpdateAuthorities(map.next_value()?))
										}
										crfg::FORCE_UPDATE_AUTHORITIES => {
											Call::Crfg(crfg::Call::ForceUpdateAuthorities(map.next_value()?))
										}
										unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
									}
								}
								finality_tracker::MODULE => {
									match method {
										finality_tracker::WRITE_FINALIZED_LOG => {
											Call::FinalityTracker(finality_tracker::Call::WriteFinalizedLog(map.next_value()?))
										}
										unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
									}
								}
								assets::MODULE => {
									match method {
										assets::ISSUE => {
											Call::Assets(assets::Call::Issue(map.next_value()?))
										}
										assets::TRANSFER => {
											Call::Assets(assets::Call::Transfer(map.next_value()?))
										}
										unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
									}
								}
								relay::MODULE => {
									match method {
										relay::TRANSFER => {
											Call::Relay(relay::Call::Transfer(map.next_value()?))
										}
										unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
									}
								}
								storage::MODULE => {
									match method {
										storage::STORE => {
											Call::Storage(storage::Call::Store(map.next_value()?))
										}
										unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
									}
								}
								sudo::MODULE => {
									match method {
										sudo::SUDO => {
											Call::Sudo(sudo::Call::Sudo(map.next_value()?))
										}
										sudo::SET_KEY => {
											Call::Sudo(sudo::Call::SetKey(map.next_value()?))
										}
										unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
									}
								}
								unknown => return Err(de::Error::invalid_value(Unexpected::Unsigned(unknown as u64), &self)),
							});
						}
					}
				}
				let call = call.ok_or_else(|| de::Error::missing_field("params"))?;
				Ok(call)
			}
		}

		const FIELDS: &'static [&'static str] = &["module", "method", "params"];
		deserializer.deserialize_struct("Call", FIELDS, CallVisitor)
	}
}

fn serialize_call<S: Serializer, T: Serialize>(serializer: S, module: u8, method: u8, params: &T) -> Result<S::Ok, S::Error> {
	let mut s = serializer.serialize_struct("Call", 3)?;
	s.serialize_field("module", &module)?;
	s.serialize_field("method", &method)?;
	s.serialize_field("params", params)?;
	s.end()
}


fn seq_next_element<'de, SA: SeqAccess<'de>, V: Visitor<'de>, T: Deserialize<'de>>(mut seq: SA, visitor: &V) -> Result<T, SA::Error> {
	let call = seq.next_element()?
		.ok_or_else(|| de::Error::invalid_length(3, visitor))?;
	Ok(call)
}

pub mod timestamp {
	use super::{Compact, Decode, Deserialize, Encode, Serialize};

	pub type Moment = u64;

	pub const MODULE: u8 = 0x00;
	pub const SET: u8 = 0x00;

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub enum Call {
		Set(Set),
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct Set {
		pub now: Compact<Moment>,
	}
}

pub mod consensus {
	use super::{Decode, Deserialize, Encode, Serialize};
	use super::Bytes;
	use super::Key;
	use super::KeyValue;

	pub const MODULE: u8 = 0x01;
	pub const REPORT_MISBEHAVIOR: u8 = 0x00;
	pub const NOTE_OFFLINE: u8 = 0x01;
	pub const REMARK: u8 = 0x02;
	pub const SET_HEAP_PAGES: u8 = 0x03;
	pub const SET_CODE: u8 = 0x04;
	pub const SET_STORAGE: u8 = 0x05;
	pub const KILL_STORAGE: u8 = 0x06;

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub enum Call {
		ReportMisbehavior(ReportMisbehavior),
		NoteOffline(NoteOffline),
		Remark(Remark),
		SetHeapPages(SetHeapPages),
		SetCode(SetCode),
		SetStorage(SetStorage),
		KillStorage(KillStorage),
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct ReportMisbehavior {
		pub report: Bytes,
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct NoteOffline {
		pub offline: (),
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct Remark {
		pub remark: Bytes,
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct SetHeapPages {
		pub pages: u64,
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct SetCode {
		pub new: Bytes,
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct SetStorage {
		pub items: Vec<KeyValue>,
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct KillStorage {
		pub keys: Vec<Key>,
	}
}

pub mod pow {
	use super::{Decode, Deserialize, Encode, Serialize};
	use super::AccountId;

	pub const MODULE: u8 = 0x02;

	pub const SET_POW_INFO: u8 = 0x00;

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub enum Call {
		SetPowInfo(SetPowInfo),
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct SetPowInfo {
		pub info: PowInfo,
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct PowInfo {
		pub coinbase: AccountId,
		pub reward_condition: RewardCondition,
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub enum RewardCondition {
		Normal,
		Slash,
	}
}

pub mod indices {
	use super::{Decode, Deserialize, Encode, Serialize};

	pub const MODULE: u8 = 0x03;

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub enum Call {}
}

pub mod balances {
	use super::{Compact, Decode, Deserialize, Encode, Serialize};
	use super::Address;

	pub const MODULE: u8 = 0x04;

	pub const TRANSFER: u8 = 0x00;
	pub const SET_BALANCE: u8 = 0x01;

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub enum Call {
		Transfer(Transfer),
		SetBalance(SetBalance),
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct Transfer {
		pub dest: Address,
		pub value: Compact<u128>,
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct SetBalance {
		pub who: Address,
		pub free: Compact<u128>,
		pub reserved: Compact<u128>,
	}
}

pub mod sharding {
	use super::{Decode, Deserialize, Encode, Serialize};

	pub const MODULE: u8 = 0x05;
	pub const SET_SHARD_INFO: u8 = 0x00;

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub enum Call {
		SetShardInfo(SetShardInfo),
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct SetShardInfo {
		pub info: ShardInfo,
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct ShardInfo {
		pub num: u16,
		pub count: u16,
		pub scale_out: Option<ScaleOut>,
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct ScaleOut {
		pub shard_num: u16,
	}
}

pub mod crfg {
	use super::{Decode, Deserialize, Encode, Serialize};
	use super::AuthorityId;

	pub const MODULE: u8 = 0x06;

	pub const UPDATE_AUTHORITIES: u8 = 0x00;
	pub const FORCE_UPDATE_AUTHORITIES: u8 = 0x01;

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub enum Call {
		UpdateAuthorities(UpdateAuthorities),
		ForceUpdateAuthorities(ForceUpdateAuthorities),
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct UpdateAuthorities {
		pub info: AuthorityId,
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct ForceUpdateAuthorities {
		pub authorities: Vec<(AuthorityId, u64)>,
		pub median: u64,
	}
}


pub mod finality_tracker {
	use super::{Decode, Deserialize, Encode, Serialize};
	use super::BlockNumber;

	pub const MODULE: u8 = 0x07;

	pub const WRITE_FINALIZED_LOG: u8 = 0x00;

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub enum Call {
		WriteFinalizedLog(WriteFinalizedLog),
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct WriteFinalizedLog {
		pub hint: BlockNumber,
	}
}

pub mod assets {
	use super::{Compact, Decode, Deserialize, Encode, Serialize};
	use super::Address;
	use super::Bytes;

	pub const MODULE: u8 = 0x08;

	pub const ISSUE: u8 = 0x00;
	pub const TRANSFER: u8 = 0x01;

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub enum Call {
		Issue(Issue),
		Transfer(Transfer),
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct Issue {
		pub name: Bytes,
		pub total: Compact<u128>,
		pub decimals: Compact<u16>,
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct Transfer {
		pub shard_code: Bytes,
		pub id: Compact<u32>,
		pub target: Address,
		pub amount: Compact<u128>,
	}
}

pub mod relay {
	use super::{Compact, Decode, Deserialize, Encode, Serialize};
	use super::Bytes;
	use super::SerdeHash;

	pub const MODULE: u8 = 0x09;
	pub const TRANSFER: u8 = 0x00;

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub enum Call {
		Transfer(Transfer),
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct Transfer {
		pub relay_type: RelayTypes,
		pub tx: Bytes,
		pub number: Compact<u64>,
		pub hash: SerdeHash,
		pub parent: SerdeHash,
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub enum RelayTypes {
		Balance,
		Assets,
	}
}

pub mod storage {
	use super::{Decode, Deserialize, Encode, Serialize};
	use super::Bytes;

	pub const MODULE: u8 = 0x0a;

	pub const STORE: u8 = 0x00;

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub enum Call {
		Store(Store),
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct Store {
		pub data: Bytes,
	}
}

pub mod sudo {
	use super::{Decode, Deserialize, Encode, Serialize};
	use super::Address;
	use super::Call as UniversalCall;

	pub const MODULE: u8 = 0x0b;
	pub const SUDO: u8 = 0x00;
	pub const SET_KEY: u8 = 0x01;

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub enum Call {
		Sudo(Sudo),
		SetKey(SetKey),
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct Sudo {
		pub proposal: Box<UniversalCall>,
	}

	#[derive(Encode, Decode, Clone, Debug, Serialize, Deserialize)]
	pub struct SetKey {
		pub addresses: Vec<Address>,
	}
}


#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_call_serde() {
		let call = Call::Timestamp(timestamp::Call::Set(timestamp::Set {
			now: Compact(12),
		}));

		let call = Call::Sudo(sudo::Call::Sudo(sudo::Sudo {
			proposal: Box::new(call),
		}));

		let call = serde_json::to_string_pretty(&call).unwrap();

		assert_eq!(call, r#"{
  "module": 11,
  "method": 0,
  "params": {
    "proposal": {
      "module": 0,
      "method": 0,
      "params": {
        "now": 12
      }
    }
  }
}"#);

		let call: Call = serde_json::from_str(&call).unwrap();

		let now = match call {
			Call::Sudo(sudo::Call::Sudo(sudo::Sudo { proposal })) => match *proposal {
				Call::Timestamp(timestamp::Call::Set(timestamp::Set { now })) => now.0,
				_ => unreachable!()
			},
			_ => unreachable!(),
		};
		assert_eq!(now, 12);
	}
}