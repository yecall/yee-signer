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

use jni::JNIEnv;
use jni::sys::jbyteArray;
use crate::SignerResult;
use std::os::raw::c_uint;

pub fn error_result_jni<R, T>(run: R, default: T, env: &JNIEnv, error: jbyteArray) -> T
	where R: Fn() -> SignerResult<T>,
{
	match run() {
		Ok(r) => r,
		Err(e) => {
			let _r = env.set_byte_array_region(error, 0, &[error_code(&e)]);
			default
		}
	}
}

pub fn error_result_ffi<R, T>(run: R, default: T, err: *mut c_uint) -> T
	where R: Fn() -> SignerResult<T>,
{
	match run() {
		Ok(r) => r,
		Err(e) => {
			unsafe { *err = error_code(&e) as c_uint };
			default
		}
	}
}

pub fn error_code(error: &str) -> i8 {
	match error {
		"invalid mini secret key" => 2,
		"invalid secret key" => 3,
		"invalid public key" => 4,
		"invalid signature" => 5,
		"jni error" => 6,
		"invalid method" => 7,
		"invalid tx" => 8,
		"invalid json" => 9,
		_ => 1,
	}
}