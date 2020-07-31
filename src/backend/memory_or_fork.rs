use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use primitive_types::{H160, H256, U256};
use sha3::{Digest, Keccak256};
use super::{Basic, Backend, ApplyBackend, Apply, Log};
use super::MemoryVicinity;
use ethers::providers::{Provider, Http};
use futures::executor::block_on;
use std::convert::TryFrom;
use ethers::types::BlockNumber;

/// Account information of a memory backend.
#[derive(Default, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ForkMemoryAccount {
	/// Account nonce.
	pub nonce: Option<U256>,
	/// Account balance.
	pub balance: Option<U256>,
	/// Full account storage.
	pub storage: Option<BTreeMap<H256, H256>>,
	/// Account code.
	pub code: Option<Vec<u8>>,
}


/// Memory backend, storing all state values in a `BTreeMap` in memory.
#[derive(Clone, Debug)]
pub struct ForkMemoryBackend<'vicinity> {
	vicinity: &'vicinity MemoryVicinity,
	state: BTreeMap<H160, ForkMemoryAccount>,
	logs: Vec<Log>,
	provider: Provider<Http>,
	block: Option<BlockNumber>
}

impl<'vicinity> ForkMemoryBackend<'vicinity> {
	/// Create a new memory backend.
	pub fn new(vicinity: &'vicinity MemoryVicinity, state: BTreeMap<H160, ForkMemoryAccount>, provider: String, bn: Option<BlockNumber>) -> Self {
		Self {
			vicinity,
			state,
			logs: Vec::new(),
			provider: Provider::<Http>::try_from(provider).expect("Could not connect to HTTP Provider"),
			block: bn,
		}
	}

	/// Get the underlying `BTreeMap` storing the state.
	pub fn state(&self) -> &BTreeMap<H160, ForkMemoryAccount> {
		&self.state
	}
}

impl<'vicinity> Backend for ForkMemoryBackend<'vicinity> {
	fn gas_price(&self) -> U256 { self.vicinity.gas_price }
	fn origin(&self) -> H160 { self.vicinity.origin }
	fn block_hash(&self, number: U256) -> H256 {
		if number >= self.vicinity.block_number ||
			self.vicinity.block_number - number - U256::one() >= U256::from(self.vicinity.block_hashes.len())
		{
			H256::default()
		} else {
			let index = (self.vicinity.block_number - number - U256::one()).as_usize();
			self.vicinity.block_hashes[index]
		}
	}
	fn block_number(&self) -> U256 { self.vicinity.block_number }
	fn block_coinbase(&self) -> H160 { self.vicinity.block_coinbase }
	fn block_timestamp(&self) -> U256 { self.vicinity.block_timestamp }
	fn block_difficulty(&self) -> U256 { self.vicinity.block_difficulty }
	fn block_gas_limit(&self) -> U256 { self.vicinity.block_gas_limit }

	fn chain_id(&self) -> U256 { self.vicinity.chain_id }

	fn exists(&self, address: H160) -> bool {
		self.state.contains_key(&address)
	}

	fn basic(&self, address: H160) -> Basic {
		let mut account;
		if let Some(acct) = self.state.get(&address) {
			account = acct.clone();
		} else {
			account = ForkMemoryAccount {
				balance: Some(block_on(
								self.provider.get_balance(address, self.block)
							).expect(&format!("Could not get balance for account: {:} from state or node", address))),
				nonce: Some(block_on(
						self.provider.get_transaction_count(address, self.block)
					).expect(&format!("Could not get nonce for account: {:} from state or node", address))),
				storage: None,
				code: None,
			}
		};

		let mut b = Basic {
			balance: U256::zero(),
			nonce: U256::zero(),
		};
		if let Some(balance) = account.balance {
			b.balance = balance;
		} else {
			account.balance = Some(block_on(
				self.provider.get_balance(address, self.block)
			).expect(&format!("Could not get balance for account: {:} from state or node", address)));
			b.balance = account.balance.unwrap();
		}

		if let Some(nonce) = account.nonce {
			b.nonce = nonce;
		} else {
			account.nonce = Some(block_on(
				self.provider.get_transaction_count(address, self.block)
			).expect(&format!("Could not get nonce for account: {:} from state or node", address)));
			b.nonce = account.nonce.unwrap();
		}
		b
	}

	fn code_hash(&self, address: H160) -> H256 {
		let mut account;
		if let Some(acct) = self.state.get(&address) {
			account = acct.clone();
		} else {
			account = ForkMemoryAccount {
				balance: None,
				nonce: None,
				storage: None,
				code: Some(block_on(self.provider.get_code(address, self.block))
					.expect(&format!("Could not get code for {:?}", address))
					.as_ref()
					.to_vec()),
			};
		};

		let code;
		if let Some(acct_code) = account.code.clone() {
			code = acct_code;
		} else {
			account.code = Some(block_on(self.provider.get_code(address, self.block))
				.expect(&format!("Could not get code for {:?}", address))
				.as_ref()
				.to_vec());
			code = account.code.clone().unwrap();
		}
		H256::from_slice(Keccak256::digest(&code).as_slice())
	}

	fn code_size(&self, address: H160) -> usize {
		let mut account;
		if let Some(acct) = self.state.get(&address) {
			account = acct.clone();
		} else {
			account = ForkMemoryAccount {
				balance: None,
				nonce: None,
				storage: None,
				code: Some(block_on(self.provider.get_code(address, self.block))
					.expect(&format!("Could not get code for {:?}", address))
					.as_ref()
					.to_vec()),
			};
		};

		let code;
		if let Some(acct_code) = account.code.clone() {
			code = acct_code;
		} else {
			account.code = Some(block_on(self.provider.get_code(address, self.block))
				.expect(&format!("Could not get code for {:?}", address))
				.as_ref()
				.to_vec());
			code = account.code.clone().unwrap();
		}
		code.len()
	}

	fn code(&self, address: H160) -> Vec<u8> {
		let mut account;
		if let Some(acct) = self.state.get(&address) {
			account = acct.clone();
		} else {
			account = ForkMemoryAccount {
				balance: None,
				nonce: None,
				storage: None,
				code: Some(block_on(self.provider.get_code(address, self.block))
					.expect(&format!("Could not get code for {:?}", address))
					.as_ref()
					.to_vec()),
			};
		};

		let code;
		if let Some(acct_code) = account.code.clone() {
			code = acct_code;
		} else {
			account.code = Some(block_on(self.provider.get_code(address, self.block))
				.expect(&format!("Could not get code for {:?}", address))
				.as_ref()
				.to_vec());
			code = account.code.clone().unwrap();
		}
		code
	}

	fn storage(&self, address: H160, index: H256) -> H256 {
		let mut account;
		if let Some(acct) = self.state.get(&address) {
			account = acct.clone();
		} else {
			account = ForkMemoryAccount {
				balance: None,
				nonce: None,
				storage: Some(BTreeMap::new()),
				code: None,
			};
		};

		let mut storage: BTreeMap<H256, H256> = BTreeMap::new();
		let val;
		if let Some(mut acct_storage) = account.storage.clone() {
			val = acct_storage.entry(index).or_insert(
				block_on(self.provider.get_storage_at(address, index, None)).expect("Could not get slot for address")
			).clone();
			storage = acct_storage;
		} else {
			val = storage.entry(index).or_insert({
				block_on(self.provider.get_storage_at(address, index, None)).expect("Could not get slot for address")
			}).clone();
		}
		account.storage = Some(storage);
		val
	}
}

impl<'vicinity> ApplyBackend for ForkMemoryBackend<'vicinity> {
	fn apply<A, I, L>(
		&mut self,
		values: A,
		logs: L,
		delete_empty: bool,
	) where
		A: IntoIterator<Item=Apply<I>>,
		I: IntoIterator<Item=(H256, H256)>,
		L: IntoIterator<Item=Log>,
	{
		for apply in values {
			match apply {
				Apply::Modify {
					address, basic, code, storage, reset_storage,
				} => {
					let is_empty = {
						let account = self.state.entry(address).or_insert(Default::default());
						account.balance = Some(basic.balance);
						account.nonce = Some(basic.nonce);
						if let Some(code) = code {
							account.code = Some(code);
						}

						if reset_storage {
							account.storage = None;
						}

						let zeros: BTreeMap<_, _> = account.storage.clone().unwrap_or(BTreeMap::new()).into_iter()
							.filter(|(_, v)| v != &H256::default())
							.collect();

						account.storage = Some(zeros);

						let mut s = account.storage.clone().expect("no storage");

						for (index, value) in storage {
							if value == H256::default() {
								s.remove(&index);
							} else {
								s.insert(index, value);
							}
						}

						account.storage = Some(s);

						account.balance == None &&
							account.nonce == None &&
							account.code == None
					};

					if is_empty && delete_empty {
						self.state.remove(&address);
					}
				},
				Apply::Delete {
					address,
				} => {
					self.state.remove(&address);
				},
			}
		}

		for log in logs {
			self.logs.push(log);
		}
	}
}
