use parity_secretstore_substrate_service::{
	TransactionPool, SecretStoreCall,
};
use crate::{
	runtime::{TransactionHash},
	substrate_client::Client,
};

///
pub struct SecretStoreTransactionPool {
	/// Substrate node RPC client.
	client: Client,
}

impl SecretStoreTransactionPool {
	////
	pub fn new(client: Client) -> SecretStoreTransactionPool {
		SecretStoreTransactionPool {
			client,
		}
	}
}

impl TransactionPool for SecretStoreTransactionPool {
	type TransactionHash = TransactionHash;

	fn submit_transaction(&self, _call: SecretStoreCall) -> Result<Self::TransactionHash, String> {
		unimplemented!()
	}
}
