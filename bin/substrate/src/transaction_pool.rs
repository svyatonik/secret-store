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
	///
	sync_futures_pool: futures::executor::ThreadPool,
}

impl SecretStoreTransactionPool {
	////
	pub fn new(client: Client, sync_futures_pool: futures::executor::ThreadPool) -> SecretStoreTransactionPool {
		SecretStoreTransactionPool {
			client,
			sync_futures_pool,
		}
	}
}

impl TransactionPool for SecretStoreTransactionPool {
	type TransactionHash = TransactionHash;

	fn submit_transaction(&self, call: SecretStoreCall) -> Result<Self::TransactionHash, String> {
		let submit_transaction = self.client.submit_transaction(crate::runtime::Call::SecretStore(
			match call {
				SecretStoreCall::ServerKeyGenerated(key_id, key) =>
					node_runtime::SecretStoreCall::server_key_generated(
						key_id,
						key,
					),
				SecretStoreCall::ServerKeyGenerationError(key_id) =>
					node_runtime::SecretStoreCall::server_key_generation_error(
						key_id,
					),
				_ => unreachable!("TODO"),
			}
		));

		futures::executor::block_on(async {
			submit_transaction.await
		}).map_err(|err| format!("{:?}", err))
	}
}
