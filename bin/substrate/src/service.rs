use std::{
	sync::Arc,
	time::Duration,
};
use futures::Stream;
use parity_secretstore_substrate_service::{Configuration, start_service};
use parity_secretstore_key_server::KeyServerImpl;
use parity_secretstore_primitives::{
	error::Error,
	executor::TokioHandle,
	key_server_key_pair::KeyServerKeyPair,
	key_storage::InMemoryKeyStorage,
};
use crate::{
	blockchain::SecretStoreBlockchain,
	key_server_set::OnChainKeyServerSet,
	substrate_client::Client,
	transaction_pool::SecretStoreTransactionPool,
};

pub fn start(
	blockchain: Arc<SecretStoreBlockchain>,
	transaction_pool: Arc<SecretStoreTransactionPool>,
	executor: TokioHandle,
	key_server: Arc<KeyServerImpl>,
	key_storage: Arc<InMemoryKeyStorage>,
	key_server_set: Arc<OnChainKeyServerSet>,
	key_server_key_pair: Arc<KeyServerKeyPair>,
	new_blocks_stream: impl Stream<Item = crate::runtime::BlockHash> + Send + 'static,
) -> Result<(), Error> {
	let listener_registrar = key_server.cluster().session_listener_registrar();
	start_service(
		key_server,
		key_storage,
		listener_registrar,
		blockchain,
		Arc::new(executor),
		transaction_pool,
		Configuration {
			self_id: key_server_key_pair.address(),
			max_active_sessions: Some(4),
			pending_restart_interval: Some(Duration::from_secs(10 * 60)),
		},
		new_blocks_stream,
	)
}
