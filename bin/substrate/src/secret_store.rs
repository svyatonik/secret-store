use std::sync::Arc;
use parity_crypto::publickey::KeyPair;
use parity_secretstore_primitives::{
	error::Error,
	executor::TokioHandle,
	key_server_key_pair::KeyServerKeyPair,
	key_storage::InMemoryKeyStorage,
};
use parity_secretstore_key_server::{ClusterConfiguration, KeyServerImpl};
use crate::{
	acl_storage::OnChainAclStorage,
	key_server_set::OnChainKeyServerSet,
	substrate_client::Client,
};

/// Start Secret Store key server.
pub fn start(
	executor: TokioHandle,
	key_server_key_pair: Arc<dyn KeyServerKeyPair>,
	listen_port: u16,
	acl_storage: Arc<OnChainAclStorage>,
	key_server_set: Arc<OnChainKeyServerSet>,
) -> Result<Arc<KeyServerImpl>, Error> {
	let key_storage = Arc::new(InMemoryKeyStorage::default());
	let key_server_config = ClusterConfiguration {
		admin_address: None,
		auto_migrate_enabled: true,
	};
	parity_secretstore_key_server::Builder::new()
		.with_self_key_pair(key_server_key_pair)
		.with_acl_storage(acl_storage)
		.with_key_storage(key_storage)
		.with_config(key_server_config)
		.build_for_tcp(
			executor,
			parity_secretstore_key_server::network::tcp::NodeAddress {
				address: "127.0.0.1".into(),
				port: listen_port,
			},
			key_server_set,
		)
}
