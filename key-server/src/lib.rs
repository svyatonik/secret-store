// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

mod key_server_cluster;
mod types;

mod traits;
mod key_server;
mod serialization;
mod blockchain;
mod migration;
mod network;

use std::sync::Arc;
use parity_runtime::Executor;

pub use crate::network::{ConnectionProvider, ConnectionManager, Connection};
pub use crate::types::{ServerKeyId, EncryptedDocumentKey, RequestSignature, Public,
	Error, NodeAddress, ClusterConfiguration};
pub use crate::traits::KeyServer;
pub use crate::blockchain::{SecretStoreChain, ContractAddress, BlockId, BlockNumber, NewBlocksNotify, Filter};
pub use key_server_cluster::message::Message;
use parity_secretstore_primitives::{
	acl_storage::AclStorage,
	key_server_set::KeyServerSet,
	key_storage::KeyStorage,
};

/// Start new key server instance
pub fn start<NetworkAddress: Clone + Send + Sync + 'static>(
	self_key_pair: Arc<dyn parity_secretstore_primitives::key_server_key_pair::KeyServerKeyPair>,
	config: ClusterConfiguration,
	executor: Executor,
	acl_storage: Arc<dyn AclStorage>,
	key_server_set: Arc<dyn KeyServerSet<NetworkAddress=NetworkAddress>>,
	key_storage: Arc<dyn KeyStorage>,
	connection_manager: Arc<dyn ConnectionManager>,
	connection_provider: Arc<dyn ConnectionProvider>,
) -> Result<Arc<key_server::KeyServerImpl>, Error> {
	let cluster = crate::key_server_cluster::new_cluster_client(
		crate::key_server_cluster::ClusterConfiguration {
			self_key_pair,
			key_server_set,
			key_storage: key_storage.clone(),
			acl_storage: acl_storage.clone(),
			admin_address: config.admin_address,
			auto_migrate_enabled: config.auto_migrate_enabled,
			preserve_sessions: false,
		},
		connection_manager,
		connection_provider,
	)?;
	cluster.run()?;

	let key_server = Arc::new(key_server::KeyServerImpl::new(cluster.client(), acl_storage, key_storage)?);

	Ok(key_server)
}
