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
pub mod network;

use std::sync::Arc;

pub use crate::network::{ConnectionProvider, ConnectionManager, Connection};
pub use crate::types::{ServerKeyId, EncryptedDocumentKey, RequestSignature, Public,
	Error, NodeAddress, ClusterConfiguration};
pub use crate::key_server::KeyServerImpl;
pub use crate::traits::KeyServer;
pub use crate::blockchain::{SecretStoreChain, ContractAddress, BlockId, BlockNumber, NewBlocksNotify, Filter};
pub use key_server_cluster::message::Message;
use parity_secretstore_primitives::{
	acl_storage::AclStorage,
	executor::TokioHandle,
	key_server_set::KeyServerSet,
	key_storage::KeyStorage,
	key_server_key_pair::KeyServerKeyPair,
};

/// 
pub struct Builder {
	self_key_pair: Option<Arc<dyn KeyServerKeyPair>>,
	acl_storage: Option<Arc<dyn AclStorage>>,
	key_storage: Option<Arc<dyn KeyStorage>>,
	config: Option<ClusterConfiguration>,
}

impl Builder {
	pub fn new() -> Self {
		Builder {
			self_key_pair: None,
			acl_storage: None,
			key_storage: None,
			config: None,
		}
	}

	pub fn with_self_key_pair(mut self, self_key_pair: Arc<dyn KeyServerKeyPair>) -> Self {
		self.self_key_pair = Some(self_key_pair);
		self
	}
	
	pub fn with_acl_storage(mut self, acl_storage: Arc<dyn AclStorage>) -> Self {
		self.acl_storage = Some(acl_storage);
		self
	}

	pub fn with_key_storage(mut self, key_storage: Arc<dyn KeyStorage>) -> Self {
		self.key_storage = Some(key_storage);
		self
	}

	pub fn with_config(mut self, config: ClusterConfiguration) -> Self {
		self.config = Some(config);
		self
	}

	pub fn build_for_tcp(
		self,
		executor: TokioHandle,
		listen_address: crate::network::tcp::NodeAddress,
		key_server_set: Arc<dyn KeyServerSet<NetworkAddress=std::net::SocketAddr>>,
	) -> Result<Arc<KeyServerImpl>, Error> {
		let self_key_pair = self.self_key_pair.ok_or_else(|| Error::Internal("Invalid initialization".into()))?;
		let acl_storage = self.acl_storage.ok_or_else(|| Error::Internal("Invalid initialization".into()))?;
		let key_storage = self.key_storage.ok_or_else(|| Error::Internal("Invalid initialization".into()))?;
		let config = self.config.ok_or_else(|| Error::Internal("Invalid initialization".into()))?;

		let connection_trigger: Box<dyn crate::key_server_cluster::connection_trigger::ConnectionTrigger<std::net::SocketAddr>> = match config.auto_migrate_enabled {
			false => Box::new(crate::key_server_cluster::connection_trigger::SimpleConnectionTrigger::new(
				key_server_set.clone(),
				config.admin_address,
			)),
			true if config.admin_address.is_none() => Box::new(crate::key_server_cluster::connection_trigger_with_migration::ConnectionTriggerWithMigration::new(
				key_server_set.clone(),
				self_key_pair.clone(),
			)),
			true => return Err(Error::Internal(
				"secret store admininstrator address key is specified with auto-migration enabled".into()
			)),
		};
		let servers_set_change_creator_connector = connection_trigger.servers_set_change_creator_connector();
		let sessions = Arc::new(crate::key_server_cluster::cluster_sessions::ClusterSessions::new(
			self_key_pair.address(),
			config.admin_address,
			key_storage.clone(),
			acl_storage.clone(),
			servers_set_change_creator_connector.clone(),
		));

		let mut nodes = key_server_set.snapshot().current_set;
		let is_isolated = nodes.remove(&self_key_pair.address()).is_none();
		let connection_provider = Arc::new(crate::network::tcp::NetConnectionsContainer::new(is_isolated, nodes));
		let message_processor = Arc::new(crate::key_server_cluster::cluster_message_processor::SessionsMessageProcessor::new(
			self_key_pair.clone(),
			servers_set_change_creator_connector.clone(),
			sessions.clone(),
			connection_provider.clone(),
		));
		let connection_manager = Arc::new(crate::network::tcp::NetConnectionsManager::new(
			executor,
			message_processor.clone(),
			connection_trigger,
			connection_provider,
			listen_address,
			self_key_pair.clone(),
			false,
		)?);
		connection_manager.start()?;
		let cluster = crate::key_server_cluster::cluster::ClusterCore::new(
			sessions,
			message_processor,
			connection_manager,
			servers_set_change_creator_connector,
			crate::key_server_cluster::cluster::ClusterConfiguration {
				acl_storage: acl_storage.clone(),
				admin_address: config.admin_address,
				auto_migrate_enabled: true,
				key_server_set: key_server_set.clone(),
				key_storage: key_storage.clone(),
				preserve_sessions: false,
				self_key_pair: self_key_pair.clone(),
			},
		)?;
		cluster.run()?;

		key_server::KeyServerImpl::new(
			cluster.client(),
			acl_storage,
			key_storage,
		).map(|key_server| Arc::new(key_server))
	}
}
