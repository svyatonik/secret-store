// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

pub use parity_secretstore_primitives::connections::*;

/*use std::collections::BTreeSet;
use std::sync::Arc;
use crate::key_server_cluster::{Error, NodeId};
use crate::key_server_cluster::message::Message;

/// Connection to the single node. Provides basic information about connected node and
/// allows sending messages to this node.
pub trait Connection: Send + Sync {
	/// Is this inbound connection? This only matters when both nodes are simultaneously establishing
	/// two connections to each other. The agreement is that the inbound connection from the node with
	/// lower NodeId is used and the other connection is closed.
	fn is_inbound(&self) -> bool;
	/// Returns id of the connected node.
	fn node_id(&self) -> &NodeId;
	/// Returns 'address' of the node to use in traces.
	fn node_address(&self) -> String;
	/// Send message to the connected node.
	fn send_message(&self, message: Message);
}

/// Connections manager. Responsible for keeping us connected to all required nodes.
pub trait ConnectionManager: 'static + Send + Sync {
	/// Returns shared reference to connections provider.
	fn provider(&self) -> Arc<dyn ConnectionProvider>;
	/// Try to reach all disconnected nodes immediately. This method is exposed mostly for
	/// tests, where all 'nodes' are starting listening for incoming connections first and
	/// only after this, they're actually start connecting to each other.
	fn connect(&self);
}

/// Connections provider. Holds all active connections and the set of nodes that we need to
/// connect to. At any moment connection could be lost and the set of connected/disconnected
/// nodes could change (at behalf of the connection manager).
/// Clone operation should be cheap (Arc).
pub trait ConnectionProvider: Send + Sync {
	/// Returns the set of currently connected nodes. Error is returned when our node is
	/// not a part of the cluster ('isolated' node).
	fn connected_nodes(&self) -> Result<BTreeSet<NodeId>, Error>;
	/// Returns the set of currently disconnected nodes.
	fn disconnected_nodes(&self) -> BTreeSet<NodeId>;
	/// Returns the reference to the active node connection or None if the node is not connected.
	fn connection(&self, node: &NodeId) -> Option<Arc<dyn Connection>>;
}
*/
#[cfg(test)]
pub mod tests {
	use std::collections::{BTreeSet, VecDeque};
	use std::sync::Arc;
	use std::sync::atomic::{AtomicBool, Ordering};
	use parking_lot::Mutex;
	use crate::key_server_cluster::{Error, NodeId};
	use crate::key_server_cluster::message::Message;
	use super::{ConnectionManager, Connection, ConnectionProvider};
	use crate::key_server_cluster::io::{deserialize_message, deserialize_header};

	/// Shared messages queue.
	pub type MessagesQueue = Arc<Mutex<VecDeque<(NodeId, NodeId, Message)>>>;

	/// Single node connections.
	pub struct TestConnections {
		core: Arc<Mutex<TestConnectionsData>>,
	}

	pub struct TestConnectionsManager {
		core: Arc<Mutex<TestConnectionsData>>,
	}

	pub struct TestConnectionsData {
		node: NodeId,
		is_isolated: bool,
		connected_nodes: BTreeSet<NodeId>,
		disconnected_nodes: BTreeSet<NodeId>,
		messages: MessagesQueue,
	}

	/// Single connection.
	pub struct TestConnection {
		from: NodeId,
		to: NodeId,
		messages: MessagesQueue,
	}

	impl TestConnections {
		pub fn manager(&self) -> Arc<TestConnectionsManager> {
			Arc::new(TestConnectionsManager { core: self.core.clone() })
		}
	}

	impl TestConnectionsManager {
		pub fn isolate(&self) {
			let mut core = self.core.lock();
			let connected_nodes = ::std::mem::replace(&mut core.connected_nodes, Default::default());
			core.is_isolated = true;
			core.disconnected_nodes.extend(connected_nodes)
		}

		pub fn disconnect(&self, node: NodeId) {
			self.core.lock().connected_nodes.remove(&node);
			self.core.lock().disconnected_nodes.insert(node);
		}

		pub fn exclude(&self, node: NodeId) {
			self.core.lock().connected_nodes.remove(&node);
			self.core.lock().disconnected_nodes.remove(&node);
		}

		pub fn include(&self, node: NodeId) {
			self.core.lock().connected_nodes.insert(node);
		}
	}

	impl parity_secretstore_primitives::connections::ConnectionManager for TestConnectionsManager {
		fn provider(&self) -> Arc<dyn ConnectionProvider> {
			Arc::new(TestConnections { core: self.core.clone() })
		}

		fn connect(&self) {}
	}

	impl ConnectionProvider for TestConnections {
		fn connected_nodes(&self) -> Result<BTreeSet<NodeId>, Error> {
			let core = self.core.lock();
			match core.is_isolated {
				false => Ok(core.connected_nodes.clone()),
				true => Err(Error::NodeDisconnected),
			}
		}

		fn disconnected_nodes(&self) -> BTreeSet<NodeId> {
			self.core.lock().disconnected_nodes.clone()
		}

		fn connection(&self, node: &NodeId) -> Option<Arc<dyn Connection>> {
			let core = self.core.lock();
			match core.connected_nodes.contains(node) {
				true => Some(Arc::new(TestConnection {
					from: core.node,
					to: *node,
					messages: core.messages.clone(),
				})),
				false => None,
			}
		}
	}

	impl Connection for TestConnection {
		fn is_inbound(&self) -> bool {
			false
		}

		fn node_id(&self) -> &NodeId {
			&self.to
		}

		fn node_address(&self) -> String {
			format!("{}", self.to)
		}

		fn send_message(&self, message: Vec<u8>) {
			let header = deserialize_header(&message).unwrap();
			let message = deserialize_message(&header, message[18..].to_vec()).unwrap();
			self.messages.lock().push_back((self.from, self.to, message))
		}
	}

	pub fn new_test_connections(
		messages: MessagesQueue,
		node: NodeId,
		mut nodes: BTreeSet<NodeId>
	) -> Arc<TestConnections> {
		let is_isolated = !nodes.remove(&node);
		Arc::new(TestConnections {
			core: Arc::new(Mutex::new(TestConnectionsData {
				node,
				is_isolated,
				connected_nodes: nodes,
				disconnected_nodes: Default::default(),
				messages,
			})),
		})
	}
}
