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

/*use std::collections::VecDeque;
use log::error;
use parking_lot::RwLock;
use codec::Encode;
use sp_core::H256;
use parity_secretstore_primitives::{
	KeyServerId,
	service::{Service, ServiceTask, ServiceResponse},
};
use crate::substrate_client::Client;

const MAX_NEW_TASKS: usize = 64;

pub struct OnChainService {
	client: Client,
	self_id: KeyServerId,
	data: RwLock<OnChainServiceData>,
}

struct OnChainServiceData {
	best_block: Option<(u32, H256)>,
	new_tasks: VecDeque<ServiceTask>,
}

struct PendingTasks {
	client: Client,
	self_id: KeyServerId,
	block: (u32, H256),
	num_pending_tasks: u32,
	current_task_index: u32,
}

impl OnChainService {
	pub fn new(client: Client, self_id: KeyServerId) -> Self {
		OnChainService {
			client,
			self_id,
			data: RwLock::new(OnChainServiceData {
				best_block: None,
				new_tasks: VecDeque::new(),
			}),
		}
	}

	pub fn set_best_block(&self, best_block: (u32, H256)) {
		self.data.write().best_block = Some(best_block);
	}

	pub fn append_block_events(&self, events: Vec<frame_system::EventRecord<node_runtime::Event, sp_core::H256>>) {
		let mut data = self.data.write();

		match data.new_tasks.len().checked_sub(MAX_NEW_TASKS) {
			Some(max_new_tasks) => data.new_tasks.extend(parse_service_task_events(events).take(max_new_tasks)),
			None => ()
		}
	}
}

impl Service for OnChainService {
	fn new_requests(&self) -> Box<dyn Iterator<Item = ServiceTask>> {
		let mut data = self.data.write();
		let mut new_tasks = VecDeque::new();
		std::mem::swap(&mut data.new_tasks, &mut new_tasks);
		Box::new(new_tasks.into_iter())
	}

	fn pending_requests(&self) -> Box<dyn Iterator<Item = ServiceTask>> {
		let best_block = match self.data.read().best_block {
			Some(best_block) => best_block,
			None => return Box::new(std::iter::empty()),
		};
		let num_pending_tasks = futures::executor::block_on(async {
			self.client.call_runtime_method(
				best_block.1,
				"SecretStoreServiceRuntimeApi_pending_tasks_count",
				vec![],
			).await
		}).unwrap_or_else(|error| {
			error!(
				target: "secretstore_net",
				"Failed to read number of pending service requests: {:?}",
				error,
			);

			0
		});

		Box::new(PendingTasks {
			client: self.client.clone(),
			self_id: self.self_id,
			block: best_block,
			num_pending_tasks,
			current_task_index: 0,
		})
	}

	fn publish_response(&self, response: ServiceResponse) {
		let response = match response {
			ServiceResponse::ServerKeyGenerated(key_id, key) =>
				ss_primitives::service::ServiceResponse::ServerKeyGenerated(
					key_id.into(),
					key.into(),
				),
			ServiceResponse::ServerKeyGenerationFailed(key_id) =>
				ss_primitives::service::ServiceResponse::ServerKeyGenerationFailed(
					key_id.into(),
				),
			ServiceResponse::ServerKeyRetrieved(key_id, key, threshold) =>
				if let Some(threshold) = truncate_threshold(threshold) {
					ss_primitives::service::ServiceResponse::ServerKeyRetrieved(
						key_id.into(),
						key.into(),
						threshold,
					)
				} else {
					return
				},
			ServiceResponse::ServerKeyRetrievalFailed(key_id) =>
				ss_primitives::service::ServiceResponse::ServerKeyRetrievalFailed(
					key_id.into(),
				),
			ServiceResponse::DocumentKeyStored(key_id) =>
				ss_primitives::service::ServiceResponse::DocumentKeyStored(
					key_id.into(),
				),
			ServiceResponse::DocumentKeyStoreFailed(key_id) =>
				ss_primitives::service::ServiceResponse::DocumentKeyStoreFailed(
					key_id.into(),
				),
			ServiceResponse::DocumentKeyCommonRetrieved(key_id, requester_id, common_point, threshold) =>
				if let Some(threshold) = truncate_threshold(threshold) {
					ss_primitives::service::ServiceResponse::DocumentKeyCommonRetrieved(
						key_id.into(),
						requester_id.into(),
						common_point.into(),
						threshold,
					)
				} else {
					return
				},
			ServiceResponse::DocumentKeyPersonalRetrieved(
				key_id,
				requester_id,
				participants,
				decrypted_secret,
				key_shadow,
			) => ss_primitives::service::ServiceResponse::DocumentKeyPersonalRetrieved(
					key_id.into(),
					requester_id.into(),
					participants.into_iter().map(Into::into).collect(),
					decrypted_secret.into(),
					key_shadow.into(),
				),
			ServiceResponse::DocumentKeyRetrievalFailed(key_id, requester_id) =>
				ss_primitives::service::ServiceResponse::DocumentKeyRetrievalFailed(
					key_id.into(),
					requester_id.into(),
				),
		};

		let submit_result = futures::executor::block_on(async {
			self.client.submit_transaction(node_runtime::Call::SecretStore(
				node_runtime::SecretStoreCall::service_response(
					response,
				),
			)).await
		});

		if let Err(error) = submit_result {
			error!(
				target: "secretstore_net",
				"Error submitting service response: {:?}",
				error,
			);
		}
	}
}

impl Iterator for PendingTasks {
	type Item = ServiceTask;

	fn next(&mut self) -> Option<Self::Item> {
		let current_task_index = self.current_task_index;
		if current_task_index == self.num_pending_tasks {
			return None;
		}

		self.current_task_index += 1;
		let pending_task: Result<Option<ss_primitives::service::ServiceTask>, _> = futures::executor::block_on(async {
			self.client.call_runtime_method(
				self.block.1,
				"SecretStoreServiceRuntimeApi_pending_task",
				vec![current_task_index.encode(), self.self_id.encode()],
			).await
		});

		match pending_task {
			Ok(pending_task) => pending_task.map(into_secret_store_service_task),
			Err(error) => {
				error!(
					target: "secretstore_net",
					"Failed to read pending service request: {:?}",
					error,
				);

				None
			},
		}
	}
}

fn parse_service_task_events(
	events: Vec<frame_system::EventRecord<node_runtime::Event, sp_core::H256>>,
) -> impl Iterator<Item = ServiceTask> {
	events.into_iter().filter_map(|event|
		match event.event {
			node_runtime::Event::substrate_secret_store_runtime(event) => match event {
				substrate_secret_store_runtime::Event::ServerKeyGenerationRequested(
					key_id,
					author_id,
					threshold,
				) => Some(ServiceTask::GenerateServerKey(
						key_id.into(),
						author_id.into(),
						threshold.into(),
					)),
				substrate_secret_store_runtime::Event::ServerKeyRetrievalRequested(key_id)
					=> Some(ServiceTask::RetrieveServerKey(
						key_id.into(),
					)),
				substrate_secret_store_runtime::Event::DocumentKeyStoreRequested(
					key_id,
					requester_id,
					common_point,
					encrypted_point,
				) => Some(ServiceTask::StoreDocumentKey(
					key_id.into(),
					requester_id.into(),
					common_point.into(),
					encrypted_point.into(),
				)),
				_ => None,
			},
			_ => None,
		}
	)
}

fn truncate_threshold(threshold: usize) -> Option<u8> {
	if threshold > std::u8::MAX as _ {
		error!(
			target: "secretstore_net",
			"Failed to publish secret store response: too large threshold",
		);

		None
	} else {
		Some(threshold as _)
	}
}

fn into_secret_store_service_task(task: ss_primitives::service::ServiceTask) -> ServiceTask {
	match task {
		ss_primitives::service::ServiceTask::GenerateServerKey(key_id, requester_id, threshold)
			=> ServiceTask::GenerateServerKey(key_id, requester_id, threshold as _),
		ss_primitives::service::ServiceTask::RetrieveServerKey(key_id)
			=> ServiceTask::RetrieveServerKey(key_id),
		ss_primitives::service::ServiceTask::StoreDocumentKey(key_id, requester_id, common_point, encrypted_point)
			=> ServiceTask::StoreDocumentKey(key_id, requester_id, common_point, encrypted_point),
		ss_primitives::service::ServiceTask::RetrieveShadowDocumentKeyCommon(key_id, requester_id)
			=> ServiceTask::RetrieveShadowDocumentKeyCommon(key_id, requester_id),
		ss_primitives::service::ServiceTask::RetrieveShadowDocumentKeyPersonal(key_id, requester_id)
			=> ServiceTask::RetrieveShadowDocumentKeyPersonal(key_id, requester_id),
	}
}
*/