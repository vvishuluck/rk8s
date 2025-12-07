use anyhow::Result;
use crate::api::xlinestore::XlineStore;
use crate::controllers::manager::{Controller, ResourceWatchResponse, WatchEvent};
use crate::node::NodeRegistry;
use async_trait::async_trait;
use common::{self, ResourceKind};
use std::sync::Arc;
use log::{info, warn};
use chrono::Utc;
use serde_json;
use serde_yaml;


/// NftablesController watches Services and Endpoints, generates nftables rules,
/// and broadcasts them to all registered worker nodes.
pub struct NftablesController {
    xline_store: Arc<XlineStore>,
    node_registry: Arc<NodeRegistry>,
}

impl NftablesController {
    pub fn new(xline_store: Arc<XlineStore>, node_registry: Arc<NodeRegistry>) -> Self {
        Self {
            xline_store,
            node_registry,
        }
    }

    async fn sync_rules(&self) -> Result<()> {
        let (services_raw, _srev) = self.xline_store.services_snapshot_with_rev().await?;
        let (endpoints_raw, _erev) = self.xline_store.endpoints_snapshot_with_rev().await?;

        let mut services = Vec::new();
        for (key, yaml) in services_raw {
            match serde_yaml::from_str::<common::ServiceTask>(&yaml) {
                Ok(svc) => services.push(svc),
                Err(e) => warn!("Failed to parse Service {}: {}", key, e),
            }
        }

        let mut endpoints = Vec::new();
        for (key, yaml) in endpoints_raw {
            match serde_yaml::from_str::<common::Endpoint>(&yaml) {
                Ok(ep) => endpoints.push(ep),
                Err(e) => warn!("Failed to parse Endpoint {}: {}", key, e),
            }
        }

        let state = common::NetworkState {
            services,
            endpoints,
            resource_version: Utc::now().to_rfc3339(),
        };

        self.broadcast_state(state).await
    }

    async fn broadcast_state(&self, state: common::NetworkState) -> Result<()> {
        let sessions = self.node_registry.list_sessions().await;
        if sessions.is_empty() {
            return Ok(());
        }

        info!("Broadcasting network state (ver={}) to {} nodes", state.resource_version, sessions.len());
        let msg = common::RksMessage::SetNetworkState(state);
        
        for (node_id, session) in sessions {
            if let Err(e) = session.tx.try_send(msg.clone()) {
                warn!("Failed to send state to node {}: {}", node_id, e);
            }
        }
        Ok(())
    }

    async fn broadcast_update(&self, update: common::NetworkUpdate) -> Result<()> {
        let sessions = self.node_registry.list_sessions().await;
        if sessions.is_empty() {
            return Ok(());
        }

        info!("Broadcasting network update (op={:?}) to {} nodes", update.op, sessions.len());
        let msg = common::RksMessage::UpdateNetworkState(update);
        
        for (node_id, session) in sessions {
            if let Err(e) = session.tx.try_send(msg.clone()) {
                warn!("Failed to send update to node {}: {}", node_id, e);
            }
        }
        Ok(())
    }

    // Helper to fetch a specific service from the store (using snapshot for now)
    async fn get_service(&self, ns: &str, name: &str) -> Result<Option<common::ServiceTask>> {
        let svc_key = format!("specs/{}/{}", ns, name);
        self.xline_store.get_service(&svc_key).await
    }

    // Only handle Endpoint upserts: Services are not watched to reduce noise.
    async fn process_upsert(&mut self, yaml: &str) -> Result<()> {
        let ep: common::Endpoint = serde_yaml::from_str(yaml)?;
        // Service name is expected to match endpoint metadata (namespace + name)
        let ns = &ep.metadata.namespace;
        let name = &ep.metadata.name;
        let svc = match self.get_service(ns, name).await? {
            Some(s) => s,
            None => return Ok(()), // Endpoint without Service is orphan, ignore
        };

        let rules = generate_service_update(&svc, &ep)?;
        info!("Stored incremental rules for endpoint {}/{}", ns, name);

        let update = common::NetworkUpdate {
            op: common::NetworkUpdateOp::Put,
            service: Some(svc),
            endpoint: Some(ep),
            resource_version: Utc::now().to_rfc3339(),
        };
        
        info!("Incremental upsert for {}/{}", ns, name);
        self.broadcast_update(update).await
    }

    // Only handle Endpoint deletions: generate reject/cleanup rules when endpoints are removed.
    async fn process_delete(&mut self, yaml: &str) -> Result<()> {
        let ep: common::Endpoint = serde_yaml::from_str(yaml)?;
        if let Some(svc) = self.get_service(&ep.metadata.namespace, &ep.metadata.name).await? {
            let empty_ep = common::Endpoint {
                api_version: "v1".into(),
                kind: "Endpoints".into(),
                metadata: ep.metadata.clone(),
                subsets: vec![],
            };
            let rules = generate_service_update(&svc, &empty_ep)?; // Reject rules
            info!("Stored incremental empty-endpoints rules for Service {}", svc.metadata.name);

            let update = NetworkUpdate {
                op: NetworkUpdateOp::Put,
                service: Some(svc),
                endpoint: Some(empty_ep),
                resource_version: "".to_string(),
            };

            self.store_incremental_rules(rules, update).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Controller for NftablesController {
    fn name(&self) -> &'static str {
        "nftables-controller"
    }

    async fn init(&mut self) -> Result<()> {
        info!("Initializing NftablesController, performing initial full sync...");
        self.sync_rules().await
    }

    fn watch_resources(&self) -> Vec<ResourceKind> {
        vec![ResourceKind::Service, ResourceKind::Endpoint]
    }

    async fn handle_watch_response(&mut self, response: &ResourceWatchResponse) -> Result<()> {
        // We only watch Endpoints in this controller.
        if response.kind != ResourceKind::Endpoint {
            return Ok(());
        }

        match &response.event {
            WatchEvent::Add { yaml } | WatchEvent::Update { new_yaml: yaml, .. } => {
                self.process_upsert(yaml).await?;
            }
            WatchEvent::Delete { yaml } => {
                self.process_delete(yaml).await?;
            }
        }
        Ok(())
    }
}

pub async fn build_rules(xline_store: &XlineStore) -> Result<String> {
    // Use snapshot helpers to avoid many RPCs
    let (services_raw, _srev) = xline_store.services_snapshot_with_rev().await?;
    let (endpoints_raw, _erev) = xline_store.endpoints_snapshot_with_rev().await?;

    let mut services = Vec::new();
    for (key, yaml) in services_raw {
        match serde_yaml::from_str::<common::ServiceTask>(&yaml) {
            Ok(svc) => services.push(svc),
            Err(e) => warn!("Failed to parse Service {}: {}", key, e),
        }
    }

    let mut endpoints = Vec::new();
    for (key, yaml) in endpoints_raw {
        match serde_yaml::from_str::<common::Endpoint>(&yaml) {
            Ok(ep) => endpoints.push(ep),
            Err(e) => warn!("Failed to parse Endpoint {}: {}", key, e),
        }
    }

    generate_nftables_config(&services, &endpoints)
}

// Re-export generation functions from libnetwork for tests
pub use libnetwork::nftables::{generate_nftables_config, generate_service_update, generate_service_delete};




