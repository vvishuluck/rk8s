use anyhow::Result;
use crate::api::xlinestore::XlineStore;
use crate::controllers::manager::{Controller, ResourceWatchResponse, WatchEvent};
use crate::node::NodeRegistry;
use async_trait::async_trait;
use common::{self, ResourceKind, NetworkUpdate, NetworkUpdateOp, RksMessage};
use std::sync::Arc;
use log::{info, warn};
// removed unused imports after switching to local rule storage only
use serde_yaml;


/// NftablesController watches Services and Endpoints, generates nftables rules,
/// and broadcasts them to all registered worker nodes.
pub struct NftablesController {
    xline_store: Arc<XlineStore>,
    node_registry: Arc<NodeRegistry>,
    last_full_rules: Option<String>,
    last_incremental_rules: Vec<String>,
}

impl NftablesController {
    pub fn new(xline_store: Arc<XlineStore>, node_registry: Arc<NodeRegistry>) -> Self {
        Self {
            xline_store,
            node_registry,
            last_full_rules: None,
            last_incremental_rules: Vec::new(),
        }
    }

    pub fn last_full_rules(&self) -> Option<&str> {
        self.last_full_rules.as_deref()
    }

    pub fn incremental_rules(&self) -> &[String] {
        &self.last_incremental_rules
    }

    async fn sync_rules(&mut self) -> Result<()> {
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

        let rules = generate_nftables_config(&services, &endpoints)?;
        self.last_full_rules = Some(rules);
        Ok(())
    }

    // Store incremental rules locally and broadcast them to all registered nodes.
    async fn store_incremental_rules(&mut self, rules: String, update: NetworkUpdate) -> Result<()> {
        self.last_incremental_rules.push(rules);

        let sessions = self.node_registry.list_sessions().await;
        if sessions.is_empty() {
            return Ok(());
        }

        info!("Broadcasting incremental nftables update to {} nodes", sessions.len());
        let msg = RksMessage::UpdateNetworkState(update);

        for (node_id, session) in sessions {
            if let Err(e) = session.tx.try_send(msg.clone()) {
                warn!("Failed to send incremental rules to node {}: {}", node_id, e);
            }
        }
        Ok(())
    }

    // Fetch a specific service object via XlineStore helper.
    // XlineStore stores services under keys like "/registry/services/specs/<ns>/<name>"
    // and its `get_service` expects the service name used when inserting (e.g. "specs/<ns>/<name>").
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

        let update = NetworkUpdate {
            op: NetworkUpdateOp::Put,
            service: Some(svc),
            endpoint: Some(ep),
            resource_version: "".to_string(),
        };

        self.store_incremental_rules(rules, update).await
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
        info!("Initializing NftablesController (local rule generation only)...");
        self.sync_rules().await
    }

    // Only watch Endpoints; Service objects are looked up on-demand.
    fn watch_resources(&self) -> Vec<ResourceKind> {
        vec![ResourceKind::Endpoint]
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




