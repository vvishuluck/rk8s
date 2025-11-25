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
        let (services_raw, _) = self.xline_store.services_snapshot_with_rev().await?;
        // Key format: /registry/services/specs/<ns>/<name>
        let suffix = format!("/{}/{}", ns, name);
        for (key, yaml) in services_raw {
            if key.ends_with(&suffix) {
                return Ok(Some(serde_yaml::from_str(&yaml)?));
            }
        }
        Ok(None)
    }

    // Helper to fetch a specific endpoint from the store
    async fn get_endpoint(&self, ns: &str, name: &str) -> Result<Option<common::Endpoint>> {
        let (endpoints_raw, _) = self.xline_store.endpoints_snapshot_with_rev().await?;
        let suffix = format!("/{}/{}", ns, name);
        for (key, yaml) in endpoints_raw {
            if key.ends_with(&suffix) {
                return Ok(Some(serde_yaml::from_str(&yaml)?));
            }
        }
        Ok(None)
    }

    async fn process_upsert(&self, ns: &str, name: &str, kind: ResourceKind, yaml: &str) -> Result<()> {
        let (svc, ep) = match kind {
            ResourceKind::Service => {
                let svc: common::ServiceTask = serde_yaml::from_str(yaml)?;
                let ep = self.get_endpoint(ns, name).await?.unwrap_or_else(|| common::Endpoint {
                    api_version: "v1".into(),
                    kind: "Endpoints".into(),
                    metadata: svc.metadata.clone(),
                    subsets: vec![],
                });
                (svc, ep)
            }
            ResourceKind::Endpoint => {
                let ep: common::Endpoint = serde_yaml::from_str(yaml)?;
                let svc = match self.get_service(ns, name).await? {
                    Some(s) => s,
                    None => return Ok(()), // Endpoint without Service is orphan, ignore
                };
                (svc, ep)
            }
            _ => return Ok(()),
        };

        let update = common::NetworkUpdate {
            op: common::NetworkUpdateOp::Put,
            service: Some(svc),
            endpoint: Some(ep),
            resource_version: Utc::now().to_rfc3339(),
        };
        
        info!("Incremental upsert for {}/{}", ns, name);
        self.broadcast_update(update).await
    }

    async fn process_delete(&self, _ns: &str, _name: &str, kind: ResourceKind, yaml: &str) -> Result<()> {
        if kind == ResourceKind::Service {
            let svc: common::ServiceTask = serde_yaml::from_str(yaml)?;
            let update = common::NetworkUpdate {
                op: common::NetworkUpdateOp::Delete,
                service: Some(svc),
                endpoint: None,
                resource_version: Utc::now().to_rfc3339(),
            };
            info!("Incremental delete for Service {}", update.service.as_ref().unwrap().metadata.name);
            self.broadcast_update(update).await?;
        }
        // If Endpoint is deleted, Service usually updates to empty endpoints or is deleted too.
        if kind == ResourceKind::Endpoint {
             let ep: common::Endpoint = serde_yaml::from_str(yaml)?;
             if let Some(svc) = self.get_service(&ep.metadata.namespace, &ep.metadata.name).await? {
                 // Regenerate service rules with empty endpoint (Reject rules)
                 let empty_ep = common::Endpoint {
                     api_version: "v1".into(),
                     kind: "Endpoints".into(),
                     metadata: ep.metadata.clone(),
                     subsets: vec![],
                 };
                 let update = common::NetworkUpdate {
                    op: common::NetworkUpdateOp::Put,
                    service: Some(svc),
                    endpoint: Some(empty_ep),
                    resource_version: Utc::now().to_rfc3339(),
                };
                 info!("Incremental update (Endpoint deleted) for Service {}", update.service.as_ref().unwrap().metadata.name);
                 self.broadcast_update(update).await?;
             }
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
        // Parse key to extract namespace and name
        // Key format example: /registry/services/specs/default/my-service
        let parts: Vec<&str> = response.key.split('/').collect();
        if parts.len() < 2 {
            warn!("Invalid key format: {}", response.key);
            return Ok(());
        }
        let name = parts.last().unwrap();
        let namespace = parts.get(parts.len() - 2).unwrap_or(&"default");

        match &response.event {
            WatchEvent::Add { yaml } | WatchEvent::Update { new_yaml: yaml, .. } => {
                self.process_upsert(namespace, name, response.kind.clone(), yaml).await?;
            }
            WatchEvent::Delete { yaml } => {
                self.process_delete(namespace, name, response.kind.clone(), yaml).await?;
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




