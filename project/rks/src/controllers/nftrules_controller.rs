use crate::api::xlinestore::XlineStore;
use crate::controllers::manager::{Controller, ResourceWatchResponse, WatchEvent};
use crate::node::NodeRegistry;
use anyhow::Result;
use async_trait::async_trait;
use common::{self, ResourceKind};
use log::{info, warn};
use serde_yaml;
use std::sync::Arc;

/// Watches Services and Endpoints, generates nftables rules, and broadcasts to workers.
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

        // Generate JSON rules (Full Sync)
        let json_rules = generate_nftables_config(&services, &endpoints)?;

        self.broadcast_rules(json_rules).await
    }

    async fn broadcast_rules(&self, json_rules: String) -> Result<()> {
        let sessions = self.node_registry.list_sessions().await;
        if sessions.is_empty() {
            info!("Broadcasting nftables rules skipped: no worker nodes connected");
            return Ok(());
        }

        info!(
            "Broadcasting full nftables rules to {} nodes (len={})",
            sessions.len(),
            json_rules.len()
        );

        let msg = common::RksMessage::SetNftablesRules(json_rules);

        for (node_id, session) in sessions {
            if let Err(e) = session.tx.try_send(msg.clone()) {
                warn!("Failed to send rules to node {}: {}", node_id, e);
            }
        }
        Ok(())
    }

    // Only handle Endpoint upserts: Services are not watched to reduce noise.
    async fn process_upsert(&mut self, yaml: &str) -> Result<()> {
        // Parse purely for logging context
        if let Ok(ep) = serde_yaml::from_str::<common::Endpoint>(yaml) {
            info!(
                "NftablesController: processing endpoint upsert {}/{}, triggering full sync",
                ep.metadata.namespace, ep.metadata.name
            );
        } else {
            info!(
                "NftablesController: processing endpoint upsert (parse failed), triggering full sync"
            );
        }

        self.sync_rules().await
    }

    // Only handle Endpoint deletions.
    async fn process_delete(&mut self, yaml: &str) -> Result<()> {
        if let Ok(ep) = serde_yaml::from_str::<common::Endpoint>(yaml) {
            info!(
                "NftablesController: processing endpoint delete {}/{}, triggering full sync",
                ep.metadata.namespace, ep.metadata.name
            );
        } else {
            info!(
                "NftablesController: processing endpoint delete (parse failed), triggering full sync"
            );
        }

        self.sync_rules().await
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

        info!(
            "NftablesController: received watch event for Endpoint kind={:?}",
            response.event
        );

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
pub use libnetwork::nftables::generate_nftables_config;
