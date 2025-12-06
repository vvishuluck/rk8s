use anyhow::Result;
use common::{Endpoint, EndpointSubset, EndpointAddress, EndpointPort, ObjectMeta, ServiceTask, ServiceSpec, ServicePort};
use libvault::storage::xline::XlineOptions;
use log::LevelFilter;
use once_cell::sync::OnceCell;
use rks::api::xlinestore::XlineStore;
use rks::controllers::manager::ControllerManager;
use rks::network::nft_rules::{generate_nftables_config, generate_service_update, generate_service_delete, NftablesController};
use rks::node::NodeRegistry;
use rks::protocol::config::load_config;
use serial_test::serial;
use serde_yaml;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout, Duration};

#[tokio::test]
async fn test_service_discovery_full_sync() -> Result<()> {
    // 1. Create a Service
    let service = ServiceTask {
        api_version: "v1".into(),
        kind: "Service".into(),
        metadata: ObjectMeta {
            name: "my-service".into(),
            namespace: "default".into(),
            ..Default::default()
        },
        spec: ServiceSpec {
            cluster_ip: Some("10.96.0.100".into()),
            ports: vec![
                ServicePort {
                    name: Some("http".into()),
                    port: 80,
                    target_port: Some(8080),
                    protocol: "TCP".into(),
                    node_port: Some(30080), // Add NodePort
                }
            ],
            selector: None,
            service_type: "NodePort".into(),
        },
    };

    // 2. Create an Endpoint
    let endpoint = Endpoint {
        api_version: "v1".into(),
        kind: "Endpoints".into(),
        metadata: ObjectMeta {
            name: "my-service".into(),
            namespace: "default".into(),
            ..Default::default()
        },
        subsets: vec![
            EndpointSubset {
                addresses: vec![
                    EndpointAddress { ip: "10.244.1.2".into(), node_name: None, target_ref: None },
                    EndpointAddress { ip: "10.244.1.3".into(), node_name: None, target_ref: None },
                ],
                ports: vec![
                    EndpointPort {
                        name: Some("http".into()),
                        port: 8080,
                        protocol: "TCP".into(),
                        app_protocol: None,
                    }
                ],
                not_ready_addresses: vec![],
            }
        ],
    };

    // 3. Generate Rules
    let services = vec![service];
    let endpoints = vec![endpoint];
    let json_rules = generate_nftables_config(&services, &endpoints)?;

    println!("Generated Rules: {}", json_rules);

    // 4. Verify Output
    // Check for ClusterIP match
    assert!(json_rules.contains("10.96.0.100"));
    // Check for Service Port match
    assert!(json_rules.contains("\"dport\""));
    assert!(json_rules.contains("80"));
    // Check for Backend IPs
    assert!(json_rules.contains("10.244.1.2"));
    assert!(json_rules.contains("10.244.1.3"));
    // Check for Backend Port
    assert!(json_rules.contains("8080"));
    // Check for numgen/map (load balancing)
    assert!(json_rules.contains("numgen"));
    assert!(json_rules.contains("map"));

    // Check for NodePort
    assert!(json_rules.contains("30080"));

    // Check for Filter Chains
    assert!(json_rules.contains("filter-input"));
    assert!(json_rules.contains("filter-forward"));
    assert!(json_rules.contains("filter-output"));
    assert!(json_rules.contains("filter-prerouting"));

    // Check for NAT Chains
    assert!(json_rules.contains("nat-prerouting"));
    assert!(json_rules.contains("nat-output"));
    assert!(json_rules.contains("nat-postrouting"));

    Ok(())
}

#[test]
fn test_generate_service_update_incremental() -> Result<()> {
    let svc = ServiceTask {
        api_version: "v1".into(),
        kind: "Service".into(),
        metadata: ObjectMeta { name: "test-svc".into(), namespace: "default".into(), ..Default::default() },
        spec: ServiceSpec {
            cluster_ip: Some("10.96.0.100".into()),
            ports: vec![ServicePort {
                name: Some("http".into()),
                protocol: "TCP".into(),
                port: 80,
                target_port: Some(8080),
                node_port: None,
            }],
            selector: None,
            service_type: "ClusterIP".into(),
        },
    };
    
    let ep = Endpoint {
        api_version: "v1".into(),
        kind: "Endpoints".into(),
        metadata: svc.metadata.clone(),
        subsets: vec![EndpointSubset {
            addresses: vec![EndpointAddress { ip: "10.244.1.5".into(), node_name: None, target_ref: None }],
            ports: vec![EndpointPort { name: Some("http".into()), port: 8080, protocol: "TCP".into(), app_protocol: None }],
            not_ready_addresses: vec![],
        }],
    };

    let json_rules = generate_service_update(&svc, &ep)?;
    println!("Incremental Update Rules: {}", json_rules);

    assert!(json_rules.contains("add"));
    assert!(json_rules.contains("service_map_tcp"));
    assert!(json_rules.contains("svc-default-test-svc-80"));
    assert!(json_rules.contains("10.244.1.5"));
    assert!(json_rules.contains("10.96.0.100"));
    
    Ok(())
}

#[test]
fn test_generate_service_delete_incremental() -> Result<()> {
    let svc = ServiceTask {
        api_version: "v1".into(),
        kind: "Service".into(),
        metadata: ObjectMeta { name: "test-svc".into(), namespace: "default".into(), ..Default::default() },
        spec: ServiceSpec {
            cluster_ip: Some("10.96.0.100".into()),
            ports: vec![ServicePort {
                name: Some("http".into()),
                protocol: "TCP".into(),
                port: 80,
                target_port: Some(8080),
                node_port: None,
            }],
            selector: None,
            service_type: "ClusterIP".into(),
        },
    };

    let json_rules = generate_service_delete(&svc)?;
    println!("Incremental Delete Rules: {}", json_rules);

    assert!(json_rules.contains("delete"));
    assert!(json_rules.contains("element"));
    assert!(json_rules.contains("service_map_tcp"));
    assert!(json_rules.contains("chain"));
    assert!(json_rules.contains("svc-default-test-svc-80"));

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_nftables_controller_generates_local_rules_on_xline_changes() -> Result<()> {
    init_logging();
    let store = match get_store().await {
        Some(store) => store,
        None => return Ok(()),
    };
    clean_store(&store).await?;

    let registry = Arc::new(NodeRegistry::default()); // unused in generation-only mode

    let manager = Arc::new(ControllerManager::new());
    let controller = Arc::new(RwLock::new(NftablesController::new(
        store.clone(),
        registry.clone(),
    )));
    manager.clone().register(controller.clone(), 1).await?;
    manager.clone().start_watch(store.clone()).await?;
    sleep(Duration::from_millis(300)).await;

    let service = sample_service("svc-watch", "10.96.0.200", 80, 8080);
    let svc_yaml = serde_yaml::to_string(&service)?;
    store
        .insert_service_yaml(&service_key(&service), &svc_yaml)
        .await?;

    let endpoint = sample_endpoint(&service, vec!["10.244.5.10"], 8080);
    let endpoint_yaml = serde_yaml::to_string(&endpoint)?;
    store
        .insert_endpoint_yaml(&endpoint_key(&endpoint), &endpoint_yaml)
        .await?;

    // Allow controller watch loop to process inserted resources and generate incremental rules.
    sleep(Duration::from_millis(500)).await;
    let guard = controller.read().await;
    let nft_rules = guard.incremental_rules().join("\n");
    assert!(!nft_rules.is_empty(), "no incremental rules stored");
    assert!(
        nft_rules.contains("svc-default-svc-watch-80"),
        "chain name missing: {}",
        nft_rules
    );
    assert!(
        nft_rules.contains("10.244.5.10"),
        "backend IP missing: {}",
        nft_rules
    );
    assert!(
        nft_rules.contains("10.96.0.200"),
        "cluster IP missing: {}",
        nft_rules
    );

    // --- Test Update: Change Endpoint IP ---
    drop(guard); // Release lock before waiting
    let updated_endpoint = sample_endpoint(&service, vec!["10.244.5.20"], 8080);
    let updated_endpoint_yaml = serde_yaml::to_string(&updated_endpoint)?;
    store
        .insert_endpoint_yaml(&endpoint_key(&updated_endpoint), &updated_endpoint_yaml)
        .await?;

    sleep(Duration::from_millis(500)).await;
    let guard = controller.read().await;
    let all_rules = guard.incremental_rules().join("\n");
    // We expect the new IP to be present in the accumulated rules
    assert!(
        all_rules.contains("10.244.5.20"),
        "updated backend IP 10.244.5.20 missing in rules: {}",
        all_rules
    );

    // --- Test Delete: Remove Service ---
    drop(guard);
    store.delete_service(&service_key(&service)).await?;
    
    sleep(Duration::from_millis(500)).await;
    let guard = controller.read().await;
    let final_rules = guard.incremental_rules().join("\n");
    
    // Check for delete command
    // The exact string depends on generate_service_delete implementation, usually contains "delete element"
    assert!(
        final_rules.contains("delete element"),
        "delete rule missing: {}",
        final_rules
    );
    assert!(
        final_rules.contains("svc-default-svc-watch-80"),
        "chain name missing in delete rule: {}",
        final_rules
    );

    clean_store(&store).await?;
    Ok(())
}

fn sample_service(name: &str, cluster_ip: &str, port: i32, target_port: i32) -> ServiceTask {
    ServiceTask {
        api_version: "v1".into(),
        kind: "Service".into(),
        metadata: ObjectMeta {
            name: name.into(),
            namespace: "default".into(),
            ..Default::default()
        },
        spec: ServiceSpec {
            cluster_ip: Some(cluster_ip.into()),
            ports: vec![ServicePort {
                name: Some("http".into()),
                port,
                target_port: Some(target_port),
                protocol: "TCP".into(),
                node_port: None,
            }],
            selector: None,
            service_type: "ClusterIP".into(),
        },
    }
}

fn sample_endpoint(service: &ServiceTask, backend_ips: Vec<&str>, backend_port: i32) -> Endpoint {
    Endpoint {
        api_version: "v1".into(),
        kind: "Endpoints".into(),
        metadata: ObjectMeta {
            name: service.metadata.name.clone(),
            namespace: service.metadata.namespace.clone(),
            ..Default::default()
        },
        subsets: vec![EndpointSubset {
            addresses: backend_ips
                .into_iter()
                .map(|ip| EndpointAddress {
                    ip: ip.into(),
                    node_name: None,
                    target_ref: None,
                })
                .collect(),
            not_ready_addresses: vec![],
            ports: vec![EndpointPort {
                name: Some("http".into()),
                port: backend_port,
                protocol: "TCP".into(),
                app_protocol: None,
            }],
        }],
    }
}

fn service_key(service: &ServiceTask) -> String {
    format!("specs/{}/{}", service.metadata.namespace, service.metadata.name)
}

fn endpoint_key(endpoint: &Endpoint) -> String {
    format!("{}/{}", endpoint.metadata.namespace, endpoint.metadata.name)
}

// Removed message-based helper functions; controller now stores rules locally.

async fn get_store() -> Option<Arc<XlineStore>> {
    let endpoints = get_xline_endpoints();
    let option = XlineOptions::new(endpoints);
    match timeout(Duration::from_secs(5), XlineStore::new(option)).await {
        Ok(Ok(store)) => {
            // Health check: if basic list operation fails, skip test by returning None.
            match store.list_service_names().await {
                Ok(_) => Some(Arc::new(store)),
                Err(_) => None,
            }
        }
        _ => None,
    }
}

fn get_xline_endpoints() -> Vec<String> {
    let config_path = std::env::var("TEST_CONFIG_PATH").unwrap_or_else(|_| {
        format!(
            "{}/tests/config.yaml",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )
    });

    match load_config(&config_path) {
        Ok(cfg) => cfg.xline_config.endpoints.clone(),
        Err(_) => vec!["http://127.0.0.1:2379".to_string()],
    }
}

async fn clean_store(store: &Arc<XlineStore>) -> Result<()> {
    for ep in store.list_endpoints().await? {
        let names = vec![
            format!("{}/{}", ep.metadata.namespace, ep.metadata.name),
            ep.metadata.name.clone(),
        ];
        for key in names {
            let _ = store.delete_endpoint(&key).await;
        }
    }
    for name in store.list_service_names().await? {
        let _ = store.delete_service(&name).await;
    }
    for name in store.list_pod_names().await? {
        let _ = store.delete_pod(&name).await;
    }
    Ok(())
}

fn init_logging() {
    static LOGGER: OnceCell<()> = OnceCell::new();
    LOGGER.get_or_init(|| {
        env_logger::builder()
            .is_test(true)
            .filter_level(LevelFilter::Info)
            .try_init()
            .ok();
    });
}
