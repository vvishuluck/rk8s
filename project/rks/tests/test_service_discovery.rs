use anyhow::Result;
use common::{Endpoint, EndpointSubset, EndpointAddress, EndpointPort, ObjectMeta, ServiceTask, ServiceSpec, ServicePort};
use rks::network::nft_rules::{generate_nftables_config, generate_service_update, generate_service_delete};

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
