use anyhow::Result;
use common::{
    Endpoint, EndpointAddress, EndpointPort, EndpointSubset, NetworkUpdate, NetworkUpdateOp,
    ObjectMeta, RksMessage, ServicePort, ServiceSpec, ServiceTask,
};
use libnetwork::nftables;
use tokio::sync::mpsc;

// Mock NetworkReceiver to verify rules are applied
struct MockNetworkReceiver {
    applied_rules: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl MockNetworkReceiver {
    fn new() -> Self {
        Self {
            applied_rules: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    async fn apply_nft_rules(&self, rules: String) -> Result<()> {
        self.applied_rules.lock().unwrap().push(rules);
        Ok(())
    }
}

// Simplified version of the message handling logic from client.rs
async fn handle_test_message(
    msg: RksMessage,
    receiver: &MockNetworkReceiver,
) -> Result<RksMessage> {
    match msg {
        RksMessage::UpdateNetworkState(update) => {
            let res = match update.op {
                NetworkUpdateOp::Put => {
                    if let (Some(svc), Some(ep)) = (update.service, update.endpoint) {
                        nftables::generate_service_update(&svc, &ep)
                    } else {
                        Err(anyhow::anyhow!("Missing service or endpoint for Put"))
                    }
                }
                NetworkUpdateOp::Delete => {
                    if let Some(svc) = update.service {
                        nftables::generate_service_delete(&svc)
                    } else {
                        Err(anyhow::anyhow!("Missing service for Delete"))
                    }
                }
            };

            match res {
                Ok(rules) => {
                    receiver.apply_nft_rules(rules).await?;
                    Ok(RksMessage::Ack)
                }
                Err(e) => Ok(RksMessage::Error(format!("generate rules failed: {e}"))),
            }
        }
        _ => Ok(RksMessage::Ack), // Ignore other messages for this test
    }
}

#[tokio::test]
async fn test_rkl_receives_and_applies_update() -> Result<()> {
    // 1. Setup Mock Receiver
    let receiver = MockNetworkReceiver::new();

    // 2. Create Test Data (Service + Endpoint)
    let service = ServiceTask {
        api_version: "v1".into(),
        kind: "Service".into(),
        metadata: ObjectMeta {
            name: "test-svc".into(),
            namespace: "default".into(),
            ..Default::default()
        },
        spec: ServiceSpec {
            cluster_ip: Some("10.96.0.100".into()),
            ports: vec![ServicePort {
                name: Some("http".into()),
                port: 80,
                target_port: Some(8080),
                protocol: "TCP".into(),
                node_port: None,
            }],
            selector: None,
            service_type: "ClusterIP".into(),
        },
    };

    let endpoint = Endpoint {
        api_version: "v1".into(),
        kind: "Endpoints".into(),
        metadata: service.metadata.clone(),
        subsets: vec![EndpointSubset {
            addresses: vec![EndpointAddress {
                ip: "10.244.1.5".into(),
                node_name: None,
                target_ref: None,
            }],
            ports: vec![EndpointPort {
                name: Some("http".into()),
                port: 8080,
                protocol: "TCP".into(),
                app_protocol: None,
            }],
            not_ready_addresses: vec![],
        }],
    };

    // 3. Construct Update Message
    let update_msg = RksMessage::UpdateNetworkState(NetworkUpdate {
        op: NetworkUpdateOp::Put,
        service: Some(service),
        endpoint: Some(endpoint),
        resource_version: "1".into(),
    });

    // 4. Simulate Message Handling
    let response = handle_test_message(update_msg, &receiver).await?;

    // 5. Verify Results
    // Check if Ack was returned
    assert!(matches!(response, RksMessage::Ack));

    // Check if rules were "applied" (stored in mock)
    let applied = receiver.applied_rules.lock().unwrap();
    assert_eq!(applied.len(), 1);
    
    let rules_json = &applied[0];
    println!("Applied Rules: {}", rules_json);

    // Basic validation of generated rules
    assert!(rules_json.contains("svc-default-test-svc-80"));
    assert!(rules_json.contains("10.244.1.5"));
    assert!(rules_json.contains("10.96.0.100"));

    Ok(())
}
