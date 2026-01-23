use common::{
    Endpoint, EndpointAddress, EndpointPort, EndpointSubset, ObjectMeta, ServicePort, ServiceSpec,
    ServiceTask,
};
use libnetwork::nftables::generate_nftables_config;
use std::fs;
use std::process::Command;

fn diagnose_transport_payloads(json_str: &str) {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str)
        && let Some(arr) = val.get("nftables").and_then(|v| v.as_array())
    {
        for (idx, obj) in arr.iter().enumerate() {
            if let Some(rule) = obj.get("rule")
                && let Some(expr_arr) = rule.get("expr").and_then(|v| v.as_array())
            {
                let mut has_l4proto_match = false;
                let mut has_transport_payload = false;
                let mut transport_protocol = String::new();

                for (expr_idx, expr) in expr_arr.iter().enumerate() {
                    if let Some(m) = expr.get("match")
                        && let Some(left) = m.get("left")
                        && let Some(meta) = left.get("meta")
                        && let Some(key) = meta.get("key").and_then(|v| v.as_str())
                        && key == "l4proto"
                    {
                        has_l4proto_match = true;
                    }

                    if let Some(m) = expr.get("match")
                        && let Some(left) = m.get("left")
                        && let Some(payload) = left.get("payload")
                        && let Some(field) = payload.get("field")
                        && let Some(proto) = payload.get("protocol").and_then(|v| v.as_str())
                        && (proto == "tcp" || proto == "udp")
                    {
                        has_transport_payload = true;
                        transport_protocol = proto.to_string();
                        if !has_l4proto_match {
                            // Use ASCII markers to avoid Unicode escape issues in fmt
                            println!(
                                "[WARN] Rule #{} expr[{}]: Found {} payload without prior l4proto match",
                                idx, expr_idx, proto
                            );
                            println!("    Rule chain: {:?}", rule.get("chain"));
                            println!("    Field: {:?}", field);
                        }
                    }
                }

                if has_transport_payload && !has_l4proto_match {
                    println!(
                        "[ERROR] Rule #{}: Uses {} payload WITHOUT l4proto match",
                        idx, transport_protocol
                    );
                    println!("   Chain: {:?}", rule.get("chain"));
                }
            }
        }
    }
}

#[test]
fn test_generate_and_check_nftables() {
    let svc = ServiceTask {
        api_version: "v1".into(),
        kind: "Service".into(),
        metadata: ObjectMeta {
            name: "mysvc".into(),
            namespace: "default".into(),
            ..Default::default()
        },
        spec: ServiceSpec {
            cluster_ip: Some("10.96.0.100".into()),
            ports: vec![ServicePort {
                name: Some("http".into()),
                protocol: "TCP".into(),
                port: 80,
                target_port: Some(8080),
                node_port: Some(30080),
            }],
            selector: None,
            service_type: "NodePort".into(),
        },
    };
    let ep = Endpoint {
        api_version: "v1".into(),
        kind: "Endpoints".into(),
        metadata: ObjectMeta {
            name: "mysvc".into(),
            namespace: "default".into(),
            ..Default::default()
        },
        subsets: vec![EndpointSubset {
            addresses: vec![
                EndpointAddress {
                    ip: "10.244.1.2".into(),
                    node_name: None,
                    target_ref: None,
                },
                EndpointAddress {
                    ip: "10.244.1.3".into(),
                    node_name: None,
                    target_ref: None,
                },
            ],
            not_ready_addresses: vec![],
            ports: vec![EndpointPort {
                name: Some("http".into()),
                port: 8080,
                protocol: "TCP".into(),
                app_protocol: None,
            }],
        }],
    };
    let json = generate_nftables_config(&[svc], &[ep]).expect("generate_nftables_config failed");
    diagnose_transport_payloads(&json);
    let path = "/tmp/generated_nft_test.json";
    fs::write(path, &json).expect("write file failed");
    // Use `nft --check` to validate the generated rules
    let output = Command::new("sudo")
        .arg("nft")
        .arg("-j")
        .arg("--check")
        .arg("-f")
        .arg(path)
        .output()
        .expect("failed to execute nft");
    println!(
        "nft --check stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    println!(
        "nft --check stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "nft --check failed");
}
