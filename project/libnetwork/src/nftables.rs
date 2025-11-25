use anyhow::Result;
use common;
use nftables::{batch::Batch, schema, types, expr, stmt};
use serde_json::{self, json};

/// Generates the FULL configuration (Table, Base Chains, Maps, and all Service Chains).
/// Used for initialization.
pub fn generate_nftables_config(services: &[common::ServiceTask], endpoints: &[common::Endpoint]) -> Result<String> {
    let mut batch = Batch::new();

    // 1. Base Table
    batch.add(schema::NfListObject::Table(schema::Table {
        family: types::NfFamily::IP,
        name: "rk8s".into(),
        ..Default::default()
    }));

    // 2. Base Chains (NAT & Filter)
    let base_chains = vec![
        ("nat-prerouting", types::NfChainType::NAT, types::NfHook::Prerouting, -100, None),
        ("nat-output", types::NfChainType::NAT, types::NfHook::Output, -100, None),
        ("nat-postrouting", types::NfChainType::NAT, types::NfHook::Postrouting, 100, None),
        ("filter-prerouting", types::NfChainType::Filter, types::NfHook::Prerouting, -110, Some(types::NfChainPolicy::Accept)),
        ("filter-input", types::NfChainType::Filter, types::NfHook::Input, 0, Some(types::NfChainPolicy::Accept)),
        ("filter-forward", types::NfChainType::Filter, types::NfHook::Forward, 0, Some(types::NfChainPolicy::Accept)),
        ("filter-output", types::NfChainType::Filter, types::NfHook::Output, 0, Some(types::NfChainPolicy::Accept)),
    ];

    for (name, ctype, hook, prio, policy) in base_chains {
        batch.add(schema::NfListObject::Chain(schema::Chain {
            family: types::NfFamily::IP,
            table: "rk8s".into(),
            name: name.into(),
            _type: Some(ctype),
            hook: Some(hook),
            prio: Some(prio),
            policy,
            ..Default::default()
        }));
    }

    // 3. Custom Chains
    batch.add(schema::NfListObject::Chain(schema::Chain {
        family: types::NfFamily::IP,
        table: "rk8s".into(),
        name: "services".into(),
        ..Default::default()
    }));
    batch.add(schema::NfListObject::Chain(schema::Chain {
        family: types::NfFamily::IP,
        table: "rk8s".into(),
        name: "services_tcp".into(),
        ..Default::default()
    }));
    batch.add(schema::NfListObject::Chain(schema::Chain {
        family: types::NfFamily::IP,
        table: "rk8s".into(),
        name: "services_udp".into(),
        ..Default::default()
    }));
    batch.add(schema::NfListObject::Chain(schema::Chain {
        family: types::NfFamily::IP,
        table: "rk8s".into(),
        name: "masquerade".into(),
        ..Default::default()
    }));

    // 4. Base Rules (Jumps)
    let jumps = vec![
        ("nat-prerouting", "services"),
        ("nat-output", "services"),
        ("nat-postrouting", "masquerade"),
    ];
    for (chain, target) in jumps {
        batch.add(schema::NfListObject::Rule(schema::Rule {
            family: types::NfFamily::IP,
            table: "rk8s".into(),
            chain: chain.into(),
            expr: std::borrow::Cow::Owned(vec![
                stmt::Statement::Jump(stmt::JumpTarget { target: target.into() })
            ]),
            ..Default::default()
        }));
    }

    // 5. Masquerade Rules
    let mark_match_stmt = stmt::Statement::Match(stmt::Match {
        left: expr::Expression::BinaryOperation(Box::new(expr::BinaryOperation::AND(
            expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta {
                key: expr::MetaKey::Mark,
            })),
            expr::Expression::Number(0x4000),
        ))),
        right: expr::Expression::Number(0),
        op: stmt::Operator::NEQ,
    });
    batch.add(schema::NfListObject::Rule(schema::Rule {
        family: types::NfFamily::IP,
        table: "rk8s".into(),
        chain: "masquerade".into(),
        expr: std::borrow::Cow::Owned(vec![
            mark_match_stmt,
            stmt::Statement::Masquerade(None)
        ]),
        comment: Some("rk8s-masquerade-marked".into()),
        ..Default::default()
    }));

    // Convert Batch to JSON Value to inject Maps and VMap rules
    let nftables = batch.to_nftables();
    let mut json_value = serde_json::to_value(&nftables)?;

    if let Some(arr) = json_value.get_mut("nftables").and_then(|v| v.as_array_mut()) {
        // A. Flush Table (First command)
        let flush_cmd = json!({
            "flush": { "table": { "family": "ip", "name": "rk8s" } }
        });
        if !arr.is_empty() { arr.insert(1, flush_cmd); }

        // B. Inject Maps (service_map_tcp, service_map_udp)
        let map_tcp = json!({
            "add": { "map": {
                "family": "ip", "table": "rk8s", "name": "service_map_tcp",
                "type": ["ipv4_addr", "inet_service"], "map": "verdict",
                "flags": ["interval"]
            }}
        });
        let map_udp = json!({
            "add": { "map": {
                "family": "ip", "table": "rk8s", "name": "service_map_udp",
                "type": ["ipv4_addr", "inet_service"], "map": "verdict",
                "flags": ["interval"]
            }}
        });
        let nodeport_map_tcp = json!({
            "add": { "map": {
                "family": "ip", "table": "rk8s", "name": "nodeport_map_tcp",
                "type": "inet_service", "map": "verdict",
                "flags": ["interval"]
            }}
        });
        let nodeport_map_udp = json!({
            "add": { "map": {
                "family": "ip", "table": "rk8s", "name": "nodeport_map_udp",
                "type": "inet_service", "map": "verdict",
                "flags": ["interval"]
            }}
        });
        arr.push(map_tcp);
        arr.push(map_udp);
        arr.push(nodeport_map_tcp);
        arr.push(nodeport_map_udp);

        // C. Inject Dispatch Rules in `services` chain
        arr.push(json!({
            "add": { "rule": {
                "family": "ip", "table": "rk8s", "chain": "services",
                "expr": [
                    { "match": { "left": { "meta": { "key": "l4proto" } }, "op": "==", "right": "tcp" } },
                    { "jump": { "target": "services_tcp" } }
                ]
            }}
        }));
        arr.push(json!({
            "add": { "rule": {
                "family": "ip", "table": "rk8s", "chain": "services",
                "expr": [
                    { "match": { "left": { "meta": { "key": "l4proto" } }, "op": "==", "right": "udp" } },
                    { "jump": { "target": "services_udp" } }
                ]
            }}
        }));

        // D. Inject VMap Rules in `services_tcp` and `services_udp`
        // ClusterIP rules first (Priority)
        arr.push(json!({
            "add": { "rule": {
                "family": "ip", "table": "rk8s", "chain": "services_tcp",
                "expr": [
                    { "vmap": {
                        "left": { "concat": [
                            { "payload": { "protocol": "ip", "field": "daddr" } },
                            { "payload": { "protocol": "tcp", "field": "dport" } }
                        ]},
                        "map": "@service_map_tcp"
                    }}
                ]
            }}
        }));
        arr.push(json!({
            "add": { "rule": {
                "family": "ip", "table": "rk8s", "chain": "services_udp",
                "expr": [
                    { "vmap": {
                        "left": { "concat": [
                            { "payload": { "protocol": "ip", "field": "daddr" } },
                            { "payload": { "protocol": "udp", "field": "dport" } }
                        ]},
                        "map": "@service_map_udp"
                    }}
                ]
            }}
        }));

        // NodePort rules (Secondary, with fib check)
        arr.push(json!({
            "add": { "rule": {
                "family": "ip", "table": "rk8s", "chain": "services_tcp",
                "expr": [
                    { "match": {
                        "left": { "fib": { "result": "type", "flags": ["daddr"] } },
                        "op": "==", "right": "local"
                    }},
                    { "vmap": {
                        "left": { "payload": { "protocol": "tcp", "field": "dport" } },
                        "map": "@nodeport_map_tcp"
                    }}
                ]
            }}
        }));
        arr.push(json!({
            "add": { "rule": {
                "family": "ip", "table": "rk8s", "chain": "services_udp",
                "expr": [
                    { "match": {
                        "left": { "fib": { "result": "type", "flags": ["daddr"] } },
                        "op": "==", "right": "local"
                    }},
                    { "vmap": {
                        "left": { "payload": { "protocol": "udp", "field": "dport" } },
                        "map": "@nodeport_map_udp"
                    }}
                ]
            }}
        }));

        // E. Inject Hairpin Rule
        let hairpin_rule = json!({
            "rule": {
                "family": "ip", "table": "rk8s", "chain": "masquerade",
                "expr": [
                    { "match": { "left": { "&": [ { "ct": { "key": "status" } }, 2 ] }, "op": "!=", "right": 0 } },
                    { "masquerade": null }
                ],
                "comment": "rk8s-masquerade-hairpin"
            }
        });
        arr.push(hairpin_rule);
    }

    // 6. Generate Service Chains & Map Elements (Full Sync)
    let mut parsed_endpoints = std::collections::HashMap::new();
    for ep in endpoints {
        parsed_endpoints.insert((ep.metadata.namespace.clone(), ep.metadata.name.clone()), ep);
    }

    for svc in services {
        let ep = parsed_endpoints.get(&(svc.metadata.namespace.clone(), svc.metadata.name.clone()))
            .map(|&e| e.clone())
            .unwrap_or_else(|| common::Endpoint {
                api_version: "v1".into(),
                kind: "Endpoints".into(),
                metadata: svc.metadata.clone(),
                subsets: vec![],
            });
        
        let update_json = generate_service_update(svc, &ep)?;
        let update_val: serde_json::Value = serde_json::from_str(&update_json)?;
        if let Some(cmds) = update_val.get("nftables").and_then(|v| v.as_array()) {
            for cmd in cmds {
                if let Some(arr) = json_value.get_mut("nftables").and_then(|v| v.as_array_mut()) {
                    arr.push(cmd.clone());
                }
            }
        }
    }

    Ok(serde_json::to_string(&json_value)?)
}

/// Generates incremental update commands for a single Service.
pub fn generate_service_update(svc: &common::ServiceTask, ep: &common::Endpoint) -> Result<String> {
    let cluster_ip = match svc.spec.cluster_ip.as_deref() {
        Some(ip) if ip != "None" && !ip.is_empty() => ip,
        _ => return Ok(json!({"nftables": []}).to_string()),
    };

    let mut commands = Vec::new();

    for svc_port in &svc.spec.ports {
        let protocol = svc_port.protocol.to_lowercase();
        let chain_name = format!("svc-{}-{}-{}", svc.metadata.namespace, svc.metadata.name, svc_port.port);
        let backend_map_name = format!("be-{}-{}-{}", svc.metadata.namespace, svc.metadata.name, svc_port.port);
        let map_name = if protocol == "udp" { "service_map_udp" } else { "service_map_tcp" };

        // 1. Create Chain (Idempotent) & Flush
        commands.push(json!({ "add": { "chain": { "family": "ip", "table": "rk8s", "name": chain_name.clone() } } }));
        commands.push(json!({ "flush": { "chain": { "family": "ip", "table": "rk8s", "name": chain_name.clone() } } }));

        // 2. Build Backends
        let mut backends = Vec::new();
        for subset in &ep.subsets {
            let target_port = subset.ports.iter().find(|p| {
                match (&svc_port.name, &p.name) {
                    (Some(n1), Some(n2)) => n1 == n2,
                    (None, None) => true,
                    // Strict matching: if service port has name, endpoint must match.
                    // If service port has no name, endpoint must have no name (or we assume single port).
                    (None, Some(_)) => false, 
                    _ => false,
                }
            });

            if let Some(tp) = target_port {
                for addr in &subset.addresses {
                    backends.push((addr.ip.clone(), tp.port));
                }
            }
        }

        // 3. Generate Rules (Reject or DNAT)
        if backends.is_empty() {
            let reject_type = if protocol == "tcp" { "tcp reset" } else { "icmp type host-unreachable" };
            commands.push(json!({
                "add": { "rule": {
                    "family": "ip", "table": "rk8s", "chain": chain_name.clone(),
                    "expr": [ { "reject": { "type": reject_type } } ],
                    "comment": "Reject (no endpoints)"
                }}
            }));
        } else {
            // Create Backend Map
            commands.push(json!({
                "add": { "map": {
                    "family": "ip", "table": "rk8s", "name": backend_map_name.clone(),
                    "type": "integer",
                    "map": "ipv4_addr",
                    "flags": ["interval"]
                }}
            }));
            commands.push(json!({
                "flush": { "map": {
                    "family": "ip", "table": "rk8s", "name": backend_map_name.clone()
                }}
            }));

            let backend_count = backends.len();
            let backend_port = backends[0].1; // Assume uniform port
            
            let mut map_elems = Vec::new();
            for (i, (ip, _)) in backends.iter().enumerate() {
                map_elems.push(json!([i, ip]));
            }

            if !map_elems.is_empty() {
                commands.push(json!({
                    "add": { "element": {
                        "family": "ip", "table": "rk8s", "name": backend_map_name.clone(),
                        "elem": map_elems
                    }}
                }));
            }

            commands.push(json!({
                "add": { "rule": {
                    "family": "ip", "table": "rk8s", "chain": chain_name.clone(),
                    "expr": [
                        { "dnat": {
                            "addr": { "map": {
                                "key": { "numgen": { "mode": "random", "mod": backend_count } },
                                "data": format!("@{}", backend_map_name)
                            }},
                            "port": backend_port
                        }}
                    ]
                }}
            }));
        }

        // 4. Update Map Element
        commands.push(json!({
            "add": { "element": {
                "family": "ip", "table": "rk8s", "name": map_name,
                "elem": [
                    {
                        "elem": [ cluster_ip, svc_port.port ],
                        "verdict": { "goto": { "target": chain_name } }
                    }
                ]
            }}
        }));

        // 5. NodePort Logic
        if let Some(node_port) = svc_port.node_port {
            let np_map_name = if protocol == "udp" { "nodeport_map_udp" } else { "nodeport_map_tcp" };
            commands.push(json!({
                "add": { "element": {
                    "family": "ip", "table": "rk8s", "name": np_map_name,
                    "elem": [
                        {
                            "elem": node_port,
                            "verdict": { "goto": { "target": chain_name } }
                        }
                    ]
                }}
            }));
        }
    }

    Ok(json!({ "nftables": commands }).to_string())
}

pub fn generate_service_delete(svc: &common::ServiceTask) -> Result<String> {
    let cluster_ip = match svc.spec.cluster_ip.as_deref() {
        Some(ip) => ip,
        None => return Ok(json!({"nftables": []}).to_string()),
    };

    let mut commands = Vec::new();

    for svc_port in &svc.spec.ports {
        let protocol = svc_port.protocol.to_lowercase();
        let chain_name = format!("svc-{}-{}-{}", svc.metadata.namespace, svc.metadata.name, svc_port.port);
        let backend_map_name = format!("be-{}-{}-{}", svc.metadata.namespace, svc.metadata.name, svc_port.port);
        let map_name = if protocol == "udp" { "service_map_udp" } else { "service_map_tcp" };

        // 1. Delete Map Element
        commands.push(json!({
            "delete": { "element": {
                "family": "ip", "table": "rk8s", "name": map_name,
                "elem": [
                    [ cluster_ip, svc_port.port ]
                ]
            }}
        }));

        if let Some(node_port) = svc_port.node_port {
            let np_map_name = if protocol == "udp" { "nodeport_map_udp" } else { "nodeport_map_tcp" };
            commands.push(json!({
                "delete": { "element": {
                    "family": "ip", "table": "rk8s", "name": np_map_name,
                    "elem": [ node_port ]
                }}
            }));
        }

        // 2. Flush & Delete Chain
        commands.push(json!({
            "flush": { "chain": { "family": "ip", "table": "rk8s", "name": chain_name.clone() } }
        }));
        commands.push(json!({
            "delete": { "chain": { "family": "ip", "table": "rk8s", "name": chain_name } }
        }));

        // 3. Delete Backend Map
        // Note: map must be empty or we flush it? delete map usually requires it to be unreferenced.
        // Since we deleted the chain using it, it should be fine.
        commands.push(json!({
            "delete": { "map": { "family": "ip", "table": "rk8s", "name": backend_map_name } }
        }));
    }

    Ok(json!({ "nftables": commands }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{ServiceTask, ServiceSpec, ServicePort, Endpoint, EndpointSubset, EndpointAddress, EndpointPort, ObjectMeta};
    use serde_json::Value;

    #[test]
    fn test_generate_nftables_config_fixes() {
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
                    EndpointAddress { ip: "10.244.1.2".into(), node_name: None, target_ref: None },
                    EndpointAddress { ip: "10.244.1.3".into(), node_name: None, target_ref: None },
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

        let json_str = generate_nftables_config(&[svc], &[ep]).expect("failed to generate config");
        let json_val: Value = serde_json::from_str(&json_str).expect("failed to parse json");
        let cmds = json_val.get("nftables").unwrap().as_array().unwrap();

        // 1. Check Map Flags (Interval)
        let map_tcp = cmds.iter().find(|c| {
            c.get("add").and_then(|a| a.get("map")).and_then(|m| m.get("name")).and_then(|n| n.as_str()) == Some("service_map_tcp")
        }).expect("service_map_tcp not found");
        
        let flags = map_tcp["add"]["map"]["flags"].as_array().expect("flags missing");
        assert!(flags.iter().any(|f| f.as_str() == Some("interval")), "service_map_tcp missing interval flag");

        // 2. Check Backend Map Type
        let be_map_name = "be-default-mysvc-80";
        let be_map = cmds.iter().find(|c| {
            c.get("add").and_then(|a| a.get("map")).and_then(|m| m.get("name")).and_then(|n| n.as_str()) == Some(be_map_name)
        }).expect("backend map not found");
        
        assert_eq!(be_map["add"]["map"]["type"], "integer");
        assert_eq!(be_map["add"]["map"]["map"], "ipv4_addr");

        // 3. Check Chain Flush
        let chain_name = "svc-default-mysvc-80";
        let flush_cmd = cmds.iter().find(|c| {
            c.get("flush").and_then(|f| f.get("chain")).and_then(|ch| ch.get("name")).and_then(|n| n.as_str()) == Some(chain_name)
        });
        assert!(flush_cmd.is_some(), "flush chain command missing");

        // 4. Check DNAT Numgen Rule
        let dnat_rule = cmds.iter().find(|c| {
            c.get("add").and_then(|a| a.get("rule"))
                .and_then(|r| r.get("chain").and_then(|n| n.as_str())) == Some(chain_name)
                && c.to_string().contains("dnat")
        }).expect("dnat rule not found");

        let exprs = dnat_rule["add"]["rule"]["expr"].as_array().unwrap();
        let dnat_expr = exprs.iter().find(|e| e.get("dnat").is_some()).unwrap();
        let map_obj = &dnat_expr["dnat"]["addr"]["map"];
        
        assert!(map_obj["key"]["numgen"].is_object(), "numgen key missing");
        assert_eq!(map_obj["data"].as_str(), Some(format!("@{}", be_map_name).as_str()), "map reference incorrect");

        // 5. Check VMap Syntax (Concatenation)
        let vmap_rule = cmds.iter().find(|c| {
            c.get("add").and_then(|a| a.get("rule"))
                .and_then(|r| r.get("chain").and_then(|n| n.as_str())) == Some("services_tcp")
                && c.to_string().contains("vmap")
                && c.to_string().contains("service_map_tcp")
        }).expect("vmap rule not found");

        let vmap_expr = vmap_rule["add"]["rule"]["expr"][0]["vmap"].as_object().unwrap();
        assert!(vmap_expr["left"]["concat"].is_array(), "vmap left should be concat");
        assert_eq!(vmap_expr["map"].as_str(), Some("@service_map_tcp"));
    }
}
