use anyhow::Result;
use common;
use nftables::{schema, types, expr, stmt};
use serde_json::{self, json, Value};

/// Generates the FULL configuration (Table, Base Chains, Maps, and all Service Chains).
/// Used for initialization.
pub fn generate_nftables_config(services: &[common::ServiceTask], endpoints: &[common::Endpoint]) -> Result<String> {
    // We use a vector of Values to mix crate-generated objects and manual JSON (for unsupported features like verdict maps).
    let mut objects: Vec<Value> = Vec::new();

    // Helper to push NfObject
    macro_rules! push_obj {
        ($obj:expr) => {
            objects.push(serde_json::to_value($obj).expect("serialization failed"));
        };
    }

    // 1. Base Table
    push_obj!(schema::NfObject::ListObject(schema::NfListObject::Table(schema::Table {
        family: types::NfFamily::IP,
        name: "rk8s".into(),
        ..Default::default()
    })));

    // 2. Flush Table (Command) - Ensure we start clean
    // Flush expects FlushObject. We use serde to construct it to avoid variant guessing.
    push_obj!(schema::NfObject::CmdObject(schema::NfCmd::Flush(
        serde_json::from_value(json!({
            "table": {
                "family": "ip",
                "name": "rk8s"
            }
        })).expect("valid flush object")
    )));

    // 3. Base Chains (NAT & Filter)
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
        push_obj!(schema::NfObject::ListObject(schema::NfListObject::Chain(schema::Chain {
            family: types::NfFamily::IP,
            table: "rk8s".into(),
            name: name.into(),
            _type: Some(ctype),
            hook: Some(hook),
            prio: Some(prio),
            policy,
            ..Default::default()
        })));
    }

    // 4. Custom Chains
    let custom_chains = vec!["services", "services_tcp", "services_udp", "masquerade"];
    for name in custom_chains {
        push_obj!(schema::NfObject::ListObject(schema::NfListObject::Chain(schema::Chain {
            family: types::NfFamily::IP,
            table: "rk8s".into(),
            name: name.into(),
            ..Default::default()
        })));
    }

    // 5. Maps (Manual JSON)
    // nftables crate SetType does not support "verdict", so we must use manual JSON.
    let maps = vec![
        ("service_map_tcp", vec!["ipv4_addr", "inet_service"]),
        ("service_map_udp", vec!["ipv4_addr", "inet_service"]),
        ("nodeport_map_tcp", vec!["inet_service"]),
        ("nodeport_map_udp", vec!["inet_service"]),
    ];

    for (name, map_types) in maps {
        let type_val = if map_types.len() == 1 {
            json!(map_types[0])
        } else {
            json!(map_types)
        };

        objects.push(json!({
            "map": {
                "family": "ip",
                "table": "rk8s",
                "name": name,
                "type": type_val,
                "map": "verdict",
                "flags": ["interval"]
            }
        }));
    }

    // 6. Base Rules (Jumps)
    let jumps = vec![
        ("nat-prerouting", "services"),
        ("nat-output", "services"),
        ("nat-postrouting", "masquerade"),
    ];
    for (chain, target) in jumps {
        push_obj!(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
            family: types::NfFamily::IP,
            table: "rk8s".into(),
            chain: chain.into(),
            expr: vec![
                stmt::Statement::Jump(stmt::JumpTarget { target: target.into() })
            ].into(),
            ..Default::default()
        })));
    }

    // 7. Dispatch Rules in `services` chain
    // TCP
    push_obj!(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
        family: types::NfFamily::IP,
        table: "rk8s".into(),
        chain: "services".into(),
        expr: vec![
            stmt::Statement::Match(stmt::Match {
                left: json_to_expr(json!({ "meta": { "key": "l4proto" } })),
                op: stmt::Operator::EQ,
                right: expr::Expression::String("tcp".into()),
            }),
            stmt::Statement::Jump(stmt::JumpTarget { target: "services_tcp".into() })
        ].into(),
        ..Default::default()
    })));
    // UDP
    push_obj!(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
        family: types::NfFamily::IP,
        table: "rk8s".into(),
        chain: "services".into(),
        expr: vec![
            stmt::Statement::Match(stmt::Match {
                left: json_to_expr(json!({ "meta": { "key": "l4proto" } })),
                op: stmt::Operator::EQ,
                right: expr::Expression::String("udp".into()),
            }),
            stmt::Statement::Jump(stmt::JumpTarget { target: "services_udp".into() })
        ].into(),
        ..Default::default()
    })));

    // 8. VMap Rules (ClusterIP)
    // TCP: daddr . dport -> @service_map_tcp
    push_obj!(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
        family: types::NfFamily::IP,
        table: "rk8s".into(),
        chain: "services_tcp".into(),
        expr: vec![
            json_to_stmt(json!({
                "vmap": {
                    "key": {
                        "concat": [
                            { "payload": { "protocol": "ip", "field": "daddr" } },
                            { "payload": { "protocol": "tcp", "field": "dport" } }
                        ]
                    },
                    "data": "@service_map_tcp"
                }
            }))
        ].into(),
        ..Default::default()
    })));
    // UDP
    push_obj!(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
        family: types::NfFamily::IP,
        table: "rk8s".into(),
        chain: "services_udp".into(),
        expr: vec![
            json_to_stmt(json!({
                "vmap": {
                    "key": {
                        "concat": [
                            { "payload": { "protocol": "ip", "field": "daddr" } },
                            { "payload": { "protocol": "udp", "field": "dport" } }
                        ]
                    },
                    "data": "@service_map_udp"
                }
            }))
        ].into(),
        ..Default::default()
    })));

    // 9. NodePort Rules (fib type local)
    // TCP
    push_obj!(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
        family: types::NfFamily::IP,
        table: "rk8s".into(),
        chain: "services_tcp".into(),
        expr: vec![
            stmt::Statement::Match(stmt::Match {
                left: json_to_expr(json!({ "fib": { "result": "type", "flags": ["daddr"] } })),
                op: stmt::Operator::EQ,
                right: expr::Expression::String("local".into()),
            }),
            json_to_stmt(json!({
                "vmap": {
                    "key": { "payload": { "protocol": "tcp", "field": "dport" } },
                    "data": "@nodeport_map_tcp"
                }
            }))
        ].into(),
        ..Default::default()
    })));
    // UDP
    push_obj!(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
        family: types::NfFamily::IP,
        table: "rk8s".into(),
        chain: "services_udp".into(),
        expr: vec![
            stmt::Statement::Match(stmt::Match {
                left: json_to_expr(json!({ "fib": { "result": "type", "flags": ["daddr"] } })),
                op: stmt::Operator::EQ,
                right: expr::Expression::String("local".into()),
            }),
            json_to_stmt(json!({
                "vmap": {
                    "key": { "payload": { "protocol": "udp", "field": "dport" } },
                    "data": "@nodeport_map_udp"
                }
            }))
        ].into(),
        ..Default::default()
    })));

    // 10. Masquerade Rules
    let mark_match_stmt = stmt::Statement::Match(stmt::Match {
        left: expr::Expression::BinaryOperation(Box::new(expr::BinaryOperation::AND(
            json_to_expr(json!({ "meta": { "key": "mark" } })),
            expr::Expression::Number(0x4000),
        ))),
        right: expr::Expression::Number(0),
        op: stmt::Operator::NEQ,
    });
    push_obj!(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
        family: types::NfFamily::IP,
        table: "rk8s".into(),
        chain: "masquerade".into(),
        expr: vec![
            mark_match_stmt,
            stmt::Statement::Masquerade(None)
        ].into(),
        comment: Some("rk8s-masquerade-marked".into()),
        ..Default::default()
    })));

    // Hairpin Rule
    push_obj!(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
        family: types::NfFamily::IP,
        table: "rk8s".into(),
        chain: "masquerade".into(),
        expr: vec![
            // ct status & 2 != 0 (DNAT bit)
            stmt::Statement::Match(stmt::Match {
                left: expr::Expression::BinaryOperation(Box::new(expr::BinaryOperation::AND(
                    json_to_expr(json!({ "ct": { "key": "status" } })),
                    expr::Expression::Number(2),
                ))),
                op: stmt::Operator::NEQ,
                right: expr::Expression::Number(0),
            }),
            stmt::Statement::Masquerade(None)
        ].into(),
        comment: Some("rk8s-masquerade-hairpin".into()),
        ..Default::default()
    })));

    // 11. Generate Service Chains & Map Elements (Full Sync)
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
        
        // Generate service update as JSON (legacy/shared function)
        let update_json = generate_service_update(svc, &ep)?;
        
        // Parse it back to Value to merge objects safely
        let update_val: Value = serde_json::from_str(&update_json)?;
        if let Some(arr) = update_val.get("nftables").and_then(|v| v.as_array()) {
            objects.extend(arr.clone());
        }
    }

    Ok(json!({ "nftables": objects }).to_string())
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
        commands.push(json!({
            "delete": { "map": { "family": "ip", "table": "rk8s", "name": backend_map_name } }
        }));
    }

    Ok(json!({ "nftables": commands }).to_string())
}

fn json_to_stmt(v: Value) -> stmt::Statement<'static> {
    serde_json::from_value(v).expect("valid statement json")
}

fn json_to_expr(v: Value) -> expr::Expression<'static> {
    serde_json::from_value(v).expect("valid expression json")
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
            c.get("map").or_else(|| c.get("add").and_then(|a| a.get("map")))
                .and_then(|m| m.get("name"))
                .and_then(|n| n.as_str()) == Some("service_map_tcp")
        }).expect("service_map_tcp not found");
        
        let map_obj = map_tcp.get("map").or_else(|| map_tcp.get("add").and_then(|a| a.get("map"))).unwrap();
        let flags = map_obj["flags"].as_array().expect("flags missing");
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
            let rule = c.get("rule").or_else(|| c.get("add").and_then(|a| a.get("rule")));
            if let Some(r) = rule {
                r.get("chain").and_then(|n| n.as_str()) == Some("services_tcp")
                && c.to_string().contains("vmap")
                && c.to_string().contains("service_map_tcp")
            } else {
                false
            }
        }).expect("vmap rule not found");

        let rule_obj = vmap_rule.get("rule").or_else(|| vmap_rule.get("add").and_then(|a| a.get("rule"))).unwrap();
        let vmap_expr = rule_obj["expr"][0]["vmap"].as_object().unwrap();
        assert!(vmap_expr["key"]["concat"].is_array(), "vmap key should be concat");
        assert_eq!(vmap_expr["data"].as_str(), Some("@service_map_tcp"));
    }
}
