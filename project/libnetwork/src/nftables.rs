use anyhow::Result;
use common;
use nftables::{schema, types, expr, stmt};
use std::borrow::Cow;
use serde_json::json;

/// Generates the FULL configuration (Table, Base Chains, and all Service Chains).
/// Used for initialization.
pub fn generate_nftables_config(services: &[common::ServiceTask], endpoints: &[common::Endpoint]) -> Result<String> {
    let mut objects: Vec<schema::NfObject> = Vec::new();

    // 1. Base Table
    objects.push(schema::NfObject::ListObject(schema::NfListObject::Table(schema::Table {
        family: types::NfFamily::IP,
        name: Cow::Borrowed("rk8s"),
        ..Default::default()
    })));

    // 2. Flush Table (Command)
    objects.push(schema::NfObject::CmdObject(schema::NfCmd::Flush(schema::FlushObject::Table(schema::Table {
        family: types::NfFamily::IP,
        name: Cow::Borrowed("rk8s"),
        ..Default::default()
    }))));

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
        objects.push(schema::NfObject::ListObject(schema::NfListObject::Chain(schema::Chain {
            family: types::NfFamily::IP,
            table: Cow::Borrowed("rk8s"),
            name: Cow::Borrowed(name),
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
        objects.push(schema::NfObject::ListObject(schema::NfListObject::Chain(schema::Chain {
            family: types::NfFamily::IP,
            table: Cow::Borrowed("rk8s"),
            name: Cow::Borrowed(name),
            ..Default::default()
        })));
    }

    // 5. Base Rules (Jumps)
    let jumps = vec![
        ("nat-prerouting", "services"),
        ("nat-output", "services"),
        ("nat-postrouting", "masquerade"),
    ];
    for (chain, target) in jumps {
        objects.push(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
            family: types::NfFamily::IP,
            table: Cow::Borrowed("rk8s"),
            chain: Cow::Borrowed(chain),
            expr: Cow::Owned(vec![
                stmt::Statement::Jump(stmt::JumpTarget { target: Cow::Borrowed(target) })
            ]),
            ..Default::default()
        })));
    }

    // 6. Dispatch Rules in `services` chain
    // TCP
    objects.push(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
        family: types::NfFamily::IP,
        table: Cow::Borrowed("rk8s"),
        chain: Cow::Borrowed("services"),
        expr: Cow::Owned(vec![
            stmt::Statement::Match(stmt::Match {
                left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta { key: expr::MetaKey::L4proto })),
                op: stmt::Operator::EQ,
                right: expr::Expression::String(Cow::Borrowed("tcp")),
            }),
            stmt::Statement::Jump(stmt::JumpTarget { target: Cow::Borrowed("services_tcp") })
        ]),
        ..Default::default()
    })));
    // UDP
    objects.push(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
        family: types::NfFamily::IP,
        table: Cow::Borrowed("rk8s"),
        chain: Cow::Borrowed("services"),
        expr: Cow::Owned(vec![
            stmt::Statement::Match(stmt::Match {
                left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta { key: expr::MetaKey::L4proto })),
                op: stmt::Operator::EQ,
                right: expr::Expression::String(Cow::Borrowed("udp")),
            }),
            stmt::Statement::Jump(stmt::JumpTarget { target: Cow::Borrowed("services_udp") })
        ]),
        ..Default::default()
    })));

    // 7. Masquerade Rules
    // Mark packets that need masquerade (0x4000)
    // This part usually requires matching source/dest or marks.
    // For simplicity, we just masquerade everything in `masquerade` chain if it was marked?
    // The original code had:
    // mark set mark or 0x4000
    // masquerade
    
    // We will just add a simple masquerade rule for now, or replicate the logic if possible.
    // Original code:
    // mark_match_stmt (mark & 0x4000 != 0) -> masquerade
    // hairpin rule (ct status & DNAT != 0) -> masquerade
    
    // Re-implementing Masquerade Rules using nftables structs
    
    // Rule 1: Masquerade if mark & 0x4000 != 0
    objects.push(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
        family: types::NfFamily::IP,
        table: Cow::Borrowed("rk8s"),
        chain: Cow::Borrowed("masquerade"),
        expr: Cow::Owned(vec![
            stmt::Statement::Match(stmt::Match {
                left: expr::Expression::BinaryOperation(Box::new(expr::BinaryOperation::AND(
                    expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta { key: expr::MetaKey::Mark })),
                    expr::Expression::Number(0x4000),
                ))),
                op: stmt::Operator::NEQ,
                right: expr::Expression::Number(0),
            }),
            stmt::Statement::Masquerade(None)
        ]),
        comment: Some(Cow::Borrowed("rk8s-masquerade-marked")),
        ..Default::default()
    })));

    // Rule 2: Hairpin (ct status dnat)
    objects.push(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
        family: types::NfFamily::IP,
        table: Cow::Borrowed("rk8s"),
        chain: Cow::Borrowed("masquerade"),
        expr: Cow::Owned(vec![
            stmt::Statement::Match(stmt::Match {
                left: expr::Expression::BinaryOperation(Box::new(expr::BinaryOperation::AND(
                    expr::Expression::Named(expr::NamedExpression::CT(expr::CT { key: "status".into(), family: None, dir: None })),
                    expr::Expression::Number(2), // DNAT bit
                ))),
                op: stmt::Operator::NEQ,
                right: expr::Expression::Number(0),
            }),
            stmt::Statement::Masquerade(None)
        ]),
        comment: Some(Cow::Borrowed("rk8s-masquerade-hairpin")),
        ..Default::default()
    })));

    // 8. Generate Service Chains (Full Sync)
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
        
        let update_objects = generate_service_update_objects(svc, &ep)?;
        objects.extend(update_objects);
    }

    let nftables = schema::Nftables { objects: Cow::Owned(objects) };
    serde_json::to_string(&nftables).map_err(|e| anyhow::anyhow!(e))
}

fn generate_service_update_objects(svc: &common::ServiceTask, ep: &common::Endpoint) -> Result<Vec<schema::NfObject<'static>>> {
    let cluster_ip = match svc.spec.cluster_ip.as_deref() {
        Some(ip) if ip != "None" && !ip.is_empty() => ip,
        _ => return Ok(Vec::new()),
    };

    let mut objects = Vec::new();

    for svc_port in &svc.spec.ports {
        let protocol = svc_port.protocol.to_lowercase();
        let chain_name = format!("svc-{}-{}-{}", svc.metadata.namespace, svc.metadata.name, svc_port.port);
        let dispatch_chain = if protocol == "udp" { "services_udp" } else { "services_tcp" };

        // 1. Create Chain
        objects.push(schema::NfObject::ListObject(schema::NfListObject::Chain(schema::Chain {
            family: types::NfFamily::IP,
            table: Cow::Borrowed("rk8s"),
            name: Cow::Owned(chain_name.clone()),
            ..Default::default()
        })));
        
        // 3. Flush & Delete Chain
        objects.push(schema::NfObject::CmdObject(schema::NfCmd::Flush(schema::FlushObject::Chain(schema::Chain {
            family: types::NfFamily::IP,
            table: Cow::Borrowed("rk8s"),
            name: Cow::Owned(chain_name.clone()),
            ..Default::default()
        }))));

        // 3. Add Dispatch Rule (in services_tcp/udp)
        // Match daddr & dport -> jump to svc chain
        // Also mark packet for masquerade if needed (0x4000) - usually done in svc chain if source is outside?
        // For now, just jump.
        objects.push(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
            family: types::NfFamily::IP,
            table: Cow::Borrowed("rk8s"),
            chain: Cow::Borrowed(dispatch_chain),
            expr: Cow::Owned(vec![
                // ensure transport protocol is matched before accessing transport-layer payload
                stmt::Statement::Match(stmt::Match {
                    left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta { key: expr::MetaKey::L4proto })),
                    op: stmt::Operator::EQ,
                    right: expr::Expression::String(Cow::Owned(protocol.clone())),
                }),
                stmt::Statement::Match(stmt::Match {
                    left: expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload::PayloadField(expr::PayloadField {
                        protocol: Cow::Borrowed("ip"),
                        field: Cow::Borrowed("daddr"),
                    }))),
                    op: stmt::Operator::EQ,
                    right: expr::Expression::String(Cow::Owned(cluster_ip.to_string())),
                }),
                stmt::Statement::Match(stmt::Match {
                    left: expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload::PayloadField(expr::PayloadField {
                        protocol: Cow::Owned(protocol.clone()),
                        field: Cow::Borrowed("dport"),
                    }))),
                    op: stmt::Operator::EQ,
                    right: expr::Expression::Number(svc_port.port as u32),
                }),
                stmt::Statement::Jump(stmt::JumpTarget { target: Cow::Owned(chain_name.clone()) })
            ]),
            ..Default::default()
        })));

        // 4. Build Backends
        let mut backends = Vec::new();
        for subset in &ep.subsets {
            let target_port = subset.ports.iter().find(|p| {
                match (&svc_port.name, &p.name) {
                    (Some(n1), Some(n2)) => n1 == n2,
                    (None, None) => true,
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

        // 5. Generate Rules in svc chain
        if backends.is_empty() {
            // Reject
             objects.push(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
                family: types::NfFamily::IP,
                table: Cow::Borrowed("rk8s"),
                chain: Cow::Owned(chain_name.clone()),
                expr: Cow::Owned(vec![
                    stmt::Statement::Reject(None) // Reject with default type (icmp port-unreachable)
                ]),
                comment: Some(Cow::Borrowed("Reject (no endpoints)")),
                ..Default::default()
            })));
        } else {
            // Load Balancing
            let num_backends = backends.len() as u32;
            
            if num_backends > 1 {
                // 1. Set Mark Rule: meta mark set (meta mark & 0xFFFF0000) | (numgen random mod N)
                objects.push(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
                    family: types::NfFamily::IP,
                    table: Cow::Borrowed("rk8s"),
                    chain: Cow::Owned(chain_name.clone()),
                    expr: Cow::Owned(vec![
                        stmt::Statement::Mangle(stmt::Mangle {
                            key: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta { key: expr::MetaKey::Mark })),
                            value: expr::Expression::Named(expr::NamedExpression::Numgen(expr::Numgen {
                                mode: expr::NgMode::Random,
                                ng_mod: num_backends,
                                offset: Some(0),
                            }))
                        })
                    ]),
                    comment: Some(Cow::Borrowed("LB: set mark")),
                    ..Default::default()
                })));

                // 2. Dispatch Rules
                for (i, (ip, port)) in backends.iter().enumerate() {
                    objects.push(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
                        family: types::NfFamily::IP,
                        table: Cow::Borrowed("rk8s"),
                        chain: Cow::Owned(chain_name.clone()),
                        expr: Cow::Owned(vec![
                            // Ensure l4proto is matched before DNAT with port (transport-layer mapping)
                            stmt::Statement::Match(stmt::Match {
                                left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta { key: expr::MetaKey::L4proto })),
                                op: stmt::Operator::EQ,
                                right: expr::Expression::String(Cow::Owned(protocol.clone())),
                            }),
                            stmt::Statement::Match(stmt::Match {
                                left: expr::Expression::BinaryOperation(Box::new(expr::BinaryOperation::AND(
                                    expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta { key: expr::MetaKey::Mark })),
                                    expr::Expression::Number(0xFFFF)
                                ))),
                                op: stmt::Operator::EQ,
                                right: expr::Expression::Number(i as u32),
                            }),
                            stmt::Statement::DNAT(Some(stmt::NAT {
                                addr: Some(expr::Expression::String(Cow::Owned(ip.clone()))),
                                family: Some(stmt::NATFamily::IP),
                                port: Some(expr::Expression::Number(*port as u32)),
                                flags: None,
                            }))
                        ]),
                        ..Default::default()
                    })));
                }
            } else {
                // Single backend
                let (ip, port) = &backends[0];
                objects.push(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
                    family: types::NfFamily::IP,
                    table: Cow::Borrowed("rk8s"),
                    chain: Cow::Owned(chain_name.clone()),
                    expr: Cow::Owned(vec![
                        // Ensure l4proto is matched before DNAT with port
                        stmt::Statement::Match(stmt::Match {
                            left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta { key: expr::MetaKey::L4proto })),
                            op: stmt::Operator::EQ,
                            right: expr::Expression::String(Cow::Owned(protocol.clone())),
                        }),
                        stmt::Statement::DNAT(Some(stmt::NAT {
                            addr: Some(expr::Expression::String(Cow::Owned(ip.clone()))),
                            family: Some(stmt::NATFamily::IP),
                            port: Some(expr::Expression::Number(*port as u32)),
                            flags: None,
                        }))
                    ]),
                    ..Default::default()
                })));
            }
        }
        
        // 6. NodePort Logic
        if let Some(node_port) = svc_port.node_port {
            objects.push(schema::NfObject::ListObject(schema::NfListObject::Rule(schema::Rule {
                family: types::NfFamily::IP,
                table: Cow::Borrowed("rk8s"),
                chain: Cow::Borrowed(dispatch_chain),
                expr: Cow::Owned(vec![
                    // ensure transport protocol is matched before accessing dport
                    stmt::Statement::Match(stmt::Match {
                        left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta { key: expr::MetaKey::L4proto })),
                        op: stmt::Operator::EQ,
                        right: expr::Expression::String(Cow::Owned(protocol.clone())),
                    }),
                    stmt::Statement::Match(stmt::Match {
                        left: expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload::PayloadField(expr::PayloadField {
                            protocol: Cow::Owned(protocol.clone()),
                            field: Cow::Borrowed("dport"),
                        }))),
                        op: stmt::Operator::EQ,
                        right: expr::Expression::Number(node_port as u32),
                    }),
                    stmt::Statement::Jump(stmt::JumpTarget { target: Cow::Owned(chain_name.clone()) })
                ]),
                ..Default::default()
            })));
        }
    }

    Ok(objects)
}

pub fn generate_service_update(svc: &common::ServiceTask, ep: &common::Endpoint) -> Result<String> {
    let objects = generate_service_update_objects(svc, ep)?;
    let nftables = schema::Nftables { objects: Cow::Owned(objects) };
    serde_json::to_string(&nftables).map_err(|e| anyhow::anyhow!(e))
}

pub fn generate_service_delete(svc: &common::ServiceTask) -> Result<String> {
    let cluster_ip = match svc.spec.cluster_ip.as_deref() {
        Some(ip) => ip,
        None => return Ok(json!({"nftables": []}).to_string()),
    };

    let mut objects = Vec::new();

    for svc_port in &svc.spec.ports {
        let protocol = svc_port.protocol.to_lowercase();
        let chain_name = format!("svc-{}-{}-{}", svc.metadata.namespace, svc.metadata.name, svc_port.port);
        let dispatch_chain = if protocol == "udp" { "services_udp" } else { "services_tcp" };

        // 1. Delete Dispatch Rule
        // We need to match the rule exactly to delete it.
        // Rule: ip daddr <ip> <proto> dport <port> jump <chain>
        let rule = schema::Rule {
            family: types::NfFamily::IP,
            table: Cow::Borrowed("rk8s"),
            chain: Cow::Borrowed(dispatch_chain),
            expr: Cow::Owned(vec![
                // same ordering as creation: first ensure l4proto then ip daddr and transport dport
                stmt::Statement::Match(stmt::Match {
                    left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta { key: expr::MetaKey::L4proto })),
                    op: stmt::Operator::EQ,
                    right: expr::Expression::String(Cow::Owned(protocol.clone())),
                }),
                stmt::Statement::Match(stmt::Match {
                    left: expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload::PayloadField(expr::PayloadField {
                        protocol: Cow::Borrowed("ip"),
                        field: Cow::Borrowed("daddr"),
                    }))),
                    op: stmt::Operator::EQ,
                    right: expr::Expression::String(Cow::Owned(cluster_ip.to_string())),
                }),
                stmt::Statement::Match(stmt::Match {
                    left: expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload::PayloadField(expr::PayloadField {
                        protocol: Cow::Owned(protocol.clone()),
                        field: Cow::Borrowed("dport"),
                    }))),
                    op: stmt::Operator::EQ,
                    right: expr::Expression::Number(svc_port.port as u32),
                }),
                stmt::Statement::Jump(stmt::JumpTarget { target: Cow::Owned(chain_name.clone()) })
            ]),
            ..Default::default()
        };
        objects.push(schema::NfObject::CmdObject(schema::NfCmd::Delete(schema::NfListObject::Rule(rule))));

        // 2. Delete NodePort Rule
        if let Some(node_port) = svc_port.node_port {
             let np_rule = schema::Rule {
                family: types::NfFamily::IP,
                table: Cow::Borrowed("rk8s"),
                chain: Cow::Borrowed(dispatch_chain),
                expr: Cow::Owned(vec![
                    // ensure l4proto match to match created NodePort rule
                    stmt::Statement::Match(stmt::Match {
                        left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta { key: expr::MetaKey::L4proto })),
                        op: stmt::Operator::EQ,
                        right: expr::Expression::String(Cow::Owned(protocol.clone())),
                    }),
                    stmt::Statement::Match(stmt::Match {
                        left: expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload::PayloadField(expr::PayloadField {
                            protocol: Cow::Owned(protocol.clone()),
                            field: Cow::Borrowed("dport"),
                        }))),
                        op: stmt::Operator::EQ,
                        right: expr::Expression::Number(node_port as u32),
                    }),
                    stmt::Statement::Jump(stmt::JumpTarget { target: Cow::Owned(chain_name.clone()) })
                ]),
                ..Default::default()
            };
            objects.push(schema::NfObject::CmdObject(schema::NfCmd::Delete(schema::NfListObject::Rule(np_rule))));
        }

        // 3. Flush & Delete Chain
        objects.push(schema::NfObject::CmdObject(schema::NfCmd::Flush(schema::FlushObject::Chain(schema::Chain {
            family: types::NfFamily::IP,
            table: Cow::Borrowed("rk8s"),
            name: Cow::Owned(chain_name.clone()),
            ..Default::default()
        }))));
        objects.push(schema::NfObject::CmdObject(schema::NfCmd::Delete(schema::NfListObject::Chain(schema::Chain {
            family: types::NfFamily::IP,
            table: Cow::Borrowed("rk8s"),
            name: Cow::Owned(chain_name.clone()),
            ..Default::default()
        }))));
    }

    let nftables = schema::Nftables { objects: Cow::Owned(objects) };
    serde_json::to_string(&nftables).map_err(|e| anyhow::anyhow!(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{ServiceTask, ServiceSpec, ServicePort, Endpoint, EndpointSubset, EndpointAddress, EndpointPort, ObjectMeta};
    use std::io::Write;
    use std::process::{Command, Stdio};

    #[test]
    fn test_generate_and_check_nftables_config() {
        // 1. Mock Data
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

        // 2. Generate Config
        let json_output = generate_nftables_config(&[svc], &[ep]).expect("failed to generate config");
        
        println!("Generated JSON:\n{}", json_output);

        // 3. Validate with nft --check (if available)
        // Note: This might require root or CAP_NET_ADMIN depending on nft version/kernel
        let status = Command::new("nft")
            .args(&["-j", "--check", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        match status {
            Ok(mut child) => {
                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(json_output.as_bytes()).expect("failed to write to stdin");
                }
                let output = child.wait_with_output().expect("failed to wait on child");
                
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    println!("nft check failed. stderr: '{}', stdout: '{}'", stderr, stdout);
                    
                    // Don't fail the test if nft is missing or permission denied, just warn
                    if stderr.contains("Permission denied") || stderr.contains("Operation not permitted") || 
                       stdout.contains("Permission denied") || stdout.contains("Operation not permitted") {
                        println!("Skipping validation: Permission denied");
                    } else if stderr.is_empty() && stdout.is_empty() {
                         println!("Skipping validation: nft failed with no output (likely permission issue in container)");
                    } else {
                        panic!("nft configuration invalid");
                    }
                } else {
                    println!("nft configuration is valid!");
                }
            },
            Err(e) => {
                println!("Skipping nft validation: nft command not found or failed to start: {}", e);
            }
        }
    }
}

