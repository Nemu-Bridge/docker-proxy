use docker_proxy::config::{
    AuthConfig, Condition, ConditionNode, GlobalConfig, ProxyConfig, RateLimitConfig,
    ResponseFilterEntry, Rule, TokenEntry,
};
use dialoguer::{Confirm, Input, MultiSelect, Select, theme::ColorfulTheme};
use std::fs;

fn main() {
    let theme = ColorfulTheme::default();

    println!();
    println!("  ===========================================");
    println!("   Docker Proxy -- Interactive Config Builder ");
    println!("  ===========================================");
    println!();

    let port: u16 = Input::with_theme(&theme)
        .with_prompt("Proxy listen port")
        .default(2376)
        .interact_text()
        .unwrap();
    println!();

    let socket_path: String = Input::with_theme(&theme)
        .with_prompt("Docker socket path (leave empty to auto-detect)")
        .allow_empty(true)
        .default("/var/run/docker.sock".to_string())
        .interact_text()
        .unwrap();
    println!();

    let auth_types = vec!["none -- no authentication", "bearer -- single shared secret", "tokens -- per-token roles"];
    let auth_choice = Select::with_theme(&theme)
        .with_prompt("Authentication type")
        .items(&auth_types)
        .default(2)
        .interact()
        .unwrap();
    println!();

    let auth = match auth_choice {
        0 => None,
        1 => {
            let secret: String = Input::with_theme(&theme)
                .with_prompt("Shared secret (supports ${ENV_VAR})")
                .default("${DOCKER_PROXY_SECRET}".to_string())
                .interact_text()
                .unwrap();
            println!();
            Some(AuthConfig {
                auth_type: Some("bearer".to_string()),
                secret: Some(secret),
                tokens: None,
                mtls: None,
            })
        }
        2 => {
            let secret: String = Input::with_theme(&theme)
                .with_prompt("Fallback secret (supports ${ENV_VAR}, leave empty to skip)")
                .allow_empty(true)
                .default(String::new())
                .interact_text()
                .unwrap();
            println!();

            let mut tokens: Vec<TokenEntry> = Vec::new();
            loop {
                println!("--- Add Token ---");
                let token: String = Input::with_theme(&theme)
                    .with_prompt("Token value")
                    .interact_text()
                    .unwrap();
                let roles = vec!["admin", "readonly", "user"];
                let role_idx = Select::with_theme(&theme)
                    .with_prompt("Role for this token")
                    .items(&roles)
                    .default(0)
                    .interact()
                    .unwrap();
                tokens.push(TokenEntry {
                    token,
                    role: Some(roles[role_idx].to_string()),
                });
                println!();
                if !Confirm::with_theme(&theme)
                    .with_prompt("Add another token?")
                    .default(false)
                    .interact()
                    .unwrap()
                {
                    break;
                }
                println!();
            }

            let secret_opt = if secret.is_empty() { None } else { Some(secret) };
            Some(AuthConfig {
                auth_type: Some("bearer".to_string()),
                secret: secret_opt,
                tokens: if tokens.is_empty() { None } else { Some(tokens) },
                mtls: None,
            })
        }
        _ => None,
    };

    let global = Some(GlobalConfig {
        port: Some(port),
        socket: if socket_path.is_empty() { None } else { Some(socket_path) },
        ..GlobalConfig::default()
    });

    let mut rules: Vec<Rule> = Vec::new();
    let mut first_rule = true;
    println!();
    loop {
        if first_rule {
            if !Confirm::with_theme(&theme)
                .with_prompt("Add access rules?")
                .default(true)
                .interact()
                .unwrap()
            {
                break;
            }
            first_rule = false;
        }

        println!();
        let templates = vec![
            "Block dangerous operations (exec, build)",
            "Read-only volumes (deny non-GET)",
            "Read-only networks (deny non-GET)",
            "Read-only images (deny non-GET)",
            "Block secrets & configs entirely",
            "Block privileged containers",
            "Block bind mounts",
            "Block host network mode",
            "Admin-only container lifecycle (start/stop/kill/etc)",
            "Admin-only create containers",
            "Admin-only delete resources",
            "Internal network only (IP CIDR whitelist)",
            "Redact container environment variables",
            "Rate limit all requests",
            "-- Custom rule (build manually) --",
        ];
        let chosen: Vec<usize> = MultiSelect::with_theme(&theme)
            .with_prompt("Select rule templates to add (space to select, enter to confirm)")
            .items(&templates)
            .interact()
            .unwrap();
        println!();

        for &idx in &chosen {
            match idx {
                0 => {
                    rules.push(Rule {
                        name: "block-exec-operations".to_string(),
                        description: Some("Prevent creating or starting exec sessions".to_string()),
                        action: "deny".to_string(),
                        conditions: vec![ConditionNode::Or {
                            or: vec![ConditionNode::Leaf(Condition {
                                field: "path".to_string(),
                                operator: "matches".to_string(),
                                value: Some(serde_yaml::Value::String(
                                    "^/containers/[^/]+/exec$".to_string(),
                                )),
                            }), ConditionNode::Leaf(Condition {
                                field: "path".to_string(),
                                operator: "matches".to_string(),
                                value: Some(serde_yaml::Value::String(
                                    "^/exec/[^/]+/start$".to_string(),
                                )),
                            })],
                        }],
                        message: Some("Exec operations are not permitted".to_string()),
                        status: Some(403),
                        ..Rule::default()
                    });
                    rules.push(build_simple_deny(
                        "block-docker-build",
                        "Prevent image builds via the API",
                        "path", "starts_with", "/build",
                        "Image building is not permitted via this proxy",
                    ));
                }
                1 => {
                    rules.push(build_readonly("readonly-volumes", "/volumes"));
                }
                2 => {
                    rules.push(build_readonly("readonly-networks", "/networks"));
                }
                3 => {
                    rules.push(build_readonly("readonly-images", "/images"));
                }
                4 => {
                    rules.push(build_simple_deny(
                        "block-secrets", "Block access to secrets",
                        "path", "starts_with", "/secrets",
                        "Secrets are not accessible",
                    ));
                    rules.push(build_simple_deny(
                        "block-configs", "Block access to configs",
                        "path", "starts_with", "/configs",
                        "Configs are not accessible",
                    ));
                }
                5 => {
                    rules.push(Rule {
                        name: "block-privileged-containers".to_string(),
                        description: Some("Prevent creating containers with --privileged".to_string()),
                        action: "deny".to_string(),
                        conditions: vec![
                            ConditionNode::Leaf(Condition {
                                field: "path".to_string(),
                                operator: "equals".to_string(),
                                value: Some(serde_yaml::Value::String("/containers/create".to_string())),
                            }),
                            ConditionNode::Leaf(Condition {
                                field: "body.HostConfig.Privileged".to_string(),
                                operator: "equals".to_string(),
                                value: Some(serde_yaml::Value::Bool(true)),
                            }),
                        ],
                        message: Some("Privileged containers are not allowed".to_string()),
                        status: Some(403),
                        ..Rule::default()
                    });
                }
                6 => {
                    rules.push(Rule {
                        name: "block-bind-mounts".to_string(),
                        description: Some("Prevent containers from bind mounting".to_string()),
                        action: "deny".to_string(),
                        conditions: vec![
                            ConditionNode::Leaf(Condition {
                                field: "path".to_string(),
                                operator: "equals".to_string(),
                                value: Some(serde_yaml::Value::String("/containers/create".to_string())),
                            }),
                            ConditionNode::Leaf(Condition {
                                field: "body.HostConfig.Binds".to_string(),
                                operator: "exists".to_string(),
                                value: None,
                            }),
                        ],
                        message: Some("Bind mounts are not allowed".to_string()),
                        status: Some(403),
                        ..Rule::default()
                    });
                }
                7 => {
                    rules.push(Rule {
                        name: "block-host-network".to_string(),
                        description: Some("Prevent containers from using host networking".to_string()),
                        action: "deny".to_string(),
                        conditions: vec![
                            ConditionNode::Leaf(Condition {
                                field: "path".to_string(),
                                operator: "equals".to_string(),
                                value: Some(serde_yaml::Value::String("/containers/create".to_string())),
                            }),
                            ConditionNode::Leaf(Condition {
                                field: "body.HostConfig.NetworkMode".to_string(),
                                operator: "equals".to_string(),
                                value: Some(serde_yaml::Value::String("host".to_string())),
                            }),
                        ],
                        message: Some("Host network mode is not allowed".to_string()),
                        status: Some(403),
                        ..Rule::default()
                    });
                }
                8 => {
                    rules.push(Rule {
                        name: "admin-only-container-lifecycle".to_string(),
                        description: Some("Only admins can start/stop/restart/kill containers".to_string()),
                        action: "require_role".to_string(),
                        conditions: vec![ConditionNode::Leaf(Condition {
                            field: "path".to_string(),
                            operator: "matches".to_string(),
                            value: Some(serde_yaml::Value::String(
                                "^/containers/[^/]+/(start|stop|restart|kill|pause|unpause|rename|update)$".to_string(),
                            )),
                        })],
                        role: Some("admin".to_string()),
                        message: Some("Admin role required for container lifecycle operations".to_string()),
                        status: Some(403),
                        ..Rule::default()
                    });
                }
                9 => {
                    rules.push(Rule {
                        name: "admin-only-create".to_string(),
                        description: Some("Only admins can create containers".to_string()),
                        action: "require_role".to_string(),
                        conditions: vec![ConditionNode::Leaf(Condition {
                            field: "path".to_string(),
                            operator: "equals".to_string(),
                            value: Some(serde_yaml::Value::String("/containers/create".to_string())),
                        })],
                        role: Some("admin".to_string()),
                        message: Some("Admin role required to create containers".to_string()),
                        status: Some(403),
                        ..Rule::default()
                    });
                }
                10 => {
                    rules.push(Rule {
                        name: "admin-only-delete".to_string(),
                        description: Some("Only admins can delete resources".to_string()),
                        action: "require_role".to_string(),
                        conditions: vec![ConditionNode::Leaf(Condition {
                            field: "method".to_string(),
                            operator: "equals".to_string(),
                            value: Some(serde_yaml::Value::String("DELETE".to_string())),
                        })],
                        role: Some("admin".to_string()),
                        message: Some("Admin role required for delete operations".to_string()),
                        status: Some(403),
                        ..Rule::default()
                    });
                }
                11 => {
                    rules.push(Rule {
                        name: "internal-network-only".to_string(),
                        description: Some("Restrict access to private network ranges and localhost".to_string()),
                        action: "deny".to_string(),
                        conditions: vec![ConditionNode::Leaf(Condition {
                            field: "client_ip".to_string(),
                            operator: "not_in".to_string(),
                            value: Some(serde_yaml::Value::Sequence(vec![
                                serde_yaml::Value::String("10.0.0.0/8".to_string()),
                                serde_yaml::Value::String("172.16.0.0/12".to_string()),
                                serde_yaml::Value::String("192.168.0.0/16".to_string()),
                                serde_yaml::Value::String("127.0.0.0/8".to_string()),
                            ])),
                        })],
                        message: Some("Access restricted to internal network".to_string()),
                        status: Some(403),
                        ..Rule::default()
                    });
                }
                12 => {
                    rules.push(Rule {
                        name: "redact-container-environment".to_string(),
                        description: Some("Redact environment variables and commands from container inspect".to_string()),
                        action: "response_filter".to_string(),
                        conditions: vec![ConditionNode::Leaf(Condition {
                            field: "path".to_string(),
                            operator: "matches".to_string(),
                            value: Some(serde_yaml::Value::String(
                                "^/containers/[^/]+/json$".to_string(),
                            )),
                        })],
                        response_filter: Some(vec![
                            ResponseFilterEntry {
                                field: "Config.Env".to_string(),
                                action: "redact".to_string(),
                                replacement: None,
                            },
                            ResponseFilterEntry {
                                field: "Config.Cmd".to_string(),
                                action: "redact".to_string(),
                                replacement: None,
                            },
                        ]),
                        ..Rule::default()
                    });
                }
                13 => {
                    rules.push(Rule {
                        name: "rate-limit-all".to_string(),
                        description: Some("Limit requests to 50 per 30 seconds, 30s penalty on exceed".to_string()),
                        action: "rate_limit".to_string(),
                        conditions: vec![ConditionNode::Leaf(Condition {
                            field: "path".to_string(),
                            operator: "matches".to_string(),
                            value: Some(serde_yaml::Value::String("^/".to_string())),
                        })],
                        rate_limit: Some(RateLimitConfig {
                            requests: 50,
                            period: 30,
                            penalty: 30,
                        }),
                        message: Some("Rate limit exceeded. You are blocked for 30 seconds.".to_string()),
                        status: Some(429),
                        ..Rule::default()
                    });
                }
                14 => {
                    match build_custom_rule(&theme) {
                        Some(rule) => rules.push(rule),
                        None => println!("  (custom rule cancelled)"),
                    }
                }
                _ => {}
            }
        }

        println!();
        if !Confirm::with_theme(&theme)
            .with_prompt("Add more rules?")
            .default(false)
            .interact()
            .unwrap()
        {
            break;
        }
    }

    let config = ProxyConfig {
        global,
        auth,
        rules: if rules.is_empty() { None } else { Some(rules) },
    };

    let yaml = serde_yaml::to_string(&config).expect("failed to serialize config");
    fs::write("config.yaml", &yaml).expect("failed to write config.yaml");

    println!();
    println!("  config.yaml written successfully.");
    println!("  {} rules configured.", config.rules.as_ref().map(|r| r.len()).unwrap_or(0));
    println!();
    println!("  Run with:  cargo run");
    println!("  Or:        DOCKER_PROXY_CONFIG=./config.yaml cargo run");
    println!();
}

fn build_simple_deny(
    name: &str,
    description: &str,
    field: &str,
    operator: &str,
    value: &str,
    message: &str,
) -> Rule {
    Rule {
        name: name.to_string(),
        description: Some(description.to_string()),
        action: "deny".to_string(),
        conditions: vec![ConditionNode::Leaf(Condition {
            field: field.to_string(),
            operator: operator.to_string(),
            value: Some(serde_yaml::Value::String(value.to_string())),
        })],
        message: Some(message.to_string()),
        status: Some(403),
        ..Rule::default()
    }
}

fn build_readonly(name: &str, prefix: &str) -> Rule {
    let resource = prefix.trim_start_matches('/');
    Rule {
        name: name.to_string(),
        description: Some(format!("Only GET is allowed on {resource}")),
        action: "deny".to_string(),
        conditions: vec![
            ConditionNode::Leaf(Condition {
                field: "path".to_string(),
                operator: "starts_with".to_string(),
                value: Some(serde_yaml::Value::String(prefix.to_string())),
            }),
            ConditionNode::Leaf(Condition {
                field: "method".to_string(),
                operator: "not_equals".to_string(),
                value: Some(serde_yaml::Value::String("GET".to_string())),
            }),
        ],
        message: Some(format!("{resource} mutations are forbidden")),
        status: Some(403),
        ..Rule::default()
    }
}

fn build_custom_rule(theme: &ColorfulTheme) -> Option<Rule> {
    println!();
    println!("  --- Custom Rule Builder ---");

    let name: String = Input::with_theme(theme)
        .with_prompt("Rule name")
        .interact_text()
        .unwrap();

    let actions = vec![
        "deny -- block the request",
        "allow -- explicitly allow (override broader rules)",
        "require_role -- require specific auth role",
        "response_filter -- redact/remove response JSON fields",
        "rate_limit -- token-bucket rate limiting",
    ];
    let action_idx = Select::with_theme(theme)
        .with_prompt("Action")
        .items(&actions)
        .default(0)
        .interact()
        .unwrap();
    let action = match action_idx {
        0 => "deny",
        1 => "allow",
        2 => "require_role",
        3 => "response_filter",
        4 => "rate_limit",
        _ => return None,
    };
    println!();

    let message: String = Input::with_theme(theme)
        .with_prompt("Block message (shown to client)")
        .default("Forbidden".to_string())
        .interact_text()
        .unwrap();
    println!();

    let mut conditions: Vec<ConditionNode> = Vec::new();
    loop {
        println!("  --- Add Condition ---");
        let fields = vec!["path", "method", "client_ip", "header.<name>", "body.<path>"];
        let field_idx = Select::with_theme(theme)
            .with_prompt("Condition field")
            .items(&fields)
            .default(0)
            .interact()
            .unwrap();
        println!();

        let mut field = fields[field_idx].to_string();
        if field_idx == 3 {
            let hdr: String = Input::with_theme(theme)
                .with_prompt("Header name")
                .default("content-type".to_string())
                .interact_text()
                .unwrap();
            field = format!("header.{hdr}");
        } else if field_idx == 4 {
            let path: String = Input::with_theme(theme)
                .with_prompt("JSON body path (dot notation)")
                .default("HostConfig.Privileged".to_string())
                .interact_text()
                .unwrap();
            field = format!("body.{path}");
        }

        let operators = vec![
            "equals", "not_equals", "contains", "not_contains",
            "starts_with", "ends_with", "matches", "not_matches",
            "in", "not_in", "exists", "not_exists",
        ];
        let op_idx = Select::with_theme(theme)
            .with_prompt("Operator")
            .items(&operators)
            .default(0)
            .interact()
            .unwrap();
        let operator = operators[op_idx].to_string();
        println!();

        let needs_value = !matches!(operator.as_str(), "exists" | "not_exists");
        let value = if needs_value {
            let v: String = Input::with_theme(theme)
                .with_prompt("Value")
                .default(String::new())
                .interact_text()
                .unwrap();
            if v.is_empty() {
                None
            } else {
                Some(serde_yaml::Value::String(v))
            }
        } else {
            None
        };

        conditions.push(ConditionNode::Leaf(Condition {
            field: field.clone(),
            operator: operator.clone(),
            value: value.clone(),
        }));
        println!();

        if !Confirm::with_theme(theme)
            .with_prompt("Add another condition?")
            .default(false)
            .interact()
            .unwrap()
        {
            break;
        }
    }

    let mut rule = Rule {
        name,
        description: None,
        action: action.to_string(),
        conditions,
        message: Some(message),
        status: Some(if action == "rate_limit" { 429 } else { 403 }),
        ..Rule::default()
    };

    match action {
        "require_role" => {
            let roles = vec!["admin", "readonly", "user"];
            let role_idx = Select::with_theme(theme)
                .with_prompt("Required role")
                .items(&roles)
                .default(0)
                .interact()
                .unwrap();
            rule.role = Some(roles[role_idx].to_string());
        }
        "response_filter" => {
            let mut filters = Vec::new();
            loop {
                let fpath: String = Input::with_theme(theme)
                    .with_prompt("JSON field to modify (dot notation)")
                    .default("Config.Env".to_string())
                    .interact_text()
                    .unwrap();
                let filter_actions = vec!["redact -- replace with ***REDACTED***", "remove -- delete the field", "replace -- set to custom value"];
                let fa_idx = Select::with_theme(theme)
                    .with_prompt("Filter action")
                    .items(&filter_actions)
                    .default(0)
                    .interact()
                    .unwrap();
                let fa = match fa_idx {
                    0 => "redact",
                    1 => "remove",
                    2 => "replace",
                    _ => "redact",
                };
                let replacement = if fa == "replace" {
                    Some(Input::<String>::with_theme(theme)
                        .with_prompt("Replacement value")
                        .default("".to_string())
                        .interact_text()
                        .unwrap())
                } else {
                    None
                };
                filters.push(ResponseFilterEntry {
                    field: fpath,
                    action: fa.to_string(),
                    replacement,
                });
                if !Confirm::with_theme(theme)
                    .with_prompt("Add another filter?")
                    .default(false)
                    .interact()
                    .unwrap()
                {
                    break;
                }
            }
            rule.response_filter = Some(filters);
        }
        "rate_limit" => {
            let requests: u64 = Input::with_theme(theme)
                .with_prompt("Max requests per window")
                .default(50u64)
                .interact_text()
                .unwrap();
            let period: u64 = Input::with_theme(theme)
                .with_prompt("Window period (seconds)")
                .default(30u64)
                .interact_text()
                .unwrap();
            let penalty: u64 = Input::with_theme(theme)
                .with_prompt("Penalty cooldown after limit hit (seconds)")
                .default(30u64)
                .interact_text()
                .unwrap();
            rule.rate_limit = Some(RateLimitConfig {
                requests,
                period,
                penalty,
            });
            rule.status = Some(429);
        }
        "deny" | "allow" => {
            let status: u16 = Input::with_theme(theme)
                .with_prompt("HTTP status code")
                .default(if action == "deny" { 403 } else { 200 })
                .interact_text()
                .unwrap();
            rule.status = Some(status);
        }
        _ => {}
    }

    Some(rule)
}
