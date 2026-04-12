//! MCP tool definitions for the org-package extension.

use convergio_types::extension::McpToolDef;
use serde_json::json;

pub fn org_package_tools() -> Vec<McpToolDef> {
    vec![
        McpToolDef {
            name: "cvg_install_package".into(),
            description: "Install an org package.".into(),
            method: "POST".into(),
            path: "/api/org-packages/install".into(),
            input_schema: json!({"type": "object", "properties": {"package_url": {"type": "string", "description": "Package URL or name"}}, "required": ["package_url"]}),
            min_ring: "trusted".into(),
            path_params: vec![],
        },
        McpToolDef {
            name: "cvg_validate_package".into(),
            description: "Validate an org package.".into(),
            method: "POST".into(),
            path: "/api/org-packages/validate".into(),
            input_schema: json!({"type": "object", "properties": {"package_url": {"type": "string"}}, "required": ["package_url"]}),
            min_ring: "community".into(),
            path_params: vec![],
        },
        McpToolDef {
            name: "cvg_list_packages".into(),
            description: "List installed org packages.".into(),
            method: "GET".into(),
            path: "/api/org-packages".into(),
            input_schema: json!({"type": "object", "properties": {}}),
            min_ring: "community".into(),
            path_params: vec![],
        },
        McpToolDef {
            name: "cvg_get_package".into(),
            description: "Get details of an installed org package.".into(),
            method: "GET".into(),
            path: "/api/org-packages/:id".into(),
            input_schema: json!({"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}),
            min_ring: "community".into(),
            path_params: vec!["id".into()],
        },
        McpToolDef {
            name: "cvg_delete_package".into(),
            description: "Uninstall an org package.".into(),
            method: "DELETE".into(),
            path: "/api/org-packages/:id".into(),
            input_schema: json!({"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}),
            min_ring: "trusted".into(),
            path_params: vec!["id".into()],
        },
    ]
}
