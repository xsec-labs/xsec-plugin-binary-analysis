use rmcp::model::Tool;
use serde_json::{json, Map, Value};

pub fn tools() -> Vec<Tool> {
    vec![
        descriptor(
            "binary_sample_import",
            "Open the Host-authorized sample import flow; Fat Mach-O imports expose architecture-specific slice records that must be selected for analysis.",
            empty(),
        ),
        descriptor(
            "binary_samples_list",
            "List Host-authorized binary samples with a cursor.",
            page(),
        ),
        descriptor(
            "binary_analysis_start",
            "Start a full analysis by default, or choose fast explicitly.",
            analysis_start(),
        ),
        descriptor(
            "binary_job_get",
            "Read one analysis job state.",
            required(&["jobId"]),
        ),
        descriptor(
            "binary_sample_info",
            "Read one Host-authorized sample summary.",
            required(&["sampleId"]),
        ),
        descriptor(
            "binary_functions_list",
            "List functions in an immutable analysis revision.",
            revision_page(),
        ),
        descriptor(
            "binary_strings_list",
            "List recovered strings in an immutable analysis revision.",
            revision_page(),
        ),
        descriptor(
            "binary_imports_list",
            "List imported symbols in an immutable analysis revision.",
            revision_page(),
        ),
        descriptor(
            "binary_disassemble",
            "Disassemble a structured binary address.",
            disassemble(),
        ),
        descriptor(
            "binary_cfg",
            "Read the CFG for a structured binary address.",
            address_query(),
        ),
        descriptor(
            "binary_references_list",
            "Read structured cross-references for a binary address.",
            references(),
        ),
        descriptor(
            "binary_decompile",
            "Start structured r2ghidra decompilation for a binary address.",
            address_query(),
        ),
        descriptor(
            "binary_annotation_upsert",
            "Save a local annotation on an immutable analysis revision.",
            annotation(),
        ),
        descriptor(
            "binary_evidence_create",
            "Create Host-managed evidence from a bounded analysis range.",
            evidence(),
        ),
        descriptor(
            "binary_debug_launch",
            "Launch a Host-managed local debug target.",
            debug_launch(),
        ),
        descriptor(
            "binary_debug_attach",
            "Attach to a Host-approved local PID.",
            debug_attach(),
        ),
        descriptor(
            "binary_debug_control",
            "Control the active Host debug session.",
            debug_control(),
        ),
        descriptor(
            "binary_debug_snapshot",
            "Read the active Host debug snapshot.",
            empty(),
        ),
        descriptor(
            "binary_debug_write",
            "Write a stopped Host debug target with optimistic revision control.",
            debug_write(),
        ),
        descriptor(
            "binary_patch_draft",
            "Create an equal-length static patch draft; Fat Mach-O fileOffset values are relative to the selected thin slice.",
            patch_draft(),
        ),
        descriptor(
            "binary_patch_export",
            "Approve, validate and export an immutable patch output.",
            required(&["patchSetId"]),
        ),
        descriptor(
            "binary_sign_configure",
            "Configure an approved signer identity without exposing secrets.",
            sign_configure(),
        ),
    ]
}

fn descriptor(name: &'static str, description: &'static str, schema: Map<String, Value>) -> Tool {
    Tool::new(name, description, schema)
}

fn empty() -> Map<String, Value> {
    schema(json!({ "type": "object", "additionalProperties": false }))
}

fn page() -> Map<String, Value> {
    schema(
        json!({ "type": "object", "additionalProperties": false, "properties": { "cursor": { "type": "string" }, "limit": { "type": "integer", "minimum": 1, "maximum": 200 } } }),
    )
}

fn required(names: &[&str]) -> Map<String, Value> {
    let properties = names
        .iter()
        .map(|name| {
            (
                (*name).to_string(),
                json!({ "type": "string", "minLength": 1 }),
            )
        })
        .collect::<Map<_, _>>();
    schema(
        json!({ "type": "object", "additionalProperties": false, "required": names, "properties": properties }),
    )
}

fn analysis_start() -> Map<String, Value> {
    schema(
        json!({ "type": "object", "additionalProperties": false, "required": ["sampleId"], "properties": { "sampleId": { "type": "string", "minLength": 1 }, "mode": { "type": "string", "enum": ["full", "fast"], "default": "full" } } }),
    )
}

fn revision_page() -> Map<String, Value> {
    schema(
        json!({ "type": "object", "additionalProperties": false, "required": ["revisionId"], "properties": { "revisionId": { "type": "string", "minLength": 1 }, "cursor": { "type": "string" }, "limit": { "type": "integer", "minimum": 1, "maximum": 200 } } }),
    )
}

fn address() -> Value {
    json!({ "type": "object", "additionalProperties": false, "required": ["sampleSha256", "addressSpace", "value"], "properties": { "sampleSha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" }, "slice": { "type": "string" }, "addressSpace": { "type": "string", "enum": ["file-offset", "rva", "va", "runtime-va"] }, "value": { "type": "string", "pattern": "^0x[0-9a-fA-F]+$" }, "debugSessionId": { "type": "string" }, "moduleIdentity": { "type": "string" }, "loadBase": { "type": "string", "pattern": "^0x[0-9a-fA-F]+$" }, "rva": { "type": "string", "pattern": "^0x[0-9a-fA-F]+$" } } })
}

fn disassemble() -> Map<String, Value> {
    schema(
        json!({ "type": "object", "additionalProperties": false, "required": ["revisionId", "address"], "properties": { "revisionId": { "type": "string" }, "address": address(), "count": { "type": "integer", "minimum": 1, "maximum": 512 } } }),
    )
}

fn address_query() -> Map<String, Value> {
    schema(
        json!({ "type": "object", "additionalProperties": false, "required": ["revisionId", "address"], "properties": { "revisionId": { "type": "string" }, "address": address() } }),
    )
}

fn references() -> Map<String, Value> {
    schema(
        json!({ "type": "object", "additionalProperties": false, "required": ["revisionId", "address", "direction"], "properties": { "revisionId": { "type": "string" }, "address": address(), "direction": { "type": "string", "enum": ["to", "from"] } } }),
    )
}

fn annotation() -> Map<String, Value> {
    schema(
        json!({ "type": "object", "additionalProperties": false, "required": ["revisionId", "address", "text", "tags"], "properties": { "revisionId": { "type": "string" }, "address": address(), "text": { "type": "string", "maxLength": 8192 }, "tags": { "type": "array", "maxItems": 32, "items": { "type": "string", "maxLength": 128 } } } }),
    )
}

fn evidence() -> Map<String, Value> {
    schema(
        json!({ "type": "object", "additionalProperties": false, "required": ["revisionId", "start", "summary"], "properties": { "revisionId": { "type": "string" }, "start": address(), "end": address(), "summary": { "type": "string", "maxLength": 8192 } } }),
    )
}

fn debug_launch() -> Map<String, Value> {
    schema(
        json!({ "type": "object", "additionalProperties": false, "required": ["sampleId", "arguments"], "properties": { "sampleId": { "type": "string" }, "arguments": { "type": "array", "maxItems": 64, "items": { "type": "string", "maxLength": 4096 } } } }),
    )
}

fn debug_attach() -> Map<String, Value> {
    schema(
        json!({ "type": "object", "additionalProperties": false, "required": ["pid"], "properties": { "pid": { "type": "integer", "minimum": 1, "maximum": 4294967295u64 }, "sampleId": { "type": "string", "minLength": 1 } } }),
    )
}

fn debug_control() -> Map<String, Value> {
    schema(
        json!({ "type": "object", "additionalProperties": false, "required": ["action"], "properties": { "action": { "type": "string", "enum": ["continue", "pause", "stepIn", "stepOver", "stepOut", "detach", "terminate"] }, "expectedStopRevision": { "type": "integer", "minimum": 0 } } }),
    )
}

fn debug_write() -> Map<String, Value> {
    schema(
        json!({ "type": "object", "additionalProperties": false, "required": ["kind", "expectedStopRevision"], "properties": { "kind": { "type": "string", "enum": ["register", "memory", "softwareBreakpoint"] }, "expectedStopRevision": { "type": "integer", "minimum": 0 }, "register": { "type": "string", "minLength": 1, "maxLength": 16, "pattern": "^[A-Za-z0-9_]+$" }, "value": { "type": "string", "pattern": "^0x[0-9a-fA-F]{1,16}$" }, "address": address(), "expectedBytes": { "type": "string", "pattern": "^0x(?:[0-9a-fA-F]{2})+$" }, "bytes": { "type": "string", "pattern": "^0x(?:[0-9a-fA-F]{2})+$" } }, "oneOf": [{ "required": ["register", "value"], "properties": { "kind": { "const": "register" } } }, { "required": ["address", "expectedBytes", "bytes"], "properties": { "kind": { "const": "memory" } } }, { "required": ["address", "expectedBytes"], "properties": { "kind": { "const": "softwareBreakpoint" } } }] }),
    )
}

fn patch_draft() -> Map<String, Value> {
    schema(
        json!({ "type": "object", "additionalProperties": false, "required": ["revisionId", "sampleSha256", "operations"], "properties": { "revisionId": { "type": "string" }, "sampleSha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" }, "slice": { "type": "string" }, "operations": { "type": "array", "minItems": 1, "maxItems": 512, "items": { "type": "object", "additionalProperties": false, "required": ["rva", "fileOffset", "expectedBytes", "replacementBytes"], "properties": { "rva": { "type": "string", "pattern": "^0x[0-9a-fA-F]+$" }, "fileOffset": { "type": "string", "pattern": "^0x[0-9a-fA-F]+$" }, "expectedBytes": { "type": "string", "pattern": "^0x[0-9a-fA-F]+$" }, "replacementBytes": { "type": "string", "pattern": "^0x[0-9a-fA-F]+$" } } } } } }),
    )
}

fn sign_configure() -> Map<String, Value> {
    schema(
        json!({ "type": "object", "additionalProperties": false, "required": ["kind", "identity"], "properties": { "kind": { "type": "string", "enum": ["macosKeychain", "windowsExternal"] }, "identity": { "type": "string", "minLength": 1, "maxLength": 1024 }, "externalToolPath": { "type": "string", "minLength": 1 }, "externalToolSha256": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$" }, "argumentTemplate": { "type": "array", "minItems": 1, "maxItems": 64, "items": { "type": "string", "minLength": 1, "maxLength": 4096 } }, "verificationCommandPath": { "type": "string", "minLength": 1 }, "verificationCommandSha256": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$" }, "verificationTemplate": { "type": "array", "minItems": 1, "maxItems": 64, "items": { "type": "string", "minLength": 1, "maxLength": 4096 } } } }),
    )
}

fn schema(value: Value) -> Map<String, Value> {
    value
        .as_object()
        .cloned()
        .expect("binary MCP tool schema is an object")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::analysis_start;

    #[test]
    fn full_mode_is_default_and_fast_remains_selectable() {
        let schema = analysis_start();

        assert_eq!(schema.get("required").unwrap(), &json!(["sampleId"]));
        assert_eq!(schema["properties"]["mode"]["default"], json!("full"));
        assert_eq!(
            schema["properties"]["mode"]["enum"],
            json!(["full", "fast"])
        );
    }
}
