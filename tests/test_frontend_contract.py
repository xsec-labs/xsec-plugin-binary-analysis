import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TOOLS = {
    "binary_sample_import": "binary.sample.import",
    "binary_samples_list": "binary.analysis.read",
    "binary_analysis_start": "binary.analysis.read",
    "binary_job_get": "binary.analysis.read",
    "binary_sample_info": "binary.analysis.read",
    "binary_functions_list": "binary.analysis.read",
    "binary_strings_list": "binary.analysis.read",
    "binary_imports_list": "binary.analysis.read",
    "binary_disassemble": "binary.analysis.read",
    "binary_cfg": "binary.analysis.read",
    "binary_references_list": "binary.analysis.read",
    "binary_decompile": "binary.analysis.read",
    "binary_annotation_upsert": "binary.analysis.read",
    "binary_evidence_create": "binary.analysis.read",
    "binary_debug_launch": "debugger.control",
    "binary_debug_attach": "debugger.control",
    "binary_debug_control": "debugger.control",
    "binary_debug_snapshot": "debugger.read",
    "binary_debug_write": "debugger.write",
    "binary_patch_draft": "binary.patch.export",
    "binary_patch_export": "binary.patch.export",
    "binary_sign_configure": "binary.sign",
}


class FrontendContractTests(unittest.TestCase):
    def test_frontend_and_agent_bind_every_mcp_tool_to_its_capability(self):
        manifest = json.loads((ROOT / "plugin.json").read_text(encoding="utf-8"))
        extension = manifest["extensions"]["com.xsec.desktop"]
        methods = extension["frontendApi"]["methods"]
        bindings = {value["mcpTool"]: value for value in methods.values()}
        self.assertEqual(set(bindings), set(EXPECTED_TOOLS))
        self.assertEqual(len(methods), len(EXPECTED_TOOLS))
        for tool, capability in EXPECTED_TOOLS.items():
            self.assertEqual(bindings[tool]["capability"], capability)
            self.assertEqual(bindings[tool]["binding"], "context")
            self.assertEqual(bindings[tool]["mcpServer"], "binary-analysis")
        agent_tools = extension["contributes"]["agentTools"]
        self.assertEqual({item["mcpTool"] for item in agent_tools.values()}, set(EXPECTED_TOOLS))
        entrypoint = extension["entrypoints"]["frontend"].removeprefix("./")
        self.assertTrue((ROOT / entrypoint).is_file())
        sidecar_entrypoint = extension["entrypoints"]["sidecar"]
        self.assertEqual(sidecar_entrypoint, "./bin/binary-analysis-mcp")
        mcp = json.loads((ROOT / "mcp.json").read_text(encoding="utf-8"))
        server = mcp["mcpServers"]["binary-analysis"]
        self.assertEqual(server["type"], "stdio")
        self.assertEqual(server["command"], sidecar_entrypoint)
        self.assertEqual(server["cwd"], "${PLUGIN_DATA}")


if __name__ == "__main__":
    unittest.main()
