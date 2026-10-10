import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
manifest = json.loads((ROOT / 'plugin.json').read_text())
methods = manifest['extensions']['com.xsec.desktop']['frontendApi']['methods']
source = (ROOT / 'frontend-src/core.ts').read_text()
declared = re.findall(r"'([^']+)'", source.split('export const RPC = Object.freeze({', 1)[1].split('});', 1)[0])
if len(declared) != len(methods) or set(declared) != set(methods):
    raise ValueError('Frontend RPC mapping differs from the manifest')
entry = ROOT / manifest['extensions']['com.xsec.desktop']['entrypoints']['frontend']
bundle = entry.read_bytes()
if re.search(rb'(?:^|;)\s*import\s', bundle):
    raise ValueError('Frontend entry contains an external import')
sbom = json.loads((ROOT / 'com.xsec.desktop/frontend-sbom.cdx.json').read_text())
if sbom['metadata']['component']['hashes'] != [{'alg': 'SHA-256', 'content': hashlib.sha256(bundle).hexdigest()}]:
    raise ValueError('Frontend SBOM hash differs from the entry')
if not (ROOT / 'com.xsec.desktop/THIRD_PARTY_NOTICES.txt').read_text().strip():
    raise ValueError('Frontend notices are empty')
lock = json.loads((ROOT / 'package-lock.json').read_text())
for component in sbom['components']:
    if lock['packages']['node_modules/' + component['name']]['version'] != component['version']:
        raise ValueError('Bundled component differs from the lockfile')
print(f'Frontend package verified: {len(methods)} RPC methods, {len(sbom["components"])} bundled components')
