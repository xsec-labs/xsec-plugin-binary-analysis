import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const directory = mkdtempSync(join(tmpdir(), 'xsec-binary-frontend-'));
let failure;
try {
  execFileSync(process.execPath, ['scripts/build.mjs', '--out-dir', directory], { cwd: root, stdio: 'inherit' });
  for (const path of ['com.xsec.desktop/frontend/index.js', 'com.xsec.desktop/THIRD_PARTY_NOTICES.txt', 'com.xsec.desktop/frontend-sbom.cdx.json']) {
    if (!readFileSync(join(root, path)).equals(readFileSync(join(directory, path)))) throw new Error('Generated frontend artifact differs: ' + path);
  }
} catch (error) { failure = error; }
try { rmSync(directory, { recursive: true }); }
catch (error) { if (failure) throw new AggregateError([failure, error], 'Frontend verification and temporary cleanup failed'); throw error; }
if (failure) throw failure;
console.log('Generated frontend, licenses and SBOM match source');
