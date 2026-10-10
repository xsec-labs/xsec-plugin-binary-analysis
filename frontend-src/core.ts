export type JsonObject = Record<string, unknown>;
export interface Context {
  surface?: { bindingRevision?: string };
  workspace?: { binding?: { projectId?: string; sessionId?: string; assignmentId?: string } };
}
export interface Host {
  apiVersion: number;
  context: Context;
  request(method: string, params: JsonObject): Promise<unknown>;
  onTheme(callback: (theme: Record<string, string>) => void): { dispose(): void };
  onContext(callback: (context: Context) => void): { dispose(): void };
}
export const RPC = Object.freeze({
  importSample: 'xsec.binary.sample.import', samples: 'xsec.binary.samples.list',
  sample: 'xsec.binary.sample.info', start: 'xsec.binary.analysis.start', job: 'xsec.binary.jobs.get',
  functions: 'xsec.binary.functions.list', strings: 'xsec.binary.strings.list', imports: 'xsec.binary.imports.list',
  disassemble: 'xsec.binary.disassemble', cfg: 'xsec.binary.cfg', references: 'xsec.binary.references.list',
  decompile: 'xsec.binary.decompile', annotate: 'xsec.binary.annotation.upsert', evidence: 'xsec.binary.evidence.create',
  debugLaunch: 'xsec.binary.debug.launch', debugAttach: 'xsec.binary.debug.attach',
  debugControl: 'xsec.binary.debug.control', debugSnapshot: 'xsec.binary.debug.snapshot', debugWrite: 'xsec.binary.debug.write',
  patchDraft: 'xsec.binary.patch.draft', patchExport: 'xsec.binary.patch.export', signConfigure: 'xsec.binary.sign.configure',
});
export type ResultKind = 'functions' | 'strings' | 'imports';
export type View = ResultKind | 'samples' | 'debug' | 'advanced';
export const LABELS: Record<View, string> = {
  samples: '受管样本', functions: '函数', strings: '字符串', imports: '导入', debug: '调试', advanced: '证据与补丁',
};
export interface Sample extends JsonObject {
  sampleId: string; sampleSha256: string; format: string; architecture: string | null; slice: string | null;
}
export interface Address extends JsonObject { sampleSha256: string; slice: string | null; addressSpace: string; value: string }
export interface Item extends JsonObject { address?: Address }
export interface Page<T> { items: T[]; nextCursor: string | null; truncated: boolean; coverage?: { detail: string; state: string } }
export interface Job { id: string; state: 'running' | 'completed' | 'failed'; revisionId: string | null; error: string | null }
export interface DebugSnapshot extends JsonObject {
  debugSessionId: string; state: 'launching' | 'stopped' | 'running' | 'detached' | 'exited' | 'failed';
  stopRevision: number; targetKind: 'launched' | 'attached'; targetPid: number;
}
export interface UiError { message: string; operationId: string }

export function record(value: unknown, label: string): JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error(label + '格式无效');
  return value as JsonObject;
}
export function text(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value) throw Error(label + '格式无效');
  return value;
}
function nullableText(value: unknown, label: string) {
  return value === null ? null : text(value, label);
}
export function mcpResult(value: unknown): unknown {
  const result = record(value, 'MCP 响应');
  if (typeof result.isError !== 'boolean' || !Array.isArray(result.content) || result.content.length !== 1)
    throw Error('MCP 响应格式无效');
  const content = record(result.content[0], 'MCP 内容');
  if (content.type !== 'text' || typeof content.text !== 'string') throw Error('MCP 内容格式无效');
  const decoded = JSON.parse(content.text) as unknown;
  if (result.isError) {
    const error = record(decoded, 'MCP 错误');
    throw Error(text(error.error, 'MCP 错误说明'));
  }
  return decoded;
}
export function parseSample(value: unknown): Sample {
  const row = record(value, '样本');
  const sampleSha256 = text(row.sampleSha256, '样本摘要');
  if (!/^[a-f0-9]{64}$/.test(sampleSha256)) throw Error('样本摘要格式无效');
  return { ...row, sampleId: text(row.sampleId, '样本 ID'), sampleSha256,
    format: text(row.format, '样本格式'), architecture: nullableText(row.architecture, '样本架构'), slice: nullableText(row.slice, '样本切片') };
}
export function parseAddress(value: unknown): Address {
  const row = record(value, '地址');
  const address = text(row.value, '地址值');
  if (!/^0x[0-9a-fA-F]{1,16}$/.test(address)) throw Error('地址必须是 64 位十六进制字符串');
  const addressSpace = text(row.addressSpace, '地址空间');
  if (!['file-offset', 'rva', 'va', 'runtime-va'].includes(addressSpace)) throw Error('地址空间无效');
  const sampleSha256 = text(row.sampleSha256, '地址样本摘要');
  if (!/^[a-f0-9]{64}$/.test(sampleSha256)) throw Error('地址样本摘要无效');
  return { ...row, sampleSha256, slice: nullableText(row.slice, '地址切片'), addressSpace, value: address };
}
export function addressInput(address: Address): JsonObject {
  const input: JsonObject = { sampleSha256: address.sampleSha256, addressSpace: address.addressSpace, value: address.value };
  for (const key of ['slice', 'debugSessionId', 'moduleIdentity', 'loadBase', 'rva']) {
    if (address[key] !== null && address[key] !== undefined) input[key] = address[key];
  }
  return input;
}
export function parseItem(value: unknown): Item {
  const row = record(value, '分析条目');
  return row.address === undefined || row.address === null ? { ...row } : { ...row, address: parseAddress(row.address) };
}
export function parsePage<T>(value: unknown, parse: (value: unknown) => T, withCoverage: boolean): Page<T> {
  const row = record(value, '列表');
  if (!Array.isArray(row.items) || typeof row.truncated !== 'boolean') throw Error('列表格式无效');
  const nextCursor = nullableText(row.nextCursor, '分页游标');
  if (nextCursor !== null && !/^\d+$/.test(nextCursor)) throw Error('分页游标格式无效');
  const result: Page<T> = { items: row.items.map(parse), nextCursor, truncated: row.truncated };
  if (withCoverage) {
    const coverage = record(row.coverage, '覆盖信息');
    result.coverage = { state: text(coverage.state, '覆盖状态'), detail: text(coverage.detail, '覆盖说明') };
  }
  return result;
}
export function parseJob(value: unknown, expectedId: string): Job {
  const row = record(value, '分析任务');
  if (row.id !== expectedId || !['running', 'completed', 'failed'].includes(String(row.state))) throw Error('分析任务身份或状态无效');
  const revisionId = nullableText(row.revisionId, '分析版本');
  if (row.state === 'completed' && !revisionId) throw Error('已完成任务缺少分析版本');
  return { id: expectedId, state: row.state as Job['state'], revisionId, error: nullableText(row.error, '任务错误') };
}
export function parseDebug(value: unknown): DebugSnapshot {
  const row = record(value, '调试快照');
  const state = text(row.state, '调试状态');
  if (!['launching', 'stopped', 'running', 'detached', 'exited', 'failed'].includes(state)) throw Error('调试状态无效');
  if (!Number.isSafeInteger(row.stopRevision) || Number(row.stopRevision) < 0) throw Error('停止态版本无效');
  if (row.targetKind !== 'launched' && row.targetKind !== 'attached') throw Error('调试目标类型无效');
  if (!Number.isSafeInteger(row.targetPid) || Number(row.targetPid) < 1 || Number(row.targetPid) > 4294967295) throw Error('调试目标 PID 无效');
  return { ...row, debugSessionId: text(row.debugSessionId, '调试会话 ID'), state: state as DebugSnapshot['state'],
    stopRevision: Number(row.stopRevision), targetKind: row.targetKind, targetPid: Number(row.targetPid) };
}
export function validateCursor(page: Page<unknown>, cursor?: string | null) {
  if (page.nextCursor !== null && BigInt(page.nextCursor) <= BigInt(cursor ?? '0')) throw Error('分页游标没有向前推进');
  if (page.nextCursor !== null && page.items.length === 0) throw Error('分页返回空条目和下一页游标');
}
export function pretty(value: unknown) { return JSON.stringify(value, null, 2); }
export function parseJson(value: string, label: string): JsonObject {
  return record(JSON.parse(value), label);
}
export function failure(error: unknown, operationId: string): UiError {
  const message = (error instanceof Error ? error.message : String(error)).slice(0, 2000);
  return { message, operationId };
}
export function contextKey(context: Context) {
  const binding = context.workspace?.binding;
  return JSON.stringify([binding?.projectId, binding?.sessionId, binding?.assignmentId, context.surface?.bindingRevision]);
}
