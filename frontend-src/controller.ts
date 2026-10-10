import { RPC, addressInput, contextKey, failure, mcpResult, parseDebug, parseItem, parseJob, parseJson, parsePage, parseSample, record, text, validateCursor,
  type Address, type Context, type DebugSnapshot, type Host, type Item, type JsonObject, type Job, type Page, type ResultKind, type Sample, type UiError, type View } from './core';

export interface State {
  contextRevision: number;
  view: View; samples?: Page<Sample>; result?: Page<Item>; sample?: Sample; revisionId?: string;
  address?: Address; job?: Job; jobId?: string; busy?: string; loading: boolean; status: string;
  error?: UiError; detail?: { title: string; value: unknown }; patchSetId?: string; debug?: DebugSnapshot;
}
type Token = { epoch: number; operationId: string };
const POLL_MS = 1200;
const POLL_WINDOW_MS = 15 * 60 * 1000;

export class BinaryController {
  private state: State = { contextRevision: 0, view: 'samples', loading: false, status: '' };
  private listeners = new Set<() => void>();
  private epoch = 0;
  private detailRevision = 0;
  private resultRevision = 0;
  private disposed = false;
  private pollTimer?: ReturnType<typeof setTimeout>;
  private pollDeadline = 0;
  private binding: string;
  private contextSubscription?: { dispose(): void };
  constructor(private readonly host: Host) { this.binding = contextKey(host.context); }
  analysisRunning = () => Boolean(this.state.jobId && (!this.state.job || this.state.job.state === 'running'));
  snapshot = () => this.state;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  private set(change: Partial<State>) {
    if (this.disposed) return;
    this.state = { ...this.state, ...change };
    for (const listener of this.listeners) listener();
  }
  private valid(token: Token) { return !this.disposed && token.epoch === this.epoch; }
  private token(): Token { return { epoch: this.epoch, operationId: crypto.randomUUID() }; }
  private stopPolling() { if (this.pollTimer !== undefined) clearTimeout(this.pollTimer); this.pollTimer = undefined; }
  private error(cause: unknown, token: Token, action: string) {
    if (!this.valid(token)) return;
    this.detailRevision += 1;
    this.set({ error: failure(cause, token.operationId), status: '', detail: undefined });
    console.error('binary.action.failed', { operation_id: token.operationId, action });
  }
  async request(method: string, params: JsonObject = {}): Promise<unknown> {
    return mcpResult(await this.host.request(method, params));
  }
  private async run(action: string, body: (token: Token) => Promise<void>) {
    if (this.disposed || this.state.busy) return;
    const token = this.token();
    this.set({ busy: action, error: undefined });
    console.info('binary.action.started', { operation_id: token.operationId, action });
    try {
      await body(token);
      if (this.valid(token)) console.info('binary.action.completed', { operation_id: token.operationId, action });
    } catch (cause) { this.error(cause, token, action); }
    finally { if (this.valid(token)) this.set({ busy: undefined, loading: false }); }
  }
  async mount() {
    if (this.contextSubscription || this.disposed) throw Error('二进制分析控制器不可重复挂载');
    this.contextSubscription = this.host.onContext(context => { void this.update(context); });
    console.info('binary.frontend.mounted');
    await this.refreshSamples();
  }
  async update(context: Context) {
    const binding = contextKey(context);
    if (binding === this.binding || this.disposed) return;
    this.binding = binding; this.epoch += 1; this.detailRevision += 1; this.resultRevision += 1; this.stopPolling();
    this.state = { contextRevision: this.epoch, view: 'samples', loading: false, status: '' };
    for (const listener of this.listeners) listener();
    console.info('binary.context.changed', { outcome: 'invalidated' });
    await this.refreshSamples();
  }
  async refreshSamples(more = false) {
    await this.run('samples.read', async token => {
      const cursor = more ? this.state.samples?.nextCursor : undefined;
      if (more && !cursor) throw Error('没有下一页样本');
      this.set({ loading: true, ...(!more ? { samples: undefined } : {}) });
      const page = parsePage(await this.request(RPC.samples, { limit: 50, ...(cursor ? { cursor } : {}) }), parseSample, false);
      validateCursor(page, cursor);
      if (!this.valid(token)) return;
      const items = more ? [...this.state.samples!.items, ...page.items] : page.items;
      const ids = new Set(items.map(item => item.sampleId));
      if (ids.size !== items.length) throw Error('样本分页包含重复标识');
      this.set({ samples: { ...page, items }, status: `受管样本：${items.length}${page.truncated ? ' · 还有更多' : ''}` });
    });
  }
  async importSample() {
    await this.run('sample.import', async token => {
      this.set({ status: '正在等待样本选择与授权…' });
      await this.request(RPC.importSample);
      if (!this.valid(token)) return;
      const page = parsePage(await this.request(RPC.samples, { limit: 50 }), parseSample, false);
      validateCursor(page);
      if (this.valid(token)) this.set({ samples: page, view: 'samples', status: '样本已导入并重新读取。' });
    });
  }
  async sampleInfo(sample: Sample) {
    await this.run('sample.info', async token => {
      const detailRevision = ++this.detailRevision;
      this.set({ detail: { title: '样本信息', value: undefined } });
      const value = await this.request(RPC.sample, { sampleId: sample.sampleId });
      if (this.valid(token) && detailRevision === this.detailRevision) this.set({ detail: { title: '样本信息', value } });
    });
  }
  async start(sample: Sample, mode: string) {
    await this.run('analysis.start', async token => {
      if (mode !== 'full' && mode !== 'fast') throw Error('分析模式无效');
      if (this.analysisRunning()) throw Error('请等待当前分析任务结束后再开始分析');
      this.detailRevision += 1; this.resultRevision += 1;
      this.stopPolling();
      const started = record(await this.request(RPC.start, { sampleId: sample.sampleId, mode }), '分析启动');
      const jobId = text(started.jobId, '分析任务 ID');
      if (started.state !== 'running') throw Error('分析启动状态无效');
      if (!this.valid(token)) return;
      this.pollDeadline = Date.now() + POLL_WINDOW_MS;
      this.set({ sample, jobId, job: undefined, revisionId: undefined, result: undefined, address: undefined,
        patchSetId: undefined, status: '分析任务已启动。', detail: undefined, view: 'samples' });
      await this.poll(token, jobId);
    });
  }
  private async poll(token: Token, jobId: string) {
    if (!this.valid(token) || this.state.jobId !== jobId) return;
    if (Date.now() >= this.pollDeadline) throw Error('状态观察已达到 15 分钟，请显式读取任务状态。');
    const job = parseJob(await this.request(RPC.job, { jobId }), jobId);
    if (!this.valid(token) || this.state.jobId !== jobId) return;
    this.set({ job, status: job.state === 'running' ? '分析进行中…' : job.state === 'completed' ? '分析完成。' : '分析失败。' });
    if (job.state === 'failed') throw Error(job.error ?? '分析引擎返回失败状态');
    if (job.state === 'completed') {
      const view = this.state.view === 'samples' ? 'functions' : this.state.view;
      this.set({ revisionId: job.revisionId!, view });
      if (view === 'functions' || view === 'strings' || view === 'imports') await this.readResults(token, view, false);
      return;
    }
    this.pollTimer = setTimeout(() => {
      this.pollTimer = undefined;
      void this.poll(token, jobId).catch(cause => this.error(cause, token, 'analysis.observe'));
    }, POLL_MS);
  }
  async readJob() {
    await this.run('analysis.read', async token => {
      if (!this.state.jobId) throw Error('当前没有分析任务');
      this.stopPolling(); this.pollDeadline = Date.now() + POLL_WINDOW_MS;
      await this.poll(token, this.state.jobId);
    });
  }
  async view(view: View) {
    if (!(view in { samples: 1, functions: 1, strings: 1, imports: 1, debug: 1, advanced: 1 })) throw Error('页面无效');
    this.detailRevision += 1; this.resultRevision += 1;
    this.set({ view, detail: undefined, result: undefined, loading: false });
    if (view === 'samples' || view === 'debug' || view === 'advanced') return;
    await this.run('results.read', async token => {
      this.set({ view }); await this.readResults(token, view, false);
    });
  }
  private async readResults(token: Token, kind: ResultKind, more: boolean) {
    const resultRevision = ++this.resultRevision;
    const revisionId = this.state.revisionId;
    if (!revisionId) throw Error('请先完成样本分析');
    const cursor = more ? this.state.result?.nextCursor : undefined;
    if (more && !cursor) throw Error('没有下一页分析结果');
    this.set({ loading: true, ...(!more ? { result: undefined } : {}) });
    const page = parsePage(await this.request(RPC[kind], { revisionId, limit: 50, ...(cursor ? { cursor } : {}) }), parseItem, true);
    validateCursor(page, cursor);
    if (!this.valid(token) || resultRevision !== this.resultRevision || this.state.revisionId !== revisionId || this.state.view !== kind) return;
    this.set({ result: { ...page, items: more ? [...this.state.result!.items, ...page.items] : page.items }, loading: false,
      status: page.coverage!.detail + (page.truncated ? ' · 还有更多' : '') });
  }
  async moreResults() {
    await this.run('results.more', async token => {
      const kind = this.state.view;
      if (!['functions', 'strings', 'imports'].includes(kind)) throw Error('当前页面没有分析分页');
      await this.readResults(token, kind as ResultKind, true);
    });
  }
  selectAddress(address: Address) { this.set({ address, status: `当前地址：${address.value}` }); }
  async query(label: string, method: string, address: Address, extra: JsonObject = {}) {
    await this.run('function.query', async token => {
      const detailRevision = ++this.detailRevision;
      if (!([RPC.disassemble, RPC.cfg, RPC.decompile, RPC.references] as string[]).includes(method)) throw Error('查询方法无效');
      if (!this.state.revisionId || !this.state.sample) throw Error('请先完成样本分析');
      if (address.sampleSha256 !== this.state.sample.sampleSha256 || address.slice !== this.state.sample.slice) throw Error('地址与当前样本不匹配');
      this.set({ address });
      this.set({ detail: { title: label, value: undefined } });
      const value = await this.request(method, { revisionId: this.state.revisionId, address: addressInput(address), ...extra });
      if (this.valid(token) && detailRevision === this.detailRevision) this.set({ detail: { title: label, value } });
    });
  }
  async advanced(key: string, method: string, json: string, title: string) {
    await this.run('advanced.' + key, async token => {
      const detailRevision = ++this.detailRevision;
      const methods: Record<string, string> = { references: RPC.references, annotate: RPC.annotate, evidence: RPC.evidence,
        patchDraft: RPC.patchDraft, patchExport: RPC.patchExport, signConfigure: RPC.signConfigure };
      if (methods[key] !== method) throw Error('操作方法与固定映射不匹配');
      this.set({ detail: { title, value: undefined } });
      const value = await this.request(method, parseJson(json, '操作参数'));
      if (!this.valid(token)) return;
      if (key === 'patchDraft') this.set({ patchSetId: text(record(value, '补丁草案').patchSetId, '补丁草案 ID') });
      if (detailRevision === this.detailRevision) this.set({ detail: { title, value } });
    });
  }
  private async debugResult(token: Token, request: Promise<unknown>, title: string) {
    const detailRevision = ++this.detailRevision;
    this.set({ debug: undefined, detail: { title, value: undefined } });
    const debug = parseDebug(await request);
    if (this.valid(token)) this.set({ debug, status: `调试状态：${debug.state} · stopRevision ${debug.stopRevision}`,
      ...(detailRevision === this.detailRevision ? { detail: { title, value: debug } } : {}) });
  }
  async debugLaunch(args: string) {
    await this.run('debug.launch', async token => {
      if (!this.state.sample) throw Error('请先选择并分析一个样本');
      const values: unknown = JSON.parse(args);
      if (!Array.isArray(values) || values.some(value => typeof value !== 'string')) throw Error('启动参数必须是字符串数组');
      await this.debugResult(token, this.request(RPC.debugLaunch, { sampleId: this.state.sample.sampleId, arguments: values }), '启动调试结果');
    });
  }
  async debugAttach(pid: string) {
    await this.run('debug.attach', async token => {
      const value = Number(pid);
      if (!/^\d+$/.test(pid) || !Number.isInteger(value) || value < 1 || value > 4294967295) throw Error('PID 必须是有效的 32 位正整数');
      await this.debugResult(token, this.request(RPC.debugAttach, { pid: value, ...(this.state.sample ? { sampleId: this.state.sample.sampleId } : {}) }), '附加调试结果');
    });
  }
  async debugRead() { await this.run('debug.read', token => this.debugResult(token, this.request(RPC.debugSnapshot), '调试快照')); }
  async debugControl(action: string) {
    await this.run('debug.control.' + action, async token => {
      if (!['continue', 'pause', 'stepIn', 'stepOver', 'stepOut', 'detach', 'terminate'].includes(action)) throw Error('调试控制无效');
      const params: JsonObject = { action };
      if (['continue', 'stepIn', 'stepOver', 'stepOut'].includes(action)) {
        if (!this.state.debug) throw Error('请先读取调试快照');
        params.expectedStopRevision = this.state.debug.stopRevision;
      }
      await this.debugResult(token, this.request(RPC.debugControl, params), '调试控制结果');
    });
  }
  async debugWrite(json: string) {
    await this.run('debug.write', async token => {
      const detailRevision = ++this.detailRevision;
      const debug = this.state.debug;
      if (!debug || debug.state !== 'stopped') throw Error('写入前必须读取停止态快照');
      const params = parseJson(json, '调试写入'); params.expectedStopRevision = debug.stopRevision;
      this.set({ debug: undefined, detail: { title: '写入及快照回读', value: undefined } });
      const write = await this.request(RPC.debugWrite, params);
      if (!this.valid(token)) return;
      const snapshot = parseDebug(await this.request(RPC.debugSnapshot));
      if (this.valid(token)) this.set({ debug: snapshot,
        ...(detailRevision === this.detailRevision ? { detail: { title: '写入及快照回读', value: { write, snapshot } } } : {}) });
    });
  }
  closeDetail() { this.detailRevision += 1; this.set({ detail: undefined }); }
  dispose = () => {
    if (this.disposed) return;
    this.disposed = true; this.epoch += 1; this.stopPolling(); this.contextSubscription?.dispose();
    this.contextSubscription = undefined; this.listeners.clear();
    console.debug('binary.frontend.disposed');
  };
}
