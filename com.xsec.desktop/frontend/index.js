function createBinaryApi(host) {
  return {
    importSample: params => host.request("xsec.binary.sample.import", params),
    samples: params => host.request("xsec.binary.samples.list", params),
    sample: params => host.request("xsec.binary.sample.info", params),
    start: params => host.request("xsec.binary.analysis.start", params),
    job: params => host.request("xsec.binary.jobs.get", params),
    functions: params => host.request("xsec.binary.functions.list", params),
    strings: params => host.request("xsec.binary.strings.list", params),
    imports: params => host.request("xsec.binary.imports.list", params),
    disassemble: params => host.request("xsec.binary.disassemble", params),
    cfg: params => host.request("xsec.binary.cfg", params),
    references: params => host.request("xsec.binary.references.list", params),
    decompile: params => host.request("xsec.binary.decompile", params),
    annotate: params => host.request("xsec.binary.annotation.upsert", params),
    evidence: params => host.request("xsec.binary.evidence.create", params),
    debugLaunch: params => host.request("xsec.binary.debug.launch", params),
    debugAttach: params => host.request("xsec.binary.debug.attach", params),
    debugControl: params => host.request("xsec.binary.debug.control", params),
    debugSnapshot: params => host.request("xsec.binary.debug.snapshot", params),
    debugWrite: params => host.request("xsec.binary.debug.write", params),
    patchDraft: params => host.request("xsec.binary.patch.draft", params),
    patchExport: params => host.request("xsec.binary.patch.export", params),
    signConfigure: params => host.request("xsec.binary.sign.configure", params),
  };
}
const PAGE_LABELS = { functions: "函数", strings: "字符串", imports: "导入" };
const POLL_MS = 1200;
const ADVANCED = [
  { key: "references", label: "引用查询" }, { key: "annotate", label: "保存注释" },
  { key: "evidence", label: "创建证据" }, { key: "patchDraft", label: "补丁草案" },
  { key: "patchExport", label: "导出补丁" }, { key: "signConfigure", label: "签名配置" },
];

function payload(result) {
  if (result?.isError) throw new Error(result?.content?.[0]?.text ?? "二进制分析请求失败");
  const text = result?.content?.[0]?.text;
  if (typeof text !== "string") throw new Error("二进制分析 MCP 返回格式无效");
  const value = JSON.parse(text);
  if (value?.error) throw new Error(value.error);
  return value;
}
function requirePage(value, withCoverage = false) {
  if (!value || typeof value !== "object" || !Array.isArray(value.items)
      || !(value.nextCursor === null || typeof value.nextCursor === "string")
      || typeof value.truncated !== "boolean") throw new Error("二进制分析分页返回格式无效");
  if (withCoverage && (!value.coverage || typeof value.coverage.detail !== "string")) {
    throw new Error("二进制分析覆盖信息返回格式无效");
  }
  return value;
}
function el(tag, text, className) {
  const value = document.createElement(tag);
  if (text !== undefined) value.textContent = text;
  if (className) value.className = className;
  return value;
}
function field(label, type = "text", value = "") {
  const wrap = el("label", undefined, "ba-field"); wrap.append(el("span", label));
  const input = el("input"); input.type = type; input.value = value;
  wrap.append(input); return { wrap, input };
}
function area(label, value = "") {
  const wrap = el("label", undefined, "ba-field"); wrap.append(el("span", label));
  const input = el("textarea"); input.value = value; wrap.append(input);
  return { wrap, input };
}
function selectField(label, options) {
  const wrap = el("label", undefined, "ba-field"); wrap.append(el("span", label));
  const input = el("select");
  for (const [name, value] of options) input.append(new Option(name, value));
  wrap.append(input); return { wrap, input };
}
function parseJson(value, label) {
  try { return JSON.parse(value); }
  catch (error) { throw new Error(label + " JSON 无效：" + String(error)); }
}
function pretty(value) { return JSON.stringify(value, null, 2); }
function sampleText(sample) {
  const digest = String(sample.sampleSha256 ?? "");
  return (sample.format ?? "未知格式") + " · " + (sample.architecture ?? "未知架构") + " · " + digest.slice(0, 16) + "…";
}
function installStyles() {
  if (document.getElementById("xsec-binary-analysis-style")) return;
  const style = el("style"); style.id = "xsec-binary-analysis-style";
  style.textContent = ':root{font-family:var(--xsec-font-family,Inter,sans-serif);color:#dde5f1;background:#0c111a}*{box-sizing:border-box}html,body,[data-xsec-plugin-root]{width:100%;height:100%;margin:0}.ba{height:100%;display:flex;flex-direction:column;background:#0c111a}.ba-header,.ba-tabs{display:flex;align-items:center;gap:8px;padding:10px 12px;border-bottom:1px solid #263247}.ba-title{font-weight:700}.ba-meta{color:#91a0b9;font-size:12px}.ba-list{overflow:auto;flex:1;padding:8px 12px}.ba-card,.ba-panel{margin:8px 0;padding:10px;border:1px solid #29364d;border-radius:8px;background:#111927}.ba-card strong,.ba-card span,.ba-field span{display:block}.ba-card span,.ba-field span{margin:4px 0;color:#9babc2;font-size:12px}.ba-status{min-height:20px;padding:8px 12px;color:#f7bd76;font-size:12px}.ba-error{color:#ff9b9b}.ba-detail{white-space:pre-wrap;overflow-wrap:anywhere;font:12px ui-monospace,monospace}.ba-tabs,.ba-actions{display:flex;flex-wrap:wrap;gap:8px}.ba-field{display:block;min-width:180px;margin:8px 0}.ba-field input,.ba-field textarea,.ba-field select{width:100%}.ba-field textarea{min-height:130px;resize:vertical}button,select,input,textarea{border:1px solid #3b4a63;border-radius:6px;background:#182337;color:#e8eef9;padding:6px 9px;font:inherit}button{cursor:pointer}button:hover{background:#243451}button:disabled{cursor:wait;opacity:.6}.ba-note{color:#9babc2;font-size:12px}';
  document.head.append(style);
}

class ViewCancelled extends Error {
  constructor(cause) { super("Binary analysis view was cancelled", { cause }); this.name = "ViewCancelled"; }
}

class BinaryAnalysisView {
  constructor(api) {
    Object.assign(this, { api, disposed: false, currentJob: null, currentRevision: null, currentSample: null, selectedAddress: null, currentKind: "functions", nextCursor: null, sampleCursor: null, pollTimer: null, patchSetId: null, snapshot: null, debugTargetKind: null });
    this.events = new AbortController();
  }
  setStatus(message, failed = false) {
    if (this.disposed) return;
    this.status.textContent = message ?? "";
    this.status.classList.toggle("ba-error", failed);
  }
  async perform(operation) {
    if (this.disposed) throw new ViewCancelled();
    try {
      const result = await operation();
      if (this.disposed) throw new ViewCancelled();
      return payload(result);
    } catch (error) {
      if (this.disposed && !(error instanceof ViewCancelled)) throw new ViewCancelled(error);
      throw error;
    }
  }
  actionButton(label, action) {
    const control = el("button", label);
    control.addEventListener("click", () => this.runButton(control, label, action), { signal: this.events.signal });
    return control;
  }
  async runButton(control, label, action) {
    if (this.disposed) return;
    control.disabled = true;
    try {
      console.info("binary.action.started", { action: label });
      const result = await action();
      if (result !== undefined) this.showOutput(result);
      console.info("binary.action.completed", { action: label });
    } catch (error) {
      if (error instanceof ViewCancelled && this.disposed) { console.debug("binary.action.cancelled", { action: label }); return; }
      this.setStatus(String(error), true);
      console.error("binary.action.failed", { action: label, message: String(error) });
    } finally { if (!this.disposed) control.disabled = false; }
  }
  showOutput(value) {
    const target = this.results?.isConnected ? this.results : this.list;
    if (target) target.append(el("pre", pretty(value), "ba-detail"));
  }
  async refreshSamples(cursor = undefined) {
    const page = requirePage(await this.perform(() => this.api.samples({ limit: 50, ...(cursor ? { cursor } : {}) })));
    this.sampleCursor = page.nextCursor;
    this.renderSamples(page.items, Boolean(cursor));
    this.setStatus("受管样本：" + page.items.length + (page.truncated ? " · 列表已截断" : ""));
  }
  renderSamples(samples, append = false) {
    this.sampleMoreButton?.remove(); this.sampleMoreButton = null;
    if (!append) this.list.replaceChildren();
    if (!samples.length && !append) this.list.append(el("p", "尚未导入经授权的样本。"));
    for (const sample of samples) this.list.append(this.sampleCard(sample));
    if (this.sampleCursor) {
      this.sampleMoreButton = this.actionButton("加载更多样本", () => this.refreshSamples(this.sampleCursor));
      this.list.append(this.sampleMoreButton);
    }
  }
  sampleCard(sample) {
    const card = el("article", undefined, "ba-card");
    card.append(el("strong", sample.displayName ?? sample.sampleId), el("span", sampleText(sample)));
    const mode = selectField("分析模式", [["完整分析（默认）", "full"], ["快速分析", "fast"]]);
    card.append(mode.wrap);
    card.append(this.actionButton("样本信息", () => this.perform(() => this.api.sample({ sampleId: sample.sampleId }))));
    card.append(this.actionButton("开始分析", () => this.startAnalysis(sample, mode.input.value)));
    return card;
  }
  async importSample() {
    this.setStatus("正在等待 Host 授权导入样本…");
    await this.perform(() => this.api.importSample({})); await this.refreshSamples();
  }
  async startAnalysis(sample, mode) {
    this.currentSample = sample;
    const job = await this.perform(() => this.api.start({ sampleId: sample.sampleId, mode }));
    this.currentJob = job.jobId; this.setStatus(mode + " 分析任务 " + job.jobId + " 已启动。");
    await this.pollJob();
  }
  async pollJob() {
    if (this.disposed || !this.currentJob) return;
    const job = await this.perform(() => this.api.job({ jobId: this.currentJob }));
    if (job.state === "completed" && job.revisionId) {
      this.currentRevision = job.revisionId; this.renderExplorer();
      this.setStatus("分析完成：" + job.revisionId); await this.loadPage("functions"); return;
    }
    if (job.state === "failed") { this.setStatus("分析失败：" + (job.error ?? "引擎返回错误"), true); return; }
    this.setStatus("分析状态：" + job.state);
    this.pollTimer = setTimeout(() => {
      void this.pollJob().catch(error => {
        if (error instanceof ViewCancelled && this.disposed) { console.debug("binary.poll.cancelled"); return; }
        throw error;
      });
    }, POLL_MS);
  }
  renderExplorer() {
    const tabs = el("nav", undefined, "ba-tabs");
    for (const kind of Object.keys(PAGE_LABELS)) tabs.append(this.actionButton(PAGE_LABELS[kind], () => this.loadPage(kind)));
    tabs.append(this.actionButton("调试", () => this.renderDebug()));
    tabs.append(this.actionButton("证据 / 补丁 / 签名", () => this.renderAdvanced()));
    this.list.replaceChildren(tabs, this.results);
  }
  async loadPage(kind, cursor = undefined) {
    this.currentKind = kind; this.nextCursor = null;
    if (!cursor) this.results.replaceChildren();
    const params = { revisionId: this.currentRevision, limit: 50, ...(cursor ? { cursor } : {}) };
    let page;
    if (kind === "functions") page = await this.perform(() => this.api.functions(params));
    else if (kind === "strings") page = await this.perform(() => this.api.strings(params));
    else if (kind === "imports") page = await this.perform(() => this.api.imports(params));
    else throw new Error("Unknown binary analysis result page");
    requirePage(page, true);
    this.nextCursor = page.nextCursor;
    this.renderItems(page.items, kind, Boolean(cursor));
    this.setStatus(page.coverage.detail + (page.truncated ? " · 结果已截断" : ""));
  }
  renderItems(items, kind, append = false) {
    this.moreButton?.remove(); this.moreButton = null;
    if (!append) this.results.replaceChildren();
    for (const item of items) {
      const card = el("article", undefined, "ba-card");
      card.append(el("strong", item.name ?? item.text ?? "导入符号"), el("span", item.address?.value ?? item.address ?? "地址不可用"));
      if (kind === "functions" && item.address) this.functionActions(card, item);
      this.results.append(card);
    }
    if (this.nextCursor) {
      this.moreButton = this.actionButton("加载更多", () => this.loadPage(this.currentKind, this.nextCursor));
      this.results.append(this.moreButton);
    }
  }
  functionActions(card, item) {
    const actions = el("div", undefined, "ba-actions");
    actions.append(this.actionButton("设为当前地址", async () => {
      this.selectedAddress = item.address; return item.address;
    }));
    actions.append(this.actionButton("反汇编", () => {
      this.selectedAddress = item.address;
      return this.perform(() => this.api.disassemble({ revisionId: this.currentRevision, address: item.address, count: 64 }));
    }));
    actions.append(this.actionButton("CFG", () => {
      this.selectedAddress = item.address;
      return this.perform(() => this.api.cfg({ revisionId: this.currentRevision, address: item.address }));
    }));
    actions.append(this.actionButton("反编译", () => {
      this.selectedAddress = item.address;
      return this.perform(() => this.api.decompile({ revisionId: this.currentRevision, address: item.address }));
    }));
    for (const direction of ["to", "from"]) actions.append(this.actionButton("引用 " + direction, () => {
      this.selectedAddress = item.address;
      return this.perform(() => this.api.references({ revisionId: this.currentRevision, address: item.address, direction }));
    }));
    card.append(actions);
  }
  renderAdvanced() {
    this.results.replaceChildren();
    const panel = el("section", undefined, "ba-panel");
    const operation = selectField("Host 操作", ADVANCED.map(item => [item.label, item.key]));
    const config = () => ADVANCED.find(item => item.key === operation.input.value);
    const args = area("结构化 JSON 参数", pretty(this.advancedInput(config().key)));
    operation.input.addEventListener("change", () => { args.input.value = pretty(this.advancedInput(config().key)); }, { signal: this.events.signal });
    panel.append(operation.wrap, el("p", "操作固定映射到清单声明的 MCP 工具；Host 将执行权限与审批校验。", "ba-note"), args.wrap);
    panel.append(this.actionButton("提交 Host 操作", async () => {
      const item = config(); const result = await this.submitAdvanced(item.key, parseJson(args.input.value, item.label));
      if (item.key === "patchDraft") this.patchSetId = result.patchSetId;
      return result;
    }));
    if (this.patchSetId) panel.append(el("p", "当前补丁草案：" + this.patchSetId, "ba-note"));
    this.results.append(panel);
  }
  advancedInput(kind) {
    if (kind === "references") return { revisionId: this.currentRevision ?? "", address: this.selectedAddress ?? {}, direction: "to" };
    if (kind === "annotate") return { revisionId: this.currentRevision ?? "", address: this.selectedAddress ?? {}, text: "", tags: [] };
    if (kind === "evidence") return { revisionId: this.currentRevision ?? "", start: this.selectedAddress ?? {}, end: null, summary: "" };
    if (kind === "patchDraft") return { revisionId: this.currentRevision ?? "", sampleSha256: this.currentSample?.sampleSha256 ?? "", slice: this.currentSample?.slice ?? null, operations: [] };
    if (kind === "patchExport") return { patchSetId: this.patchSetId ?? "" };
    if (kind === "signConfigure") return { kind: "macosKeychain", identity: "" };
    throw new Error("Unknown binary analysis Host operation");
  }
  async submitAdvanced(kind, params) {
    if (kind === "references") return this.perform(() => this.api.references(params));
    if (kind === "annotate") return this.perform(() => this.api.annotate(params));
    if (kind === "evidence") return this.perform(() => this.api.evidence(params));
    if (kind === "patchDraft") return this.perform(() => this.api.patchDraft(params));
    if (kind === "patchExport") return this.perform(() => this.api.patchExport(params));
    if (kind === "signConfigure") return this.perform(() => this.api.signConfigure(params));
    throw new Error("Unknown binary analysis Host operation");
  }
  renderDebug() {
    this.results.replaceChildren();
    const panel = el("section", undefined, "ba-panel");
    const args = area("启动参数 JSON（字符串数组）", "[]");
    const pid = field("附加进程 PID", "number");
    panel.append(args.wrap, this.actionButton("启动受管样本", async () => {
      if (!this.currentSample) throw new Error("请先选择并分析一个样本");
      const values = parseJson(args.input.value, "启动参数");
      if (!Array.isArray(values) || values.some(value => typeof value !== "string")) throw new Error("启动参数必须是字符串数组");
      return this.drawSnapshot(await this.perform(() => this.api.debugLaunch({ sampleId: this.currentSample.sampleId, arguments: values })));
    }));
    panel.append(pid.wrap, this.actionButton("附加本机进程", async () => {
      const value = Number(pid.input.value);
      if (!Number.isInteger(value) || value < 1 || value > 4294967295) throw new Error("PID 必须是有效的 32 位正整数");
      return this.drawSnapshot(await this.perform(() => this.api.debugAttach({ pid: value, ...(this.currentSample ? { sampleId: this.currentSample.sampleId } : {}) })));
    }));
    panel.append(this.actionButton("刷新调试快照", () => this.refreshDebugSnapshot()));
    this.debugActions = el("div", undefined, "ba-actions");
    panel.append(this.debugActions); this.renderDebugControls();
    const write = area("停止态寄存器 / 内存 / 软件断点 JSON（运行时地址可复制快照 pcAddress）", '{"kind":"register","register":"","value":"0x0"}');
    panel.append(write.wrap, this.actionButton("提交停止态写入", () => this.writeDebug(write.input.value)));
    this.results.append(panel);
  }
  async refreshDebugSnapshot() { return this.drawSnapshot(await this.perform(() => this.api.debugSnapshot({}))); }
  renderDebugControls() {
    if (!this.debugActions) return;
    this.debugActions.replaceChildren();
    if (!this.snapshot || !["launching", "stopped", "running"].includes(this.snapshot.state)) return;
    const actions = ["continue", "pause", "stepIn", "stepOver", "stepOut"];
    if (this.debugTargetKind === "attached") actions.push("detach");
    actions.push("terminate");
    for (const action of actions) this.debugActions.append(this.actionButton(action, () => this.controlDebug(action)));
  }
  drawSnapshot(value) {
    this.snapshot = value; this.stopRevision = value.stopRevision; this.debugTargetKind = value.targetKind ?? null;
    if (["detached", "exited", "failed"].includes(value.state)) this.debugTargetKind = null;
    this.renderDebugControls();
    this.setStatus("调试状态：" + value.state + " · stopRevision " + value.stopRevision);
    return value;
  }
  async controlDebug(action) {
    const params = { action };
    if (["continue", "stepIn", "stepOver", "stepOut"].includes(action)) {
      if (this.stopRevision === undefined) throw new Error("请先读取调试快照");
      params.expectedStopRevision = this.stopRevision;
    }
    return this.drawSnapshot(await this.perform(() => this.api.debugControl(params)));
  }
  async writeDebug(text) {
    if (this.snapshot?.state !== "stopped" || this.stopRevision === undefined) throw new Error("写入前必须读取停止态快照");
    const params = parseJson(text, "调试写入"); params.expectedStopRevision = this.stopRevision;
    const result = await this.perform(() => this.api.debugWrite(params));
    const snapshot = await this.refreshDebugSnapshot(); return { write: result, snapshot };
  }
  async mount(target) {
    installStyles(); const shell = el("section", undefined, "ba"); const header = el("header", undefined, "ba-header");
    header.append(el("span", "二进制分析", "ba-title"), el("span", "Host 受管样本", "ba-meta"));
    header.append(this.actionButton("导入样本", () => this.importSample()));
    this.status = el("div", "正在读取受管样本…", "ba-status");
    this.list = el("main", undefined, "ba-list"); this.results = el("div");
    shell.append(header, this.status, this.list); target.replaceChildren(shell);
    console.info("binary.frontend.mounted");
    await this.refreshSamples();
  }
  dispose() {
    this.disposed = true; if (this.pollTimer) clearTimeout(this.pollTimer);
    this.events.abort();
    this.pollTimer = null; console.debug("binary.frontend.disposed");
  }
}

export async function activate(host) {
  console.debug("binary.frontend.activated", { apiVersion: host.apiVersion });
  const api = createBinaryApi(host);
  let root;
  let view;
  let disposed = false;
  const render = async () => {
    if (disposed) throw new Error("Binary analysis controller has been disposed");
    if (!root) throw new Error("Binary analysis controller must be mounted before updating");
    view?.dispose();
    const next = new BinaryAnalysisView(api);
    view = next;
    try { await next.mount(root); }
    catch (error) {
      if (error instanceof ViewCancelled && next.disposed) { console.debug("binary.view.cancelled"); return; }
      throw error;
    }
  };
  return {
    async mount(target) {
      if (disposed) throw new Error("Binary analysis controller has been disposed");
      if (root) throw new Error("Binary analysis controller is already mounted");
      root = target;
      await render();
    },
    async update() {
      console.debug("binary.frontend.updated");
      await render();
    },
    dispose() {
      disposed = true;
      view?.dispose();
      root?.replaceChildren();
      root = undefined;
    },
  };
}
