const RPC = Object.freeze({
  importSample: "xsec.binary.sample.import", samples: "xsec.binary.samples.list",
  sample: "xsec.binary.sample.info", start: "xsec.binary.analysis.start",
  job: "xsec.binary.jobs.get", functions: "xsec.binary.functions.list",
  strings: "xsec.binary.strings.list", imports: "xsec.binary.imports.list",
  disassemble: "xsec.binary.disassemble", cfg: "xsec.binary.cfg",
  references: "xsec.binary.references.list", decompile: "xsec.binary.decompile",
  annotate: "xsec.binary.annotation.upsert", evidence: "xsec.binary.evidence.create",
  debugLaunch: "xsec.binary.debug.launch", debugAttach: "xsec.binary.debug.attach",
  debugControl: "xsec.binary.debug.control", debugSnapshot: "xsec.binary.debug.snapshot",
  debugWrite: "xsec.binary.debug.write", patchDraft: "xsec.binary.patch.draft",
  patchExport: "xsec.binary.patch.export", signConfigure: "xsec.binary.sign.configure",
});
const PAGE_RPC = { functions: RPC.functions, strings: RPC.strings, imports: RPC.imports };
const PAGE_LABELS = { functions: "函数", strings: "字符串", imports: "导入" };
const POLL_MS = 1200;
const ADVANCED = [
  { key: "references", label: "引用查询", method: RPC.references, template: c => ({ revisionId: c.currentRevision ?? "", address: c.selectedAddress ?? {}, direction: "to" }) },
  { key: "annotate", label: "保存注释", method: RPC.annotate, template: c => ({ revisionId: c.currentRevision ?? "", address: c.selectedAddress ?? {}, text: "", tags: [] }) },
  { key: "evidence", label: "创建证据", method: RPC.evidence, template: c => ({ revisionId: c.currentRevision ?? "", start: c.selectedAddress ?? {}, end: null, summary: "" }) },
  { key: "patchDraft", label: "补丁草案", method: RPC.patchDraft, template: c => ({ revisionId: c.currentRevision ?? "", sampleSha256: c.currentSample?.sampleSha256 ?? "", slice: c.currentSample?.slice ?? null, operations: [] }) },
  { key: "patchExport", label: "导出补丁", method: RPC.patchExport, template: c => ({ patchSetId: c.patchSetId ?? "" }) },
  { key: "signConfigure", label: "签名配置", method: RPC.signConfigure, template: () => ({ kind: "macosKeychain", identity: "" }) },
];

function payload(result) {
  if (result?.isError) throw new Error(result?.content?.[0]?.text ?? "二进制分析请求失败");
  const text = result?.content?.[0]?.text;
  if (typeof text !== "string") throw new Error("二进制分析 MCP 返回格式无效");
  const value = JSON.parse(text);
  if (value?.error) throw new Error(value.error);
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

class BinaryAnalysisController {
  constructor(host) {
    Object.assign(this, { host, disposed: false, currentJob: null, currentRevision: null, currentSample: null, selectedAddress: null, currentKind: "functions", nextCursor: null, sampleCursor: null, pollTimer: null, patchSetId: null, snapshot: null, debugTargetKind: null });
  }
  setStatus(message, failed = false) {
    this.status.textContent = message ?? "";
    this.status.classList.toggle("ba-error", failed);
  }
  async request(method, params = {}, quiet = false) {
    if (!quiet) console.info("binary.rpc.started", { method });
    try {
      const result = payload(await this.host.request(method, params));
      if (!quiet) console.info("binary.rpc.completed", { method });
      return result;
    } catch (error) {
      console.error("binary.rpc.failed", { method, message: String(error) });
      throw error;
    }
  }
  actionButton(label, action) {
    const control = el("button", label);
    control.addEventListener("click", () => this.runButton(control, label, action));
    return control;
  }
  async runButton(control, label, action) {
    control.disabled = true;
    try {
      console.info("binary.action.started", { action: label });
      const result = await action();
      if (result !== undefined) this.showOutput(result);
      console.info("binary.action.completed", { action: label });
    } catch (error) {
      this.setStatus(String(error), true);
      console.error("binary.action.failed", { action: label, message: String(error) });
    } finally { control.disabled = false; }
  }
  showOutput(value) {
    const target = this.results?.isConnected ? this.results : this.list;
    if (target) target.append(el("pre", pretty(value), "ba-detail"));
  }
  async refreshSamples(cursor = undefined) {
    const page = await this.request(RPC.samples, { limit: 50, ...(cursor ? { cursor } : {}) });
    this.sampleCursor = page.nextCursor ?? null;
    this.renderSamples(page.items ?? [], Boolean(cursor));
    this.setStatus("受管样本：" + (page.items?.length ?? 0) + (page.truncated ? " · 列表已截断" : ""));
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
    card.append(this.actionButton("样本信息", () => this.request(RPC.sample, { sampleId: sample.sampleId })));
    card.append(this.actionButton("开始分析", () => this.startAnalysis(sample, mode.input.value)));
    return card;
  }
  async importSample() {
    this.setStatus("正在等待 Host 授权导入样本…");
    await this.request(RPC.importSample); await this.refreshSamples();
  }
  async startAnalysis(sample, mode) {
    this.currentSample = sample;
    const job = await this.request(RPC.start, { sampleId: sample.sampleId, mode });
    this.currentJob = job.jobId; this.setStatus(mode + " 分析任务 " + job.jobId + " 已启动。");
    await this.pollJob();
  }
  async pollJob() {
    if (this.disposed || !this.currentJob) return;
    const job = await this.request(RPC.job, { jobId: this.currentJob }, true);
    if (job.state === "completed" && job.revisionId) {
      this.currentRevision = job.revisionId; this.renderExplorer();
      this.setStatus("分析完成：" + job.revisionId); await this.loadPage("functions"); return;
    }
    if (job.state === "failed") { this.setStatus("分析失败：" + (job.error ?? "引擎返回错误"), true); return; }
    this.setStatus("分析状态：" + job.state);
    this.pollTimer = setTimeout(() => this.pollJob().catch(error => this.setStatus(String(error), true)), POLL_MS);
  }
  renderExplorer() {
    const tabs = el("nav", undefined, "ba-tabs");
    for (const kind of Object.keys(PAGE_RPC)) tabs.append(this.actionButton(PAGE_LABELS[kind], () => this.loadPage(kind)));
    tabs.append(this.actionButton("调试", () => this.renderDebug()));
    tabs.append(this.actionButton("证据 / 补丁 / 签名", () => this.renderAdvanced()));
    this.list.replaceChildren(tabs, this.results);
  }
  async loadPage(kind, cursor = undefined) {
    this.currentKind = kind; this.nextCursor = null;
    if (!cursor) this.results.replaceChildren();
    const page = await this.request(PAGE_RPC[kind], { revisionId: this.currentRevision, limit: 50, ...(cursor ? { cursor } : {}) });
    this.nextCursor = page.nextCursor ?? null;
    this.renderItems(page.items ?? [], kind, Boolean(cursor));
    this.setStatus(page.coverage?.detail ?? "分析覆盖信息不可用");
    if (page.truncated) this.setStatus((page.coverage?.detail ?? "") + " · 结果已截断");
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
    for (const [label, method, extra] of [["反汇编", RPC.disassemble, { count: 64 }], ["CFG", RPC.cfg, {}], ["反编译", RPC.decompile, {}]]) {
      actions.append(this.actionButton(label, () => {
        this.selectedAddress = item.address;
        return this.request(method, { revisionId: this.currentRevision, address: item.address, ...extra });
      }));
    }
    for (const direction of ["to", "from"]) actions.append(this.actionButton("引用 " + direction, () => {
      this.selectedAddress = item.address;
      return this.request(RPC.references, { revisionId: this.currentRevision, address: item.address, direction });
    }));
    card.append(actions);
  }
  renderAdvanced() {
    this.results.replaceChildren();
    const panel = el("section", undefined, "ba-panel");
    const operation = selectField("Host 操作", ADVANCED.map(item => [item.label, item.key]));
    const config = () => ADVANCED.find(item => item.key === operation.input.value);
    const args = area("结构化 JSON 参数", pretty(config().template(this)));
    operation.input.addEventListener("change", () => { args.input.value = pretty(config().template(this)); });
    panel.append(operation.wrap, el("p", "操作固定映射到清单声明的 MCP 工具；Host 将执行权限与审批校验。", "ba-note"), args.wrap);
    panel.append(this.actionButton("提交 Host 操作", async () => {
      const item = config(); const result = await this.request(item.method, parseJson(args.input.value, item.label));
      if (item.key === "patchDraft") this.patchSetId = result.patchSetId;
      return result;
    }));
    if (this.patchSetId) panel.append(el("p", "当前补丁草案：" + this.patchSetId, "ba-note"));
    this.results.append(panel);
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
      return this.drawSnapshot(await this.request(RPC.debugLaunch, { sampleId: this.currentSample.sampleId, arguments: values }));
    }));
    panel.append(pid.wrap, this.actionButton("附加本机进程", async () => {
      const value = Number(pid.input.value);
      if (!Number.isInteger(value) || value < 1 || value > 4294967295) throw new Error("PID 必须是有效的 32 位正整数");
      return this.drawSnapshot(await this.request(RPC.debugAttach, { pid: value, ...(this.currentSample ? { sampleId: this.currentSample.sampleId } : {}) }));
    }));
    panel.append(this.actionButton("刷新调试快照", () => this.refreshDebugSnapshot()));
    this.debugActions = el("div", undefined, "ba-actions");
    panel.append(this.debugActions); this.renderDebugControls();
    const write = area("停止态寄存器 / 内存 / 软件断点 JSON（运行时地址可复制快照 pcAddress）", '{"kind":"register","register":"","value":"0x0"}');
    panel.append(write.wrap, this.actionButton("提交停止态写入", () => this.writeDebug(write.input.value)));
    this.results.append(panel);
  }
  async refreshDebugSnapshot() { return this.drawSnapshot(await this.request(RPC.debugSnapshot)); }
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
    return this.drawSnapshot(await this.request(RPC.debugControl, params));
  }
  async writeDebug(text) {
    if (this.snapshot?.state !== "stopped" || this.stopRevision === undefined) throw new Error("写入前必须读取停止态快照");
    const params = parseJson(text, "调试写入"); params.expectedStopRevision = this.stopRevision;
    const result = await this.request(RPC.debugWrite, params);
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
    try { await this.refreshSamples(); }
    catch (error) { this.setStatus(String(error), true); }
  }
  dispose() {
    this.disposed = true; if (this.pollTimer) clearTimeout(this.pollTimer);
    this.pollTimer = null; console.debug("binary.frontend.disposed");
  }
}

export async function activate(host) {
  console.debug("binary.frontend.activated", { apiVersion: host.apiVersion });
  return new BinaryAnalysisController(host);
}
