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
const SVG_NS = "http://www.w3.org/2000/svg";
const ICONS = {
  chip: "M9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3M7 6h10a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1zM10 10h4v4h-4z",
  upload: "M12 16V5M7 9l5-5 5 5M5 20h14",
  list: "M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01",
  play: "M7 5l12 7-12 7z",
  close: "M6 6l12 12M18 6L6 18",
};
function icon(name) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("aria-hidden", "true"); svg.setAttribute("class", "ba-icon");
  const path = document.createElementNS(SVG_NS, "path"); path.setAttribute("d", ICONS[name]);
  svg.append(path); return svg;
}
// 结果按 JSON 着色：键、字符串、数字和字面量各一种语义色，和 Desktop 的代码块一致。
function jsonBlock(value) {
  const pre = el("pre", undefined, "ba-detail");
  const text = pretty(value) ?? "null";
  const pattern = /("(?:[^"\\]|\\.)*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false|null)\b/g;
  let last = 0;
  for (const match of text.matchAll(pattern)) {
    if (match.index > last) pre.append(text.slice(last, match.index));
    if (match[1] !== undefined && match[2] !== undefined) pre.append(el("span", match[1], "key"), match[2]);
    else if (match[1] !== undefined) pre.append(el("span", match[1], "string"));
    else if (match[3] !== undefined) pre.append(el("span", match[3], "number"));
    else pre.append(el("span", match[4], "literal"));
    last = match.index + match[0].length;
  }
  if (last < text.length) pre.append(text.slice(last));
  return pre;
}
const DEBUG_LABELS = { continue: "继续", pause: "暂停", stepIn: "单步进入", stepOver: "单步跳过", stepOut: "单步跳出", detach: "分离", terminate: "终止" };
function installStyles() {
  if (document.getElementById("xsec-binary-analysis-style")) return;
  const style = el("style"); style.id = "xsec-binary-analysis-style";
  style.textContent = `
    :root{--ba-fb-surface:#ffffff;--ba-fb-subtle:#f0f0f2;--ba-fb-text:#18181b;--ba-fb-muted:#62626b;--ba-fb-border:#dcdce1;--ba-fb-danger:#b42318;--ba-fb-success:#187344;--ba-fb-warning:#8a5700;color-scheme:light dark}
    @media(prefers-color-scheme:dark){:root{--ba-fb-surface:#19191c;--ba-fb-subtle:#232327;--ba-fb-text:#f4f4f5;--ba-fb-muted:#a1a1aa;--ba-fb-border:#35353c;--ba-fb-danger:#ff938a;--ba-fb-success:#7ad6a0;--ba-fb-warning:#e9bd70}}
    html,body,[data-xsec-plugin-root]{width:100%;height:100%;margin:0}body{background:var(--xsec-content-surface,var(--ba-fb-surface))}
    .ba{--surface:var(--xsec-content-surface,var(--ba-fb-surface));--subtle:var(--xsec-bg-subtle,var(--ba-fb-subtle));--text:var(--xsec-text-primary,var(--ba-fb-text));--muted:var(--xsec-text-secondary,var(--ba-fb-muted));--border:var(--xsec-border-default,var(--ba-fb-border));--accent:var(--xsec-text-accent,var(--ba-fb-text));--info:color-mix(in srgb,#0169cc 68%,var(--text));--danger:var(--xsec-status-error,var(--ba-fb-danger));--success:var(--xsec-status-success,var(--ba-fb-success));--warning:var(--xsec-status-warning,var(--ba-fb-warning));
      --hairline:color-mix(in srgb,var(--text) 10%,transparent);--field:color-mix(in srgb,var(--text) 5.5%,transparent);--field-hover:color-mix(in srgb,var(--text) 8%,transparent);--radius:var(--xsec-radius-md,8px);--radius-panel:var(--xsec-radius-lg,12px);--mono:ui-monospace,"SF Mono","Cascadia Mono",Consolas,"Liberation Mono",monospace;
      height:100%;display:flex;flex-direction:column;background:var(--surface);color:var(--text);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei","Noto Sans CJK SC",system-ui,sans-serif;-webkit-font-smoothing:antialiased}
    .ba *{box-sizing:border-box}.ba [hidden]{display:none}
    .ba-header{display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--hairline)}.ba-mark{display:grid;place-items:center;width:32px;height:32px;border-radius:var(--radius);background:color-mix(in srgb,var(--info) 12%,var(--surface));color:var(--info)}
    .ba-heading{flex:1;min-width:0;display:flex;flex-direction:column}.ba-title{font-weight:650;line-height:20px}.ba-meta{color:var(--muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .ba-icon{width:16px;height:16px;flex:none;fill:none;stroke:currentColor;stroke-width:1.75;stroke-linecap:round;stroke-linejoin:round}
    .ba button{display:inline-flex;align-items:center;justify-content:center;gap:6px;height:32px;padding:0 12px;border:0;border-radius:var(--radius);background:var(--field);color:var(--text);font:inherit;font-size:13px;font-weight:500;white-space:nowrap;cursor:pointer;transition:background-color .12s}
    .ba button:hover{background:var(--field-hover)}.ba button:disabled{cursor:wait;opacity:.55}.ba button.primary{background:var(--accent);color:var(--surface);color:oklch(from var(--accent) clamp(0,(.65 - l)*1000,1) 0 0)}.ba button.primary:hover{background:color-mix(in srgb,var(--accent) 88%,var(--surface))}
    .ba button.ghost{background:transparent}.ba button.ghost:hover{background:var(--field)}.ba button.small{height:26px;padding:0 8px;font-size:12px}.ba button.danger{color:var(--danger)}
    .ba :is(button,input,select,textarea):focus-visible{outline:2px solid var(--info);outline-offset:1px}
    .ba-status{display:flex;align-items:center;gap:8px;min-height:32px;padding:6px 16px;color:var(--muted);font-size:12px;border-bottom:1px solid var(--hairline)}.ba-status::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--success);flex:none}
    .ba-status.ba-error{color:var(--danger);background:color-mix(in srgb,var(--danger) 8%,var(--surface))}.ba-status.ba-error::before{background:var(--danger)}.ba-status:empty::before{background:var(--muted)}
    .ba-list{overflow:auto;flex:1;padding:16px;display:flex;flex-direction:column;gap:12px}.ba-results{display:flex;flex-direction:column;gap:12px}
    .ba-card,.ba-panel{display:flex;flex-direction:column;gap:12px;padding:16px;border:1px solid var(--hairline);border-radius:var(--radius-panel);background:var(--surface)}
    .ba-sample{flex-direction:row;align-items:center;flex-wrap:wrap}.ba-sample-main{flex:1;min-width:200px;display:flex;flex-direction:column;gap:4px}.ba-sample-main strong{font-weight:650;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .ba-chips{display:flex;gap:6px;flex-wrap:wrap;align-items:center}.ba-chip{padding:1px 8px;border:1px solid var(--hairline);border-radius:6px;font-size:12px;line-height:18px}.ba-chip.mono,.ba-mono{font-family:var(--mono)}.ba-chip.accent{border-color:transparent;color:var(--info);background:color-mix(in srgb,var(--info) 12%,var(--surface));font-weight:600}
    .ba-sample-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.ba .ba-sample-actions select{width:auto}
    .ba-tabs{display:flex;gap:4px;padding:3px;border-radius:calc(var(--radius) + 2px);background:var(--field);align-self:flex-start;flex-wrap:wrap}.ba .ba-tabs button{height:28px;background:transparent;color:var(--muted)}.ba .ba-tabs button:hover{color:var(--text)}
    .ba .ba-tabs button.active{background:var(--surface);color:var(--text);font-weight:600;box-shadow:0 1px 2px color-mix(in srgb,#000 14%,transparent)}
    .ba-rows{display:flex;flex-direction:column;border:1px solid var(--hairline);border-radius:var(--radius-panel);overflow:hidden}.ba-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:8px 12px 8px 16px}.ba-row+.ba-row{border-top:1px solid var(--hairline)}
    .ba-row:hover{background:color-mix(in srgb,var(--text) 3%,transparent)}.ba-row.current{background:color-mix(in srgb,var(--info) 7%,var(--surface))}.ba-row-main{flex:1;min-width:160px;display:flex;align-items:baseline;gap:12px}
    .ba-row-main strong{font:600 13px/1.5 var(--mono);overflow-wrap:anywhere;user-select:text}.ba-row-main span{font:12px var(--mono);color:var(--muted);user-select:text}.ba-actions{display:flex;flex-wrap:wrap;gap:6px}
    .ba-empty{padding:48px 16px;text-align:center;color:var(--muted)}
    .ba-output{border:1px solid var(--hairline);border-radius:var(--radius);background:var(--subtle);overflow:hidden}.ba-output-head{display:flex;align-items:center;gap:8px;padding:4px 4px 4px 12px;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--hairline)}.ba-output-head span{flex:1}
    .ba-detail{margin:0;padding:10px 12px;max-height:420px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.5 var(--mono);user-select:text}.ba-detail .key{font-weight:600}.ba-detail .string{color:var(--success)}.ba-detail .number{color:var(--warning)}.ba-detail .literal{font-weight:600}
    .ba-panel h2{margin:0;font-size:14px;line-height:20px;font-weight:650}.ba-group{display:flex;flex-direction:column;gap:8px}.ba-group+.ba-group{padding-top:12px;border-top:1px solid var(--hairline)}.ba-group-title{font-size:12px;font-weight:600;color:var(--muted)}
    .ba-field{display:flex;flex-direction:column;gap:6px;min-width:180px}.ba-field span{font-size:13px;font-weight:500}.ba-inline{display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap}.ba-inline .ba-field{flex:1}
    .ba :is(input,select,textarea){width:100%;height:32px;padding:0 10px;border:0;border-radius:var(--radius);background:var(--field);color:var(--text);font:inherit;font-size:13px}.ba :is(input,select,textarea):hover{background:var(--field-hover)}
    .ba select{appearance:none;-webkit-appearance:none;padding-right:28px;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%238a8a93' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M4 6l4 4 4-4'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 8px center;background-size:16px;cursor:pointer}.ba textarea{height:auto;min-height:120px;padding:8px 10px;resize:vertical;font:12px/1.5 var(--mono)}.ba textarea.short{min-height:56px}.ba-note{margin:0;color:var(--muted);font-size:12px}
    @media(prefers-reduced-motion:reduce){.ba button{transition:none}}
  `;
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
  actionButton(label, action, className = "", iconName = "") {
    const control = el("button", undefined, className);
    control.type = "button";
    if (iconName) control.append(icon(iconName));
    control.append(el("span", label));
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
    if (!target) return;
    const box = el("div", undefined, "ba-output"), head = el("div", undefined, "ba-output-head");
    const close = el("button", undefined, "ghost small");
    close.type = "button"; close.title = "移除这条结果"; close.setAttribute("aria-label", "移除这条结果"); close.append(icon("close"));
    close.addEventListener("click", () => box.remove(), { signal: this.events.signal });
    head.append(el("span", "结果"), close);
    box.append(head, jsonBlock(value)); target.append(box);
    box.scrollIntoView({ block: "nearest" });
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
    if (!samples.length && !append) this.list.append(el("p", "尚未导入经授权的样本。", "ba-empty"));
    for (const sample of samples) this.list.append(this.sampleCard(sample));
    if (this.sampleCursor) {
      this.sampleMoreButton = this.actionButton("加载更多样本", () => this.refreshSamples(this.sampleCursor));
      this.list.append(this.sampleMoreButton);
    }
  }
  sampleCard(sample) {
    const card = el("article", undefined, "ba-card ba-sample");
    const main = el("div", undefined, "ba-sample-main"), chips = el("div", undefined, "ba-chips");
    const digest = String(sample.sampleSha256 ?? "");
    chips.append(el("span", sample.format ?? "未知格式", "ba-chip accent"), el("span", sample.architecture ?? "未知架构", "ba-chip"),
      el("span", digest.slice(0, 16) + "…", "ba-chip mono"));
    if (sample.displayName && sample.displayName !== sample.sampleId) chips.append(el("span", sample.sampleId, "ba-chip mono"));
    main.append(el("strong", sample.displayName ?? sample.sampleId), chips);
    main.title = sampleText(sample);
    const actions = el("div", undefined, "ba-sample-actions");
    const mode = el("select");
    mode.setAttribute("aria-label", "分析模式");
    for (const [name, value] of [["完整分析（默认）", "full"], ["快速分析", "fast"]]) mode.append(new Option(name, value));
    actions.append(mode, this.actionButton("样本信息", () => this.perform(() => this.api.sample({ sampleId: sample.sampleId })), "ghost"),
      this.actionButton("开始分析", () => this.startAnalysis(sample, mode.value), "primary", "play"));
    card.append(main, actions);
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
    const tab = (label, action) => {
      const control = this.actionButton(label, action);
      control.addEventListener("click", () => {
        for (const other of tabs.children) other.classList.toggle("active", other === control);
      }, { signal: this.events.signal });
      tabs.append(control);
      return control;
    };
    for (const kind of Object.keys(PAGE_LABELS)) tab(PAGE_LABELS[kind], () => this.loadPage(kind));
    tab("调试", () => this.renderDebug());
    tab("证据 / 补丁 / 签名", () => this.renderAdvanced());
    tabs.firstElementChild.classList.add("active");
    this.results.className = "ba-results";
    this.list.replaceChildren(tabs, this.results);
    if (this.sampleMeta) this.sampleMeta.textContent = (this.currentSample?.displayName ?? this.currentSample?.sampleId ?? "") + " · " + this.currentRevision;
    if (this.backButton) this.backButton.hidden = false;
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
    if (!append) { this.results.replaceChildren(); this.rows = null; }
    if (!this.rows?.isConnected) { this.rows = el("div", undefined, "ba-rows"); if (items.length) this.results.append(this.rows); }
    if (!items.length && !append) this.results.append(el("p", "没有" + PAGE_LABELS[kind], "ba-empty"));
    for (const item of items) {
      const row = el("article", undefined, "ba-row"), main = el("div", undefined, "ba-row-main");
      main.append(el("strong", item.name ?? item.text ?? "导入符号"), el("span", item.address?.value ?? item.address ?? "地址不可用"));
      row.append(main);
      if (kind === "functions" && item.address) this.functionActions(row, item);
      this.rows.append(row);
    }
    if (this.nextCursor) {
      this.moreButton = this.actionButton("加载更多", () => this.loadPage(this.currentKind, this.nextCursor));
      this.results.append(this.moreButton);
    }
  }
  functionActions(card, item) {
    const actions = el("div", undefined, "ba-actions");
    const select = () => {
      this.selectedAddress = item.address;
      for (const other of card.parentElement?.children ?? []) other.classList.toggle("current", other === card);
    };
    actions.append(this.actionButton("设为当前地址", async () => {
      select(); return item.address;
    }, "small"));
    actions.append(this.actionButton("反汇编", () => {
      select();
      return this.perform(() => this.api.disassemble({ revisionId: this.currentRevision, address: item.address, count: 64 }));
    }, "small"));
    actions.append(this.actionButton("CFG", () => {
      select();
      return this.perform(() => this.api.cfg({ revisionId: this.currentRevision, address: item.address }));
    }, "small"));
    actions.append(this.actionButton("反编译", () => {
      select();
      return this.perform(() => this.api.decompile({ revisionId: this.currentRevision, address: item.address }));
    }, "small"));
    for (const direction of ["to", "from"]) actions.append(this.actionButton("引用 " + direction, () => {
      select();
      return this.perform(() => this.api.references({ revisionId: this.currentRevision, address: item.address, direction }));
    }, "small"));
    card.append(actions);
  }
  renderAdvanced() {
    this.results.replaceChildren();
    const panel = el("section", undefined, "ba-panel");
    const operation = selectField("Host 操作", ADVANCED.map(item => [item.label, item.key]));
    const config = () => ADVANCED.find(item => item.key === operation.input.value);
    const args = area("结构化 JSON 参数", pretty(this.advancedInput(config().key)));
    operation.input.addEventListener("change", () => { args.input.value = pretty(this.advancedInput(config().key)); }, { signal: this.events.signal });
    panel.append(el("h2", "Host 操作"), operation.wrap, el("p", "操作固定映射到清单声明的 MCP 工具；Host 将执行权限与审批校验。", "ba-note"), args.wrap);
    const submit = el("div", undefined, "ba-actions");
    panel.append(submit);
    submit.append(this.actionButton("提交 Host 操作", async () => {
      const item = config(); const result = await this.submitAdvanced(item.key, parseJson(args.input.value, item.label));
      if (item.key === "patchDraft") this.patchSetId = result.patchSetId;
      return result;
    }, "primary"));
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
    args.input.className = "short";
    const pid = field("附加进程 PID", "number");
    const group = (title, ...children) => {
      const node = el("div", undefined, "ba-group");
      node.append(el("div", title, "ba-group-title"), ...children);
      return node;
    };
    const row = (...children) => {
      const node = el("div", undefined, "ba-inline");
      node.append(...children);
      return node;
    };
    panel.append(el("h2", "调试"));
    const launch = this.actionButton("启动受管样本", async () => {
      if (!this.currentSample) throw new Error("请先选择并分析一个样本");
      const values = parseJson(args.input.value, "启动参数");
      if (!Array.isArray(values) || values.some(value => typeof value !== "string")) throw new Error("启动参数必须是字符串数组");
      return this.drawSnapshot(await this.perform(() => this.api.debugLaunch({ sampleId: this.currentSample.sampleId, arguments: values })));
    }, "primary", "play");
    const attach = this.actionButton("附加本机进程", async () => {
      const value = Number(pid.input.value);
      if (!Number.isInteger(value) || value < 1 || value > 4294967295) throw new Error("PID 必须是有效的 32 位正整数");
      return this.drawSnapshot(await this.perform(() => this.api.debugAttach({ pid: value, ...(this.currentSample ? { sampleId: this.currentSample.sampleId } : {}) })));
    });
    this.debugActions = el("div", undefined, "ba-actions");
    panel.append(group("启动", args.wrap, row(launch)), group("附加", row(pid.wrap, attach)),
      group("控制", row(this.actionButton("刷新调试快照", () => this.refreshDebugSnapshot())), this.debugActions));
    this.renderDebugControls();
    const write = area("停止态寄存器 / 内存 / 软件断点 JSON（运行时地址可复制快照 pcAddress）", '{"kind":"register","register":"","value":"0x0"}');
    panel.append(group("停止态写入", write.wrap, row(this.actionButton("提交停止态写入", () => this.writeDebug(write.input.value)))));
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
    for (const action of actions) {
      const control = this.actionButton(DEBUG_LABELS[action], () => this.controlDebug(action), action === "terminate" ? "danger" : "");
      control.title = action;
      this.debugActions.append(control);
    }
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
    const mark = el("span", undefined, "ba-mark"), heading = el("div", undefined, "ba-heading");
    mark.append(icon("chip"));
    this.sampleMeta = el("span", "Host 受管样本", "ba-meta");
    heading.append(el("span", "二进制分析", "ba-title"), this.sampleMeta);
    this.backButton = this.actionButton("样本列表", async () => {
      this.backButton.hidden = true; this.sampleMeta.textContent = "Host 受管样本";
      await this.refreshSamples();
    }, "ghost", "list");
    this.backButton.hidden = true;
    header.append(mark, heading, this.backButton, this.actionButton("导入样本", () => this.importSample(), "", "upload"));
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
