import { useLayoutEffect, useRef, useState, useSyncExternalStore, type ReactNode } from 'react';
import { ArrowDown, FileUp, Play, RotateCw } from 'lucide-react';
import { Badge, ControlButton, Drawer, EmptyState, ErrorState, Field, Input, PageHeader, Section, Select, Spinner, Tabs, Textarea, Toolbar } from '@xsec/ui-react';
import { LABELS, RPC, addressInput, pretty, type JsonObject, type Sample, type View } from './core';
import { BinaryController, type State } from './controller';

const MODES = [{ value: 'full', label: '完整分析' }, { value: 'fast', label: '快速分析' }];
const OPERATIONS = [
  { key: 'references', label: '引用查询', method: RPC.references },
  { key: 'annotate', label: '保存注释', method: RPC.annotate },
  { key: 'evidence', label: '创建证据', method: RPC.evidence },
  { key: 'patchDraft', label: '补丁草案', method: RPC.patchDraft },
  { key: 'patchExport', label: '导出补丁', method: RPC.patchExport },
  { key: 'signConfigure', label: '签名配置', method: RPC.signConfigure },
] as const;
type Operation = typeof OPERATIONS[number]['key'];
function template(key: Operation, state: State): JsonObject {
  const revisionId = state.revisionId ?? '', address = state.address ? addressInput(state.address) : {};
  switch (key) {
    case 'references': return { revisionId, address, direction: 'to' };
    case 'annotate': return { revisionId, address, text: '', tags: [] };
    case 'evidence': return { revisionId, start: address, summary: '' };
    case 'patchDraft': return { revisionId, sampleSha256: state.sample?.sampleSha256 ?? '',
      ...(state.sample?.slice ? { slice: state.sample.slice } : {}), operations: [] };
    case 'patchExport': return { patchSetId: state.patchSetId ?? '' };
    case 'signConfigure': return { kind: 'macosKeychain', identity: '' };
  }
}
function Json({ value }: { value: unknown }) {
  return <pre className="ba-json" tabIndex={0} aria-label="结构化结果">{pretty(value)}</pre>;
}
function SampleCard({ sample, controller, disabled, remember }: {
  sample: Sample; controller: BinaryController; disabled: boolean; remember: () => void;
}) {
  const [mode, setMode] = useState('full');
  return <article className="ba-card">
    <div className="ba-card-heading"><strong>{sample.sampleId}</strong><Badge>{sample.format}</Badge></div>
    <p className="ba-note">{sample.architecture ?? '架构未标注'}{sample.slice ? ' · ' + sample.slice : ''}</p>
    <code className="ba-digest" title={sample.sampleSha256}>{sample.sampleSha256}</code>
    <Field label="分析模式">{props => <Select {...props} options={MODES} value={mode} disabled={disabled}
      onValueChange={value => { if (value !== 'full' && value !== 'fast') throw Error('分析模式无效'); setMode(value); }}/>}</Field>
    <div className="ba-actions">
      <ControlButton variant="secondary" disabled={disabled} onClick={() => { remember(); void controller.sampleInfo(sample); }}>样本信息</ControlButton>
      <ControlButton disabled={disabled || controller.analysisRunning()} onClick={() => { remember(); void controller.start(sample, mode); }}><Play size={15}/>开始分析</ControlButton>
    </div>
  </article>;
}
export function BinaryApp({ controller }: { controller: BinaryController }) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const disabled = Boolean(state.busy);
  const finalFocus = useRef<HTMLElement | null>(null);
  const remember = () => { finalFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; };
  const [operation, setOperation] = useState<Operation>('references');
  const [parameters, setParameters] = useState(pretty(template('references', state)));
  const [launchArguments, setLaunchArguments] = useState('[]');
  const [pid, setPid] = useState('');
  const [write, setWrite] = useState('{"kind":"register","register":"","value":"0x0"}');
  useLayoutEffect(() => {
    setOperation('references');
    setParameters(pretty({ revisionId: '', address: {}, direction: 'to' }));
    setLaunchArguments('[]'); setPid(''); setWrite('{"kind":"register","register":"","value":"0x0"}');
    finalFocus.current = null;
  }, [state.contextRevision]);
  const retry = state.view === 'samples' ? () => controller.refreshSamples() : state.view === 'debug' ? () => controller.debugRead()
    : ['functions', 'strings', 'imports'].includes(state.view) ? () => controller.view(state.view) : undefined;
  const refresh = <ControlButton variant="secondary" disabled={disabled} onClick={() => void controller.refreshSamples()}><RotateCw size={15}/>重新读取样本</ControlButton>;
  const sampleContent = <>
    <Toolbar className="ba-toolbar"><p className="ba-note">{state.samples ? `${state.samples.items.length} 个受管样本` : '读取授权任务中的样本'}</p>{refresh}</Toolbar>
    {state.samples && state.samples.items.length === 0 ? <EmptyState title="尚未导入样本" description="导入经授权的二进制文件，开始静态分析。"/> : null}
    <div className="ba-samples">{state.samples?.items.map(sample => <SampleCard key={sample.sampleId} sample={sample} controller={controller} disabled={disabled} remember={remember}/>)}</div>
    {state.samples?.nextCursor ? <ControlButton className="ba-more" variant="secondary" disabled={disabled} onClick={() => void controller.refreshSamples(true)}><ArrowDown size={15}/>加载更多样本</ControlButton> : null}
  </>;
  function results(view: View): ReactNode {
    const active = state.view === view;
    const result = active ? state.result : undefined;
    return <>
      <Toolbar className="ba-toolbar"><p className="ba-note">{result ? `${result.items.length} 条结果` : '分析结果'}{result?.coverage ? ' · ' + result.coverage.state : ''}</p>
        <ControlButton variant="secondary" disabled={disabled || !state.revisionId} onClick={() => void controller.view(view)}><RotateCw size={15}/>重新读取结果</ControlButton></Toolbar>
      {result?.coverage ? <p className="ba-coverage">{result.coverage.detail}{result.truncated ? ' · 结果已截断，请继续分页。' : ''}</p> : null}
      {result?.items.length === 0 ? <EmptyState title="当前分析没有此类结果" description={result.coverage?.detail}/> : null}
      {!state.revisionId ? <EmptyState title="先完成样本分析" description="选择受管样本及分析模式，完成后即可浏览结果。"/> : null}
      <div className="ba-result-list">{result?.items.map((item, index) => <article className="ba-card" key={`${state.revisionId}:${view}:${index}`}>
        <div className="ba-card-heading"><strong>{typeof item.name === 'string' ? item.name : typeof item.text === 'string' ? item.text : '导入符号'}</strong>
          {item.address ? <code>{item.address.value}</code> : null}</div>
        {view === 'functions' && item.address ? <div className="ba-actions">
          <ControlButton variant="ghost" disabled={disabled} onClick={() => controller.selectAddress(item.address!)}>设为当前地址</ControlButton>
          {([
            ['反汇编', RPC.disassemble, { count: 64 }], ['CFG', RPC.cfg, {}], ['反编译', RPC.decompile, {}],
            ['引用 to', RPC.references, { direction: 'to' }], ['引用 from', RPC.references, { direction: 'from' }],
          ] as [string, string, JsonObject][]).map(([label, method, extra]) => <ControlButton key={label} variant="secondary" disabled={disabled}
            onClick={() => { remember(); void controller.query(label, method, item.address!, extra); }}>{label}</ControlButton>)}
        </div> : null}
      </article>)}</div>
      {result?.nextCursor ? <ControlButton className="ba-more" variant="secondary" disabled={disabled} onClick={() => void controller.moreResults()}><ArrowDown size={15}/>加载更多结果</ControlButton> : null}
    </>;
  }
  const debug = state.debug;
  const activeDebug = Boolean(debug && ['launching', 'running', 'stopped'].includes(debug.state));
  const debugContent = <div className="ba-form">
    <Section title="启动与附加">
      <p className="ba-note">选择受管样本或本机进程，授权后进入调试。</p>
      <div className="ba-form-grid">
        <Field label="启动参数 JSON" hint={'字符串数组，例如 ["--help"]'}>{props => <Textarea {...props} value={launchArguments} onChange={event => setLaunchArguments(event.target.value)} disabled={disabled}/>}</Field>
        <Field label="附加进程 PID">{props => <Input {...props} inputMode="numeric" value={pid} onChange={event => setPid(event.target.value)} disabled={disabled}/>}</Field>
      </div>
      <div className="ba-actions">
        <ControlButton disabled={disabled || activeDebug || !state.sample} onClick={() => { remember(); void controller.debugLaunch(launchArguments); }}>启动受管样本</ControlButton>
        <ControlButton variant="secondary" disabled={disabled || activeDebug} onClick={() => { remember(); void controller.debugAttach(pid); }}>附加本机进程</ControlButton>
        <ControlButton variant="secondary" disabled={disabled} onClick={() => { remember(); void controller.debugRead(); }}><RotateCw size={15}/>读取调试快照</ControlButton>
      </div>
    </Section>
    <Section title="调试控制">
      {debug ? <p className="ba-debug-status"><Badge tone={debug.state === 'failed' ? 'danger' : debug.state === 'stopped' ? 'warning' : 'neutral'}>{debug.state}</Badge>
        <span>PID {debug.targetPid} · 停止态版本 {debug.stopRevision}</span></p> : <p className="ba-note">读取调试快照后显示可用控制。</p>}
      {activeDebug ? <div className="ba-actions">{([
        ['continue', '继续'], ['pause', '暂停'], ['stepIn', '步入'], ['stepOver', '步过'], ['stepOut', '步出'], ['detach', '分离'], ['terminate', '终止'],
      ] as const).filter(([action]) => action !== 'detach' || debug?.targetKind === 'attached').map(([action, label]) => <ControlButton key={action}
        variant={action === 'terminate' ? 'danger' : 'secondary'} disabled={disabled ||
          (['continue', 'stepIn', 'stepOver', 'stepOut'].includes(action) && debug?.state !== 'stopped') ||
          (action === 'pause' && debug?.state !== 'running')}
        onClick={() => { remember(); void controller.debugControl(action); }}>{label}</ControlButton>)}</div> : null}
    </Section>
    <Section title="停止态写入">
      <Field label="寄存器、内存或软件断点 JSON" hint="运行时地址可复制调试快照的 pcAddress；写入使用当前停止态版本。">{props => <Textarea {...props} className="ba-code-input" value={write} onChange={event => setWrite(event.target.value)} disabled={disabled}/>}</Field>
      <ControlButton disabled={disabled || debug?.state !== 'stopped'} onClick={() => { remember(); void controller.debugWrite(write); }}>提交写入并回读</ControlButton>
    </Section>
  </div>;
  const advancedContent = <Section title="证据与补丁" className="ba-form">
    <p className="ba-note">保存分析注释与证据，创建补丁草案并导出。导出和签名由应用请求授权。</p>
    <Field label="操作">{props => <Select {...props} options={OPERATIONS.map(item => ({ value: item.key, label: item.label }))} value={operation} disabled={disabled}
      onValueChange={value => {
        const item = OPERATIONS.find(entry => entry.key === value);
        if (!item) throw Error('操作无效'); setOperation(item.key); setParameters(pretty(template(item.key, state)));
      }}/>}</Field>
    <Field label="结构化 JSON 参数">{props => <Textarea {...props} className="ba-code-input" value={parameters} disabled={disabled} onChange={event => setParameters(event.target.value)}/>}</Field>
    <div className="ba-actions">
      <ControlButton disabled={disabled} onClick={() => {
        const item = OPERATIONS.find(entry => entry.key === operation)!;
        remember(); void controller.advanced(item.key, item.method, parameters, item.label);
      }}>提交操作</ControlButton>
      <ControlButton variant="secondary" disabled={disabled} onClick={() => setParameters(pretty(template(operation, state)))}>填入当前样本与地址</ControlButton>
    </div>
    {state.patchSetId ? <p className="ba-note">当前补丁草案：<code>{state.patchSetId}</code></p> : null}
  </Section>;
  const contents: Record<View, ReactNode> = { samples: sampleContent, functions: results('functions'), strings: results('strings'), imports: results('imports'), debug: debugContent, advanced: advancedContent };
  return <main className="ba-page" aria-busy={state.loading || undefined}>
    <PageHeader title="二进制分析" description="从受管样本到分析、调试与证据。" actions={
      <ControlButton disabled={disabled} onClick={() => void controller.importSample()} loading={state.busy === 'sample.import'}><FileUp size={16}/>导入样本</ControlButton>}/>
    {state.sample || state.jobId ? <div className="ba-current"><div><strong>当前样本</strong><code>{state.sample?.sampleId}</code></div>
      <div><strong>分析任务</strong><code>{state.jobId}</code></div>
      {state.job ? <Badge tone={state.job.state === 'completed' ? 'success' : state.job.state === 'failed' ? 'danger' : 'neutral'}>{state.job.state}</Badge> : null}
      <ControlButton size="sm" variant="secondary" disabled={disabled || !state.jobId} onClick={() => void controller.readJob()}>读取任务状态</ControlButton></div> : null}
    {state.address ? <p className="ba-note">当前地址：<code>{state.address.value}</code> · {state.address.addressSpace}</p> : null}
    {state.error ? <ErrorState title="操作未完成" description={state.error.message} errorId={state.error.operationId}
      action={retry ? <ControlButton variant="secondary" size="sm" disabled={disabled} onClick={() => void retry()}>重新读取</ControlButton> : undefined}/> : null}
    <div className="ba-status" role="status" aria-live="polite">{state.busy || state.loading ? <Spinner label={state.status || '正在处理…'}/> : state.status}</div>
    <Tabs label="二进制分析视图" value={state.view} onValueChange={value => {
      if (!Object.hasOwn(LABELS, value)) throw Error('页面无效'); void controller.view(value as View);
    }} items={(Object.keys(LABELS) as View[]).map(view => ({ value: view, label: LABELS[view], content: contents[view], disabled }))}/>
    <Drawer open={Boolean(state.detail)} title={state.detail?.title ?? '分析详情'} description="操作返回的结构化结果" className="ba-drawer" finalFocus={finalFocus}
      onOpenChange={open => { if (!open) controller.closeDetail(); }}>{state.detail ? state.detail.value === undefined ?
        <Spinner label="正在读取详情…"/> : <Json value={state.detail.value}/> : null}</Drawer>
  </main>;
}
