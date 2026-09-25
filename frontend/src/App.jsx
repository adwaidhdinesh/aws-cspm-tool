import { useEffect, useMemo, useState } from "react";
import { api } from "./api";

const TABS = ["Overview", "Assets", "Findings", "Compliance", "Drift", "AI Copilot"];
const SEVERITIES = ["Critical", "High", "Medium", "Low"];
const SEVERITY_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };

const formatDate = (value) => value ? new Date(value).toLocaleString() : "—";
const grade = (score) => score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

function csvDownload(rows, name) {
  if (!rows.length) return;
  const fields = Object.keys(rows[0]);
  const value = (item) => `"${String(item ?? "").replaceAll('"', '""')}"`;
  const content = [fields.join(","), ...rows.map((row) => fields.map((field) => value(row[field])).join(","))].join("\n");
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([content], { type: "text/csv" }));
  link.download = name;
  link.click();
  URL.revokeObjectURL(link.href);
}

function Stat({ label, value, detail, tone }) {
  return <article className={`stat ${tone || ""}`}><span>{label}</span><strong>{value}</strong>{detail && <small>{detail}</small>}</article>;
}

function Empty({ children }) {
  return <div className="empty">{children}</div>;
}

function InlineLoading() {
  return <div className="inline-loading" role="status">Loading details…</div>;
}

function Trend({ scans }) {
  const history = [...scans].slice(0, 8).reverse();
  if (history.length < 2) return null;
  return <section className="panel trend-panel">
    <div><h2>Posture trend</h2><p className="muted">Last {history.length} scans</p></div>
    <div className="trend-bars" aria-label="Posture score over recent scans">
      {history.map((item) => <div className="trend-bar" key={item.id} title={`Scan #${item.id}: ${item.score}/100`}>
        <i style={{ height: `${Math.max(item.score, 4)}%` }} /><span>{item.score}</span>
      </div>)}
    </div>
  </section>;
}

function FindingRow({ finding, expanded, onToggle }) {
  return <article className={`finding ${finding.status === "FAIL" ? "failed" : "passed"}`}>
    <button className="finding-head" onClick={onToggle} aria-expanded={expanded}>
      <span className={`badge ${finding.severity?.toLowerCase()}`}>{finding.severity}</span>
      <span className={`badge status-${finding.status?.toLowerCase()}`}>{finding.status}</span>
      <span className="finding-title">{finding.title}</span>
      <span className="finding-resource">{finding.service} / {finding.resource}</span>
      <span>{expanded ? "−" : "+"}</span>
    </button>
    {expanded && <div className="finding-body">
      <dl>
        <div><dt>Rule</dt><dd>{finding.rule_id}</dd></div>
        <div><dt>CIS control</dt><dd>{finding.cis_control}</dd></div>
        <div><dt>Description</dt><dd>{finding.description || "—"}</dd></div>
        <div><dt>Remediation</dt><dd>{finding.remediation || "—"}</dd></div>
        <div><dt>NIST 800-53</dt><dd>{finding.nist_controls || "—"}</dd></div>
        <div><dt>PCI DSS v4.0</dt><dd>{finding.pci_controls || "—"}</dd></div>
        <div><dt>ISO 27001:2022</dt><dd>{finding.iso_controls || "—"}</dd></div>
      </dl>
    </div>}
  </article>;
}

export default function App() {
  const [scans, setScans] = useState([]);
  const [scanId, setScanId] = useState("");
  const [data, setData] = useState(null);
  const [extras, setExtras] = useState({});
  const [extrasLoading, setExtrasLoading] = useState({});
  const [extrasError, setExtrasError] = useState({});
  const [tab, setTab] = useState("Overview");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [severityFilter, setSeverityFilter] = useState(SEVERITIES);
  const [statusFilter, setStatusFilter] = useState(["PASS", "FAIL"]);
  const [openFinding, setOpenFinding] = useState(null);
  const [assetId, setAssetId] = useState("");
  const [chat, setChat] = useState([]);
  const [question, setQuestion] = useState("");
  const [asking, setAsking] = useState(false);

  useEffect(() => {
    api("/api/scans")
      .then((items) => { setScans(items); setScanId((current) => current || String(items[0]?.id || "")); })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!scanId) return;
    setLoading(true); setError(""); setData(null); setChat([]); setAssetId(""); setExtras({}); setExtrasLoading({}); setExtrasError({});
    Promise.all([
      api(`/api/scans/${scanId}`), api(`/api/scans/${scanId}/findings`),
      api(`/api/scans/${scanId}/assets`)
    ]).then(([scan, findings, assets]) => {
      setData({ scan, findings, assets });
      setAssetId(String(assets.find((asset) => asset.status === "ACTIVE")?.id || ""));
    }).catch((err) => setError(err.message)).finally(() => setLoading(false));
  }, [scanId]);

  useEffect(() => {
    const routes = {
      Compliance: ["compliance", `/api/scans/${scanId}/compliance`],
      Drift: ["drift", `/api/scans/${scanId}/drift`],
      "AI Copilot": ["copilot", `/api/scans/${scanId}/copilot/status`]
    };
    const request = routes[tab];
    if (!scanId || !request || extras[request[0]] || extrasLoading[request[0]] || extrasError[request[0]]) return;
    let cancelled = false;
    setExtrasLoading((current) => ({ ...current, [request[0]]: true }));
    api(request[1])
      .then((result) => !cancelled && setExtras((current) => ({ ...current, [request[0]]: result })))
      .catch((err) => {
        if (!cancelled) {
          setError(err.message);
          setExtrasError((current) => ({ ...current, [request[0]]: err.message }));
        }
      })
      .finally(() => !cancelled && setExtrasLoading((current) => ({ ...current, [request[0]]: false })));
    return () => { cancelled = true; };
  }, [tab, scanId, extras, extrasLoading, extrasError]);

  const findings = data?.findings || [];
  const activeAssets = useMemo(() => (data?.assets || []).filter((item) => item.status === "ACTIVE"), [data]);
  const filtered = useMemo(() => findings.filter((item) => severityFilter.includes(item.severity) && statusFilter.includes(item.status)), [findings, severityFilter, statusFilter]);
  const failures = findings.filter((item) => item.status === "FAIL");
  const selectedAsset = data?.assets.find((item) => String(item.id) === assetId);
  const services = useMemo(() => activeAssets.reduce((result, asset) => ({ ...result, [asset.service]: (result[asset.service] || 0) + 1 }), {}), [activeAssets]);
  const highestPriority = useMemo(
    () => [...failures].sort((left, right) => SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity])[0],
    [findings]
  );
  const failureRate = data?.scan?.total_checks ? Math.round(data.scan.failed_checks / data.scan.total_checks * 100) : 0;

  function toggleFilter(value, state, setter) {
    setter(state.includes(value) ? state.filter((item) => item !== value) : [...state, value]);
  }

  function openPriorityFinding() {
    if (!highestPriority) return;
    setSeverityFilter([highestPriority.severity]);
    setStatusFilter(["FAIL"]);
    setOpenFinding(highestPriority.id);
    setTab("Findings");
  }

  async function submitQuestion(event) {
    event.preventDefault();
    const text = question.trim();
    if (!text || asking) return;
    setQuestion(""); setChat((items) => [...items, { role: "user", content: text }]); setAsking(true);
    try {
      const response = await api(`/api/scans/${scanId}/copilot`, { method: "POST", body: JSON.stringify({ question: text }) });
      setChat((items) => [...items, { role: "assistant", content: response.answer }]);
    } catch (err) {
      setChat((items) => [...items, { role: "assistant", content: `⚠️ ${err.message}` }]);
    } finally { setAsking(false); }
  }

  if (loading && !data) return <main className="center-message">Loading CSPM data…</main>;
  if (error && !data) return <main className="center-message error">Unable to load the dashboard: {error}</main>;
  if (!scans.length) return <main className="center-message"><h1>No scans yet</h1><p>Run <code>python main.py</code> after PostgreSQL is available, then refresh this page.</p></main>;

  const scan = data?.scan;
  const maxService = Math.max(...Object.values(services), 1);
  return <main className="app-shell">
    <header className="topbar">
      <div><p className="eyebrow">CSPM / AWS</p><h1>Cloud Security <em>Posture</em></h1><p className="subtitle">Continuous assessment against CIS Foundations benchmarks</p></div>
      <label className="scan-picker">Scan
        <select value={scanId} onChange={(event) => setScanId(event.target.value)}>
          {scans.map((item) => <option key={item.id} value={item.id}>#{item.id} · {item.account_id} · {formatDate(item.timestamp)}</option>)}
        </select>
      </label>
    </header>

    {error && <div className="notice error">{error}</div>}
    {scan && <>
      <section className="context"><span>Account <b>{scan.account_id}</b></span><span>Scan <b>#{scan.id}</b></span><span>{formatDate(scan.timestamp)}</span><span className={`grade grade-${grade(scan.score)}`}>Grade {grade(scan.score)}</span></section>
      <nav className="tabs" aria-label="Dashboard sections">{TABS.map((item) => <button key={item} className={tab === item ? "active" : ""} onClick={() => setTab(item)}>{item}</button>)}</nav>

      {tab === "Overview" && <section className="section">
        <div className="hero"><div><p className="eyebrow">Current security posture</p><strong className="score">{scan.score}<small>/100</small></strong><p>Grade {grade(scan.score)} · {failureRate}% of checks need attention</p></div><div className="severity-strip" aria-label="Failures by severity">{SEVERITIES.map((severity) => <span key={severity} className={`badge ${severity.toLowerCase()}`}>{severity} {failures.filter((f) => f.severity === severity).length}</span>)}</div></div>
        <section className={`priority ${highestPriority ? "priority-open" : "priority-clear"}`}>
          <div><p className="eyebrow">{highestPriority ? "Start here" : "Good news"}</p><h2>{highestPriority ? `${highestPriority.severity} risk: ${highestPriority.title}` : "No failing checks in this scan"}</h2><p>{highestPriority ? `${highestPriority.service} · ${highestPriority.resource}` : "This account passed every recorded check."}</p></div>
          {highestPriority && <button onClick={openPriorityFinding}>View remediation <span aria-hidden="true">→</span></button>}
        </section>
        <div className="stats"><Stat label="Active assets" value={activeAssets.length} detail="Resources currently in scope" /><Stat label="Checks failed" value={`${scan.failed_checks}/${scan.total_checks}`} detail="Need investigation" tone="danger" /><Stat label="Checks passed" value={scan.passed_checks} detail="No issue detected" tone="success" /><Stat label="Services monitored" value={Object.keys(services).length} detail="AWS service types" /></div>
        <div className="overview-grid"><Trend scans={scans} /><section className="panel"><h2>Assets by service</h2>{Object.keys(services).length ? Object.entries(services).map(([service, count]) => <div className="bar-row" key={service}><span>{service}</span><div><i style={{ width: `${count / maxService * 100}%` }} /></div><b>{count}</b></div>) : <Empty>No active assets.</Empty>}</section><section className="panel"><h2>Failures by service</h2>{failures.length ? Object.entries(failures.reduce((result, f) => ({ ...result, [f.service]: (result[f.service] || 0) + 1 }), {})).map(([service, count]) => <div className="bar-row red" key={service}><span>{service}</span><div><i style={{ width: `${count / Math.max(failures.length, 1) * 100}%` }} /></div><b>{count}</b></div>) : <Empty>No failing findings.</Empty>}</section></div>
      </section>}

      {tab === "Assets" && <section className="section"><h2>Asset inventory</h2><p className="muted">Resources missing from a later scan remain available as deleted assets for historical review.</p><div className="stats compact"><Stat label="Active assets" value={activeAssets.length} /><Stat label="Regions" value={new Set(activeAssets.map((item) => item.region).filter(Boolean)).size} /><Stat label="Services" value={Object.keys(services).length} /></div><div className="asset-layout"><section className="panel"><label>Browse asset<select value={assetId} onChange={(event) => setAssetId(event.target.value)}>{data.assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.name || asset.resource_id} · {asset.service} · {asset.status}</option>)}</select></label></section>{selectedAsset && <section className="panel"><h2>{selectedAsset.name || selectedAsset.resource_id}</h2><dl className="details"><div><dt>Service</dt><dd>{selectedAsset.service}</dd></div><div><dt>Resource ID</dt><dd>{selectedAsset.resource_id}</dd></div><div><dt>Region</dt><dd>{selectedAsset.region || "—"}</dd></div><div><dt>Status</dt><dd>{selectedAsset.status}</dd></div><div><dt>ARN</dt><dd>{selectedAsset.arn || "—"}</dd></div><div><dt>First seen</dt><dd>{formatDate(selectedAsset.first_seen)}</dd></div></dl><h3>Tags</h3><pre>{JSON.stringify(selectedAsset.tags, null, 2)}</pre><h3>Configuration</h3><pre>{JSON.stringify(selectedAsset.metadata, null, 2)}</pre></section>}</div></section>}

      {tab === "Findings" && <section className="section"><div className="section-heading"><div><h2>Findings</h2><p className="muted">Expand a finding for remediation and framework mappings.</p></div><button className="secondary" onClick={() => csvDownload(filtered, "findings.csv")}>Download CSV</button></div><div className="filters"><fieldset><legend>Severity</legend>{SEVERITIES.map((item) => <label key={item}><input type="checkbox" checked={severityFilter.includes(item)} onChange={() => toggleFilter(item, severityFilter, setSeverityFilter)} /> {item}</label>)}</fieldset><fieldset><legend>Status</legend>{["PASS", "FAIL"].map((item) => <label key={item}><input type="checkbox" checked={statusFilter.includes(item)} onChange={() => toggleFilter(item, statusFilter, setStatusFilter)} /> {item}</label>)}</fieldset></div><div className="findings">{filtered.length ? filtered.map((finding) => <FindingRow key={finding.id} finding={finding} expanded={openFinding === finding.id} onToggle={() => setOpenFinding(openFinding === finding.id ? null : finding.id)} />) : <Empty>No findings match these filters.</Empty>}</div></section>}

      {tab === "Compliance" && <section className="section"><h2>Compliance framework mapping</h2><p className="muted">Mappings are simplified references, not an official framework crosswalk.</p>{extrasError.compliance ? <Empty>Compliance details could not be loaded.</Empty> : extrasLoading.compliance || !extras.compliance ? <InlineLoading /> : <div className="frameworks">{extras.compliance.frameworks.map((framework) => { const controls = extras.compliance.summary[framework] || {}; const total = Object.values(controls).length; const passed = Object.values(controls).filter((item) => item.fail === 0).length; return <section className="panel" key={framework}><h3>{framework}</h3><strong className="framework-score">{total ? Math.round(passed / total * 100) : 100}%</strong><p>{passed} of {total} mapped controls passing</p><table><thead><tr><th>Control</th><th>Failing</th><th>Passing</th></tr></thead><tbody>{Object.entries(controls).map(([control, count]) => <tr key={control}><td>{control}</td><td>{count.fail}</td><td>{count.pass}</td></tr>)}</tbody></table></section>; })}</div>}</section>}

      {tab === "Drift" && <section className="section"><h2>Drift since previous scan</h2>{extrasError.drift ? <Empty>Drift details could not be loaded.</Empty> : extrasLoading.drift || !extras.drift ? <InlineLoading /> : extras.drift.previous_scan ? <><p className="muted">Compared with scan #{extras.drift.previous_scan.id} from {formatDate(extras.drift.previous_scan.timestamp)}.</p><div className="stats compact">{Object.entries(extras.drift.counts).map(([label, value]) => <Stat key={label} label={label.replaceAll("_", " ")} value={value} />)}</div><div className="panel table-wrap"><table><thead><tr><th>Type</th><th>Severity</th><th>Rule</th><th>Service</th><th>Resource</th><th>Detail</th></tr></thead><tbody>{extras.drift.changes.map((change, index) => <tr key={`${change.rule_id}-${index}`}><td>{change.type}</td><td>{change.severity}</td><td>{change.rule_id}</td><td>{change.service}</td><td>{change.resource}</td><td>{change.detail}</td></tr>)}</tbody></table>{!extras.drift.changes.length && <Empty>No drift detected since the previous scan.</Empty>}</div></> : <Empty>This is the earliest scan for this account — nothing to compare yet.</Empty>}</section>}

      {tab === "AI Copilot" && <section className="section copilot"><h2>AI Security Copilot</h2><p className="muted">Answers use the selected scan only; the copilot cannot contact AWS or run scans.</p>{extrasError.copilot ? <Empty>Copilot configuration could not be loaded.</Empty> : extrasLoading.copilot || !extras.copilot ? <InlineLoading /> : <>{extras.copilot.configuration_message && <div className="notice">{extras.copilot.configuration_message}</div>}<div className="suggestions">{["What are my most critical security issues?", "What should I fix first?", "Which services have the most issues?"].map((item) => <button key={item} onClick={() => setQuestion(item)}>{item}</button>)}</div><div className="chat">{chat.length ? chat.map((message, index) => <div key={index} className={`message ${message.role}`}>{message.content}</div>) : <Empty>Ask a question about this scan to begin.</Empty>}</div><form onSubmit={submitQuestion}><input value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="Ask about this scan…" aria-label="Ask the AI security copilot" /><button disabled={asking}>{asking ? "Thinking…" : "Ask"}</button></form></>}</section>}
    </>}
  </main>;
}
