import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  BarChart3,
  Bot,
  ChevronRight,
  CheckCircle2,
  Download,
  FileJson,
  FileUp,
  Play,
  Plus,
  RefreshCw,
  Save,
  Search,
  Send,
  Settings,
  Shield,
  Target,
  Trash2,
  XCircle,
} from "lucide-react";
import "./styles.css";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

const OWASP_CATEGORIES = [
  "LLM01-Prompt Injection",
  "LLM02-Sensitive Information Disclosure",
  "LLM03-Supply Chain",
  "LLM04-Data_model_poisoning",
  "LLM05-Improper_output_handling",
  "LLM06-Excessive_agency",
  "LLM07-Insecure Plugin Design",
  "LLM08-Vector_Embedding_Weaknesses",
  "LLM09-Misinformation",
  "LLM10-Unbounded_Consumption",
];

const CRESCENDO_PROFILES = {
  authority_escalation_system_prompt: "Authority Escalation: System Prompt Extraction",
  hypothetical_phishing_campaign: "Hypothetical Framing: Phishing Campaign",
  roleplay_physical_security_bypass: "Role-Playing: Physical Security Bypass",
  incremental_policy_disable: "Incremental Normalization: Disable Policy",
  educational_malware_code: "Educational Framing: Malware Code",
};

const emptyTarget = {
  name: "Internal HR Chatbot",
  url: "mock://internal-hr-chatbot",
  method: "POST",
  headers: { "Content-Type": "application/json" },
  request_template: { message: "{{prompt}}", conversation_id: "{{conversation_id}}" },
  auth: { type: "none" },
  timeout_seconds: null,
};

function App() {
  const [page, setPage] = useState("Dashboard");
  const [targets, setTargets] = useState([]);
  const [reports, setReports] = useState([]);
  const [scenarios, setScenarios] = useState({});
  const [settings, setSettings] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState("");

  const refresh = async () => {
    setLoading(true);
    try {
      const [targetData, reportData, scenarioData, runtimeData] = await Promise.all([
        api("/targets"),
        api("/reports"),
        api("/scenarios"),
        api("/settings/runtime"),
      ]);
      setTargets(targetData);
      setReports(reportData);
      setScenarios(scenarioData.scenarios || {});
      setSettings(runtimeData);
    } catch (error) {
      setNotice(error.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  return (
    <div className="app-shell">
      <Sidebar page={page} setPage={setPage} />
      <main className="main-panel">
        <TopBar loading={loading} refresh={refresh} notice={notice} clearNotice={() => setNotice("")} />
        {page === "Dashboard" && <Dashboard targets={targets} reports={reports} scenarios={scenarios} />}
        {page === "Targets" && <Targets targets={targets} refresh={refresh} setNotice={setNotice} />}
        {page === "Simulations" && (
          <Simulations targets={targets} reports={reports} scenarios={scenarios} refresh={refresh} setPage={setPage} setNotice={setNotice} />
        )}
        {page === "Reports" && <Reports reports={reports} />}
        {page === "Tool scan" && <ToolScan targets={targets} setNotice={setNotice} />}
        {page === "Configurations" && <Configurations settings={settings} setSettings={setSettings} setNotice={setNotice} />}
      </main>
    </div>
  );
}

function Sidebar({ page, setPage }) {
  const items = [
    ["Dashboard", BarChart3],
    ["Targets", Target],
    ["Simulations", Activity],
    ["Reports", FileJson],
    ["Tool scan", Search],
    ["Configurations", Settings],
  ];
  return (
    <aside className="sidebar">
      <div className="brand"><span className="brand-badge" />H-ATLAS</div>
      <nav className="nav-list">
        {items.map(([label, Icon]) => (
          <button key={label} className={page === label ? "nav-item active" : "nav-item"} onClick={() => setPage(label)}>
            <Icon size={18} />
            <span>{label}</span>
          </button>
        ))}
      </nav>
    </aside>
  );
}

function TopBar({ loading, refresh, notice, clearNotice }) {
  return (
    <>
      <div className="topbar">
        <div />
        <button className="icon-button" onClick={refresh} title="Refresh">
          <RefreshCw size={18} className={loading ? "spin" : ""} />
        </button>
      </div>
      {notice && (
        <div className="alert error">
          <AlertTriangle size={18} />
          <span>{notice}</span>
          <button className="ghost-button compact" onClick={clearNotice}>Dismiss</button>
        </div>
      )}
    </>
  );
}

function Dashboard({ targets, reports, scenarios }) {
  const completed = reports.filter(({ report }) => String(report.status).toUpperCase() === "COMPLETED");
  const failed = reports.filter(({ report }) => String(report.status).toUpperCase() === "FAILED");
  const percents = reports.flatMap(({ report }) => (report.scenario_results || []).map(scenarioPercent));
  const avg = percents.length ? Math.round(percents.reduce((a, b) => a + b, 0) / percents.length) : 0;
  const threat = avg >= 70 ? ["CRITICAL", "red"] : avg >= 40 ? ["ELEVATED", "yellow"] : avg >= 10 ? ["MODERATE", "blue"] : ["LOW", "green"];
  const inventory = Object.values(scenarios).flat().length;
  const coverage = coverageRows(reports);

  return (
    <section>
      <h1>Dashboard</h1>
      <ThreatBanner level={threat[0]} tone={threat[1]} value={avg} />
      <div className="kpi-grid five">
        <Kpi label="Targets" value={targets.length} sublabel="registered endpoints" tone="blue" />
        <Kpi label="Attack Scenarios" value={inventory} sublabel="plugin inventory" tone="yellow" />
        <Kpi label="Scans Run" value={reports.length} sublabel="total executions" tone="blue" />
        <Kpi label="Completed" value={completed.length} sublabel="successful scans" tone="green" />
        <Kpi label="Failed" value={failed.length} sublabel="error / cancelled" tone="red" />
      </div>
      <div className="split-grid">
        <Panel title="Recent Activity">
          {reports.length ? reports.slice(0, 8).map(({ filename, report }) => (
            <ActivityRow key={filename} report={report} />
          )) : <EmptyText>No simulations have been run yet.</EmptyText>}
        </Panel>
        <Panel title="Coverage">
          {coverage.length ? coverage.map(row => <CoverageBar key={row.category} {...row} />) : <EmptyText>Run simulations to see OWASP coverage.</EmptyText>}
        </Panel>
      </div>
    </section>
  );
}

function ThreatBanner({ level, value, tone }) {
  return (
    <div className={`threat-banner ${tone}`}>
      <div>
        <div className="eyebrow">SYSTEM THREAT LEVEL</div>
        <div className="threat-title">{level}</div>
      </div>
      <div className="threat-score">
        <strong>{value}%</strong>
        <span>avg vulnerability across all scans</span>
      </div>
    </div>
  );
}

function Kpi({ label, value, sublabel, tone }) {
  return (
    <div className={`kpi-card ${tone}`}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value}</div>
      <div className="kpi-sub">{sublabel}</div>
    </div>
  );
}

function Targets({ targets, refresh, setNotice }) {
  const [mode, setMode] = useState("library");
  const [selected, setSelected] = useState(null);

  if (selected) {
    return <TargetDetail item={selected} back={() => setSelected(null)} refresh={refresh} setNotice={setNotice} />;
  }

  return (
    <section>
      <h1>Targets</h1>
      <Segmented value={mode} onChange={setMode} options={[["library", "Target Library"], ["create", "Create Target"]]} />
      {mode === "create" ? (
        <TargetForm refresh={refresh} setNotice={setNotice} onSaved={() => setMode("library")} />
      ) : (
        <div className="card-grid three">
          {targets.map(item => <TargetCard key={item.filename} item={item} onOpen={() => setSelected(item)} />)}
          {!targets.length && <EmptyText>No targets found. Create a target to start scanning.</EmptyText>}
        </div>
      )}
    </section>
  );
}

function TargetCard({ item, onOpen }) {
  const target = item.target;
  return (
    <button className="target-card" onClick={onOpen}>
      <div className="card-title-row">
        <strong>{target.name}</strong>
        <span className="status-pill running">{target.method}</span>
      </div>
      <div className="muted ellipsis">{target.url}</div>
      <div className="detail-table compact-table">
        <div><span>Auth</span><b>{target.auth?.type || "none"}</b></div>
        <div><span>Timeout</span><b>{target.timeout_seconds || "default"}</b></div>
      </div>
    </button>
  );
}

function TargetDetail({ item, back, refresh, setNotice }) {
  const [editing, setEditing] = useState(false);
  const [current, setCurrent] = useState(item);
  const [test, setTest] = useState(null);
  const target = current.target;

  const deleteTarget = async () => {
    await api(`/targets/${current.filename}`, { method: "DELETE" });
    setNotice("Target deleted.");
    await refresh();
    back();
  };

  const testTarget = async () => {
    setTest({ loading: true });
    try {
      setTest(await api("/targets/test", { method: "POST", body: target }));
    } catch (error) {
      setTest({ ok: false, error: error.message });
    }
  };

  if (editing) {
    return (
      <TargetForm
        filename={current.filename}
        initial={target}
        refresh={refresh}
        setNotice={setNotice}
        onSaved={(saved, payload) => {
          setCurrent({ filename: saved.filename, target: payload });
          setEditing(false);
        }}
      />
    );
  }

  return (
    <section>
      <button className="plain-back" onClick={back}><ArrowLeft size={18} /></button>
      <h1>{target.name}</h1>
      <table className="target-detail-table"><tbody>
        <tr><th>URL</th><td>{target.url}</td></tr>
        <tr><th>Method</th><td>{target.method}</td></tr>
        <tr><th>Auth</th><td>{target.auth?.type || "none"}</td></tr>
        <tr><th>Timeout</th><td>{target.timeout_seconds || "default"}</td></tr>
      </tbody></table>
      <div className="action-row">
        <button className="primary-button" onClick={() => setEditing(true)}>Edit</button>
        <button className="secondary-button" onClick={testTarget}>Test target</button>
        <button className="danger-button" onClick={deleteTarget}><Trash2 size={16} />Delete</button>
      </div>
      {test && <div className={test.ok ? "alert success" : "alert error"}>{test.loading ? "Testing target..." : test.ok ? `OK ${test.status_code}: ${test.preview}` : test.error}</div>}
      <JsonBlock value={target} />
    </section>
  );
}

const STREAMING_TYPES = ["token", "chunk", "event", "sse", "websocket"];
const NON_STREAMING_TYPES = ["synchronous", "retrieval", "generative", "batch", "workflow"];
const AUTH_OPTIONS = [
  ["none", "none - No authentication required"],
  ["bearer_token_from_env", "bearer_token_from_env - Bearer token from environment"],
  ["bearer_token_in_header", "bearer_token_in_header - Bearer token in header"],
  ["api_key_header", "api_key_header - API key in custom header"],
  ["basic_auth", "basic_auth - Basic username/password auth"],
  ["oauth2", "oauth2_client_credentials - OAuth2 client credentials"],
  ["jwt", "jwt_token_auth - JWT token authentication"],
];

function TargetForm({ initial = emptyTarget, filename = "", refresh, setNotice, onSaved }) {
  if (!filename) {
    return <CreateTargetWizard refresh={refresh} setNotice={setNotice} onSaved={onSaved} />;
  }
  return <ManualTargetForm initial={initial} filename={filename} refresh={refresh} setNotice={setNotice} onSaved={onSaved} />;
}

function CreateTargetWizard({ refresh, setNotice, onSaved }) {
  const [deliveryMode, setDeliveryMode] = useState("streaming");
  const [deliveryType, setDeliveryType] = useState("token");
  const [authType, setAuthType] = useState("none");
  const [createOption, setCreateOption] = useState("upload");
  const [draft, setDraft] = useState(buildTargetTemplate({ deliveryMode, deliveryType, authType }));
  const [assistantAnswers, setAssistantAnswers] = useState({});
  const [uploadError, setUploadError] = useState("");
  const [chatMessages, setChatMessages] = useState([
    {
      role: "assistant",
      text: assistantOpeningMessage(deliveryMode, deliveryType, authType),
    },
  ]);
  const [chatInput, setChatInput] = useState("");
  const [assistantLoading, setAssistantLoading] = useState(false);

  useEffect(() => {
    setDraft(current => ({
      ...buildTargetTemplate({ deliveryMode, deliveryType, authType }),
      name: current.name || "Internal HR Chatbot",
      url: current.url || "mock://internal-hr-chatbot",
    }));
  }, [deliveryMode, deliveryType, authType]);

  const applyUploadedJson = async event => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      setDraft(normalizeTarget(parsed));
      setUploadError("");
      setNotice("Uploaded target JSON loaded into the form.");
    } catch (error) {
      setUploadError(`Invalid target JSON: ${error.message}`);
    }
  };

  const sendAssistantMessage = async () => {
    const text = chatInput.trim();
    if (!text) return;
    const nextMessages = [...chatMessages, { role: "user", text }];
    setChatMessages(nextMessages);
    setChatInput("");

    const step = nextAssistantStep(assistantAnswers, authType);
    const updatedAnswers = { ...assistantAnswers };
    const wantsFinal = /generate|final|create json|build json|done|finish/i.test(text);
    if (step && !wantsFinal) {
      updatedAnswers[step.id] = text;
    }
    setAssistantAnswers(updatedAnswers);

    const followUp = nextAssistantQuestion(updatedAnswers, authType);
    if (followUp && !wantsFinal) {
      setChatMessages(messages => [...messages, { role: "assistant", text: followUp }]);
      setDraft(inferTargetFromAssistantAnswers(updatedAnswers, draft, { deliveryMode, deliveryType, authType }));
      return;
    }

    const localDraft = inferTargetFromAssistantAnswers(updatedAnswers, draft, { deliveryMode, deliveryType, authType });
    setDraft(localDraft);
    setAssistantLoading(true);
    try {
      const response = await api("/targets/assistant", {
        method: "POST",
        body: {
          messages: [
            ...nextMessages,
            {
              role: "user",
              text: `Generate the final target JSON from these guided answers: ${JSON.stringify(updatedAnswers)}`,
            },
          ],
          current_target: localDraft,
          delivery_template: localDraft.auth?.template_preview?.delivery_template || deliveryTemplate(deliveryMode, deliveryType),
          auth_template: localDraft.auth?.template_preview?.auth_template || authTemplate(authType),
          combination: localDraft.auth?.template_preview?.combination || "",
        },
      });
      const finalDraft = response.target ? normalizeTarget(response.target) : localDraft;
      setDraft(finalDraft);
      setChatMessages(messages => [...messages, { role: "assistant", text: `${response.reply} Your JSON draft is ready in Template preview. (${response.provider})` }]);
    } catch (error) {
      setDraft(localDraft);
      setChatMessages(messages => [
        ...messages,
        { role: "assistant", text: `I created a local JSON draft from your answers. LLM assistant request failed: ${error.message}` },
      ]);
    } finally {
      setAssistantLoading(false);
    }
  };

  const clearAssistant = () => {
    setAssistantAnswers({});
    setChatInput("");
    setChatMessages([{ role: "assistant", text: assistantOpeningMessage(deliveryMode, deliveryType, authType) }]);
  };

  return (
    <div className="create-target-wizard">
      <h1 className="wizard-title">Configure Your Target</h1>
      <WizardStep title="Step 1: Target Type">
        <Field label={<span>Is your target streaming or non-streaming? <span className="help-dot">?</span></span>}>
          <RadioRow
            value={deliveryMode}
            onChange={value => {
              setDeliveryMode(value);
              setDeliveryType(value === "streaming" ? "token" : "synchronous");
            }}
            options={[["streaming", "streaming"], ["non-streaming", "non-streaming"]]}
          />
        </Field>
        <Field label={`Select ${deliveryMode} type`}>
          <select value={deliveryType} onChange={event => setDeliveryType(event.target.value)}>
            {(deliveryMode === "streaming" ? STREAMING_TYPES : NON_STREAMING_TYPES).map(item => <option key={item}>{item}</option>)}
          </select>
        </Field>
        <p className="hint-text">
          {deliveryMode === "streaming" ? "Choose one: token, chunk, event, sse, websocket." : "Choose one: synchronous, retrieval, generative, batch, workflow."}
        </p>
      </WizardStep>

      <WizardStep title="Step 2: Authentication Type">
        <Field label={<span>Select authentication type <span className="help-dot align-right">?</span></span>}>
          <select value={authType} onChange={event => setAuthType(event.target.value)}>
            {AUTH_OPTIONS.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
          </select>
        </Field>
      </WizardStep>

      <WizardStep title="Step 3: Preview and Download JSON">
        <p className="hint-text">Target mode: {deliveryMode === "streaming" ? "Streaming" : "Non-streaming"} | Type: {deliveryType}</p>
        <p className="combination-text">{draft.auth?.template_preview?.combination}</p>
        <div className="preview-actions">
          <details className="template-preview">
            <summary><ChevronRight size={17} />Template preview</summary>
            <JsonBlock value={draft} />
          </details>
          <DownloadButton filename="target-template.json" label="Download template" text={JSON.stringify(draft, null, 2)} type="application/json" />
        </div>
      </WizardStep>

      <WizardStep title="Step 4: Create Target Options" divider={false}>
        <RadioRow
          value={createOption}
          onChange={setCreateOption}
          options={[["upload", "Upload JSON"], ["assistant", "AI Assistance Chatbot"], ["manual", "Manual Form"]]}
        />
        {createOption === "upload" && (
          <UploadJsonTarget uploadError={uploadError} applyUploadedJson={applyUploadedJson} draft={draft} setCreateOption={setCreateOption} />
        )}
        {createOption === "assistant" && (
          <AssistantTargetBuilder
            messages={chatMessages}
            input={chatInput}
            setInput={setChatInput}
            send={sendAssistantMessage}
            loading={assistantLoading}
            clear={clearAssistant}
          />
        )}
        {createOption === "manual" && (
          <>
            <p className="option-description">Use the manual form below to enter or refine the target configuration directly.</p>
            <div className="alert info">After choosing the target type and authentication template above, complete the Create target form below.</div>
            <ManualTargetForm initial={draft} refresh={refresh} setNotice={setNotice} onSaved={onSaved} onDraftChange={setDraft} />
          </>
        )}
      </WizardStep>
    </div>
  );
}

function WizardStep({ title, children, divider = true }) {
  return (
    <section className={divider ? "wizard-step" : "wizard-step no-divider"}>
      <h2>{title}</h2>
      {children}
    </section>
  );
}

function RadioRow({ value, onChange, options }) {
  return (
    <div className="radio-row">
      {options.map(([id, label]) => (
        <label key={id} className="radio-option">
          <input type="radio" checked={value === id} onChange={() => onChange(id)} />
          <span>{label}</span>
        </label>
      ))}
    </div>
  );
}

function UploadJsonTarget({ uploadError, applyUploadedJson, draft, setCreateOption }) {
  return (
    <div className="option-block">
      <p className="option-description">Upload an existing target JSON, validate it, and optionally load it into the form below.</p>
      <h3>JSON File Upload & Auto Processing</h3>
      <Field label={<span>Upload target JSON <span className="help-dot align-right">?</span></span>}>
        <label className="file-upload">
          <FileUp size={18} />
          <span>Upload JSON</span>
          <input type="file" accept="application/json,.json" onChange={applyUploadedJson} />
        </label>
      </Field>
      {uploadError && <div className="alert error">{uploadError}</div>}
      <button className="secondary-button" type="button" onClick={() => setCreateOption("manual")}>Load current template into manual form</button>
      <JsonBlock value={draft} />
    </div>
  );
}

function AssistantTargetBuilder({ messages, input, setInput, send, clear, loading }) {
  return (
    <div className="assistant-builder">
      <p className="option-description">Use real-time AI chat to generate/refine target JSON aligned to your selected auth and delivery type.</p>
      <h2>AI Assistance Chatbot</h2>
      <p className="option-description">Ask for modifications or say: generate final JSON for my selected configuration.</p>
      <div className="assistant-meta">
        <button className="ghost-button compact" type="button" onClick={clear}>Clear chat</button>
        <span>The configured LLM provider is used when ready; otherwise fallback mode is used.</span>
      </div>
      <div className="assistant-thread">
        {messages.map((message, index) => (
          <div className={`assistant-message ${message.role}`} key={`${message.role}-${index}`}>
            {message.role === "assistant" && <span className="assistant-icon"><Bot size={18} /></span>}
            <p>{message.text}</p>
          </div>
        ))}
        {loading && (
          <div className="assistant-message assistant">
            <span className="assistant-icon"><Bot size={18} /></span>
            <p>Generating target JSON with the configured LLM provider...</p>
          </div>
        )}
      </div>
      <div className="assistant-input">
        <input disabled={loading} value={input} onChange={event => setInput(event.target.value)} onKeyDown={event => event.key === "Enter" && send()} placeholder="Describe what you want in the target JSON" />
        <button className="icon-button" type="button" disabled={loading} onClick={send} title="Send"><Send size={18} /></button>
      </div>
    </div>
  );
}

function ManualTargetForm({ initial = emptyTarget, filename = "", refresh, setNotice, onSaved, onDraftChange }) {
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState({
    name: initial.name,
    url: initial.url,
    method: initial.method,
    headers: JSON.stringify(initial.headers || {}, null, 2),
    request_template: JSON.stringify(initial.request_template || {}, null, 2),
    auth: JSON.stringify(initial.auth || { type: "none" }, null, 2),
    timeout_seconds: initial.timeout_seconds || "",
  });

  useEffect(() => {
    setForm({
      name: initial.name,
      url: initial.url,
      method: initial.method,
      headers: JSON.stringify(initial.headers || {}, null, 2),
      request_template: JSON.stringify(initial.request_template || {}, null, 2),
      auth: JSON.stringify(initial.auth || { type: "none" }, null, 2),
      timeout_seconds: initial.timeout_seconds || "",
    });
  }, [initial]);

  const updateForm = patch => {
    setForm(current => {
      const next = { ...current, ...patch };
      try {
        onDraftChange?.({
          name: next.name,
          url: next.url,
          method: next.method,
          headers: JSON.parse(next.headers || "{}"),
          request_template: JSON.parse(next.request_template || "{}"),
          auth: JSON.parse(next.auth || "{}"),
          timeout_seconds: next.timeout_seconds ? Number(next.timeout_seconds) : null,
        });
      } catch {
        // Keep editing responsive while JSON is temporarily invalid.
      }
      return next;
    });
  };

  const save = async event => {
    event.preventDefault();
    if (saving) return;
    setSaving(true);
    try {
      const payload = {
        name: form.name,
        url: form.url,
        method: form.method,
        headers: JSON.parse(form.headers || "{}"),
        request_template: JSON.parse(form.request_template || "{}"),
        auth: JSON.parse(form.auth || "{}"),
        timeout_seconds: form.timeout_seconds ? Number(form.timeout_seconds) : null,
      };
      const saved = await api(filename ? `/targets/${filename}` : "/targets", { method: filename ? "PUT" : "POST", body: payload });
      setNotice("Target saved.");
      await refresh();
      onSaved?.(saved, payload);
    } catch (error) {
      setNotice(`Unable to save target: ${error.message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <form className="form-panel" onSubmit={save}>
      <h2>{filename ? "Edit target" : "Create target"}</h2>
      <Field label="Target name"><input value={form.name} onChange={e => updateForm({ name: e.target.value })} /></Field>
      <Field label="URL"><input value={form.url} onChange={e => updateForm({ url: e.target.value })} /></Field>
      <div className="form-grid">
        <Field label="Method"><select value={form.method} onChange={e => updateForm({ method: e.target.value })}>{["POST", "GET", "PUT", "PATCH"].map(x => <option key={x}>{x}</option>)}</select></Field>
        <Field label="Timeout"><input type="number" min="1" max="300" value={form.timeout_seconds} onChange={e => updateForm({ timeout_seconds: e.target.value })} placeholder="default" /></Field>
      </div>
      <Field label="Headers JSON"><textarea rows={5} value={form.headers} onChange={e => updateForm({ headers: e.target.value })} /></Field>
      <Field label="Request body template JSON"><textarea rows={6} value={form.request_template} onChange={e => updateForm({ request_template: e.target.value })} /></Field>
      <Field label="Auth config JSON"><textarea rows={6} value={form.auth} onChange={e => updateForm({ auth: e.target.value })} /></Field>
      <div className="action-row"><button className="primary-button" type="submit" disabled={saving}><Save size={16} />{saving ? "Saving..." : "Save target"}</button></div>
    </form>
  );
}

function Simulations({ targets, reports, scenarios, refresh, setPage, setNotice }) {
  const [view, setView] = useState("history");
  const [selected, setSelected] = useState(null);
  const [prefill, setPrefill] = useState(null);

  if (view === "new") {
    return <NewSimulation targets={targets} scenarios={scenarios} refresh={refresh} setNotice={setNotice} back={() => setView("history")} prefill={prefill} />;
  }
  if (selected) {
    return <SimulationDetail report={selected.report} back={() => setSelected(null)} rerun={(mode) => { setPrefill({ report: selected.report, mode }); setSelected(null); setView("new"); }} />;
  }
  return <SimulationHistory reports={reports} open={setSelected} create={() => { setPrefill(null); setView("new"); }} />;
}

function SimulationHistory({ reports, open, create }) {
  const [query, setQuery] = useState("");
  const filtered = reports.filter(({ report }) => JSON.stringify(report).toLowerCase().includes(query.toLowerCase()));
  return (
    <section>
      <h1>Simulations</h1>
      <div className="toolbar">
        <div className="search-box"><Search size={17} /><input placeholder="Search by any field" value={query} onChange={e => setQuery(e.target.value)} /></div>
        <button className="primary-button" onClick={create}><Plus size={16} />New Simulation</button>
      </div>
      <div className="card-grid three">
        {filtered.map(item => <SimulationCard key={item.filename} item={item} onOpen={() => open(item)} />)}
        {!filtered.length && <EmptyText>No simulations found. Click New Simulation to start a scan.</EmptyText>}
      </div>
    </section>
  );
}

function SimulationCard({ item, onOpen }) {
  const report = item.report;
  const status = String(report.status || "RUNNING").toUpperCase();
  const statusClass = status === "COMPLETED" ? "complete" : status === "FAILED" ? "failed" : "running";
  const percent = simulationPercent(report);
  const categories = [...new Set((report.scenario_results || []).map(s => s.owasp_category))].slice(0, 2).join(", ") || "-";
  return (
    <button className="simulation-card" onClick={onOpen}>
      <div className="simulation-card-header">
        <strong>{report.scan_name || "Simulation"}</strong>
        <span className={`status-pill ${statusClass}`}>{status === "COMPLETED" ? "Complete" : status === "FAILED" ? "Failed" : "Running"}</span>
      </div>
      <div className="simulation-card-meta">Target: {report.target_name || "-"}</div>
      <div className="simulation-card-meta">Vulnerability type: {categories}</div>
      <div className="simulation-card-row"><span>Vulnerability Found</span><b>{percent}%</b></div>
      <div className="simulation-card-row"><span>Status</span><span>{status}</span></div>
      <div className="simulation-card-row"><span>Scan initiated</span><span>{formatDate(report.started_at)}</span></div>
    </button>
  );
}

function SimulationDetail({ report, back, rerun }) {
  const status = String(report.status || "RUNNING").toUpperCase();
  return (
    <section>
      <button className="plain-back" onClick={back}><ArrowLeft size={18} /></button>
      <h1>{report.scan_name} <span className={`status-pill inline ${status === "COMPLETED" ? "complete" : "failed"}`}>{status}</span></h1>
      <table className="target-detail-table"><tbody>
        <tr><th>Target</th><td>{report.target_name}</td></tr>
        <tr><th>Status</th><td>{status}</td></tr>
        <tr><th>Scenarios run</th><td>{(report.scenario_results || []).length}</td></tr>
        <tr><th>Avg vulnerability</th><td>{simulationPercent(report)}%</td></tr>
      </tbody></table>
      <div className="action-row">
        <button className="primary-button" onClick={() => rerun("rerun")}><Play size={16} />Rerun</button>
        <button className="primary-button" onClick={() => rerun("modify")}>Edit & Scan</button>
      </div>
      <ScenarioResults report={report} />
    </section>
  );
}

function NewSimulation({ targets, scenarios, refresh, setNotice, back, prefill }) {
  const firstTarget = targets[0]?.target;
  const [scanName, setScanName] = useState(prefill?.report ? `${prefill.report.scan_name} ${prefill.mode === "rerun" ? "Rerun" : "Modified"}` : `LLM01 Scan ${new Date().toLocaleString()}`);
  const [targetName, setTargetName] = useState(prefill?.report?.target_name || firstTarget?.name || "");
  const [category, setCategory] = useState(firstCategory(prefill?.report) || OWASP_CATEGORIES[0]);
  const [turnMode, setTurnMode] = useState("Single-turn");
  const [profile, setProfile] = useState("authority_escalation_system_prompt");
  const [settings, setSettings] = useState({ max_turns: 10, timeout_seconds: 30, concurrency: 2, retry_count: 2, temperature: 0.2 });
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const categoryScenarios = scenarios[category] || [];
  const filteredScenarios = categoryScenarios.filter(s => scenarioMatchesTurnMode(s, turnMode));
  const selectedScenarioIds = filteredScenarios.map(s => s.id);
  const categoryTurnCounts = categoryScenarios.reduce(
    (acc, scenario) => {
      acc.single_turn += Number(scenario.turn_counts?.single_turn || 0);
      acc.multi_turn += Number(scenario.turn_counts?.multi_turn || 0);
      acc.total += Number(scenario.turn_counts?.total || 0);
      return acc;
    },
    { single_turn: 0, multi_turn: 0, total: 0 },
  );
  const selectedTurnScenarioCount = turnMode === "Single-turn" ? categoryTurnCounts.single_turn : categoryTurnCounts.multi_turn;
  const selectedTarget = targets.find(item => item.target.name === targetName)?.target;

  const start = async () => {
    setRunning(true);
    setResult(null);
    try {
      const ids = selectedScenarioIds.length ? selectedScenarioIds : filteredScenarios.slice(0, 1).map(s => s.id);
      const payload = {
        scan_name: scanName,
        target: selectedTarget,
        owasp_category: category,
        scenario_ids: ids,
        settings: {
          ...settings,
          max_turns: turnMode === "Multi-turn" ? Number(settings.max_turns) : 1,
          crescendo_profile: profile,
          prompt_injection_include_single_turn: turnMode === "Single-turn" && ids.includes("llm01.prompt_injection"),
        },
      };
      const scan = await api("/scans", { method: "POST", body: payload });
      setResult(scan);
      setNotice(`Scan finished with status ${scan.status}.`);
      await refresh();
    } catch (error) {
      setNotice(error.message);
    } finally {
      setRunning(false);
    }
  };

  return (
    <section>
      <button className="plain-back" onClick={back}><ArrowLeft size={18} /></button>
      <h1>Simulations</h1>
      {prefill?.mode && <div className="alert info">{prefill.mode === "rerun" ? "Rerun mode loaded. Review details and click Start scan to execute again." : "Modify mode loaded. Update configuration, then click Start scan."}</div>}
      {!targets.length ? <EmptyText>Create a target before starting a scan.</EmptyText> : (
        <div className="form-panel">
          <Field label="Scan name"><input value={scanName} onChange={e => setScanName(e.target.value)} /></Field>
          <div className="form-grid">
            <Field label="Target"><select value={targetName} onChange={e => setTargetName(e.target.value)}>{targets.map(t => <option key={t.filename}>{t.target.name}</option>)}</select></Field>
            <Field label="OWASP LLM vulnerability category"><select value={category} onChange={e => setCategory(e.target.value)}>{OWASP_CATEGORIES.map(x => <option key={x}>{x}</option>)}</select></Field>
          </div>
          <Field label="Attack turn type">
            <Segmented value={turnMode} onChange={setTurnMode} options={[["Single-turn", "Single-turn"], ["Multi-turn", "Multi-turn"]]} />
          </Field>
          <div className="auto-scenario-summary">
            <div>
              <strong>{selectedTurnScenarioCount}</strong>
              <span>{turnMode.toLowerCase()} attack scenario{selectedTurnScenarioCount === 1 ? "" : "s"} will run for this vulnerability type.</span>
            </div>
            <p className="scenario-count-breakdown">
              This category has {categoryTurnCounts.single_turn} single-turn and {categoryTurnCounts.multi_turn} multi-turn attack scenarios ({categoryTurnCounts.total} total).
            </p>
            {filteredScenarios.length ? (
              <ul>
                {filteredScenarios.map(s => (
                  <li key={s.id}>
                    {s.name}
                    <span>{turnMode === "Single-turn" ? s.turn_counts?.single_turn || 0 : s.turn_counts?.multi_turn || 0}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p>No {turnMode.toLowerCase()} scenarios are available for this vulnerability type.</p>
            )}
          </div>
          {selectedScenarioIds.includes("llm01.crescendo_attack") && (
            <Field label="Crescendo attack profile"><select value={profile} onChange={e => setProfile(e.target.value)}>{Object.entries(CRESCENDO_PROFILES).map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></Field>
          )}
          <div className="form-grid three-cols">
            {turnMode === "Multi-turn" && (
              <Field label="Max turns"><input type="number" min="1" max="25" value={settings.max_turns} onChange={e => setSettings({ ...settings, max_turns: Number(e.target.value) })} /></Field>
            )}
            <Field label="Timeout"><input type="number" min="1" max="300" value={settings.timeout_seconds} onChange={e => setSettings({ ...settings, timeout_seconds: Number(e.target.value) })} /></Field>
            <Field label="Concurrency"><input type="number" min="1" max="20" value={settings.concurrency} onChange={e => setSettings({ ...settings, concurrency: Number(e.target.value) })} /></Field>
            <Field label="Retry count"><input type="number" min="0" max="5" value={settings.retry_count} onChange={e => setSettings({ ...settings, retry_count: Number(e.target.value) })} /></Field>
            <Field label="Temperature"><input type="range" min="0" max="2" step="0.05" value={settings.temperature} onChange={e => setSettings({ ...settings, temperature: Number(e.target.value) })} /></Field>
          </div>
          <Progress value={running ? 55 : result ? 100 : 0} label={running ? "Current stage: scan_running" : result ? "Progress: 100%" : "Progress: 0%"} />
          <div className="action-row">
            <button className="primary-button" disabled={!scanName || !selectedTarget || running || !selectedScenarioIds.length} onClick={start}><Play size={16} />{running ? "Running..." : "Start scan"}</button>
          </div>
          {result && <div className="alert success">Scan finished with status {result.status}. Open Reports to review history, transcripts, and exports.</div>}
        </div>
      )}
    </section>
  );
}

function Reports({ reports }) {
  const [selectedName, setSelectedName] = useState(reports[0]?.filename || "");
  const selected = reports.find(item => item.filename === selectedName) || reports[0];
  useEffect(() => {
    if (!selectedName && reports[0]) setSelectedName(reports[0].filename);
  }, [reports, selectedName]);
  return (
    <section>
      <h1>Reports</h1>
      {!reports.length ? <EmptyText>No scan results found.</EmptyText> : (
        <>
          <Field label="Scan history"><select value={selected?.filename || ""} onChange={e => setSelectedName(e.target.value)}>{reports.map(({ filename, report }) => <option key={filename} value={filename}>{report.scan_name} | {report.target_name} | {formatDate(report.completed_at || report.started_at)}</option>)}</select></Field>
          <div className="kpi-grid three">
            <Kpi label="Target" value={selected.report.target_name || "-"} sublabel="assessment target" tone="blue" />
            <Kpi label="Status" value={selected.report.status || "-"} sublabel="scan state" tone={selected.report.status === "COMPLETED" ? "green" : "red"} />
            <Kpi label="Scenarios" value={(selected.report.scenario_results || []).length} sublabel="executed scenarios" tone="yellow" />
          </div>
          <div className="action-row">
            <DownloadButton filename={selected.filename} label="Export JSON" text={JSON.stringify(selected.report, null, 2)} type="application/json" />
            <DownloadButton filename={selected.filename.replace(".json", "-enterprise.md")} label="Export Enterprise MD" text={enterpriseMarkdown(selected.report)} type="text/markdown" />
          </div>
          <ScenarioResults report={selected.report} />
        </>
      )}
    </section>
  );
}

function ScenarioResults({ report }) {
  return (
    <div className="scenario-stack">
      {(report.scenario_results || []).map(scenario => (
        <details className="scenario-panel" key={scenario.scenario_id} open>
          <summary>{scenario.scenario_name || "Scenario"} - Vulnerability {scenarioPercent(scenario)}%</summary>
          <Progress value={scenarioPercent(scenario)} />
          <div className="scenario-meta">
            <div><b>Vulnerability type</b><code>{scenario.owasp_category}</code></div>
            <div><b>Why this percentage was assigned</b><p>{vulnerabilityReason(scenario)}</p></div>
            <div><b>Recommended remediation</b><p>{remediationText(scenario)}</p></div>
          </div>
          <JudgeLog scenario={scenario} />
          <ChatTranscript scenario={scenario} />
        </details>
      ))}
    </div>
  );
}

function JudgeLog({ scenario }) {
  const rows = (scenario.turns || []).filter(t => t.judge_decision);
  if (!rows.length) return null;
  return (
    <div>
      <h3>Judge agent strategy log</h3>
      {rows.map(turn => {
        const risk = Number(turn.judge_decision.risk_score || 0);
        const tone = risk >= 0.7 ? "red" : risk >= 0.4 ? "yellow" : "green";
        return <div className={`judge-row ${tone}`} key={turn.turn}><b>Turn {turn.turn}</b><code>{turn.judge_decision.next_action}</code><span>Risk {risk.toFixed(2)}</span><p>{turn.judge_decision.reasoning}</p></div>;
      })}
    </div>
  );
}

function ChatTranscript({ scenario }) {
  return (
    <div className="chat-transcript">
      {(scenario.turns || []).map(turn => (
        <React.Fragment key={turn.turn}>
          <div className="chat-row user"><div className="chat-bubble"><span>Prompt</span>{turn.prompt?.prompt}</div></div>
          <div className="chat-row assistant"><div className="chat-bubble"><span>Chatbot</span>{chatbotText(turn.response?.body || "")}</div></div>
        </React.Fragment>
      ))}
    </div>
  );
}

const TOOL_SCAN_TOOLS = [
  {
    id: "garak",
    name: "Garak",
    purpose: "Probe LLM applications with model and plugin based vulnerability checks.",
    command: "garak --target_type ollama --target_name llama3.2 --probe_tags owasp",
    status: "Ready for connector",
  },
  {
    id: "pyrit",
    name: "PyRIT",
    purpose: "Run prompt orchestration, scoring, and red-team attack workflows.",
    command: "pyrit scan --target target.json",
    status: "Ready for connector",
  },
  {
    id: "deepteam",
    name: "DeepTeam",
    purpose: "Evaluate adversarial prompts and model safety behavior across attack categories.",
    command: "deepteam run --target target.json",
    status: "Ready for connector",
  },
];

const GARAK_TARGET_TYPES = [
  "ollama",
  "openai",
  "azure",
  "groq",
  "huggingface",
  "rest",
  "websocket",
  "rasa",
  "bedrock",
  "cohere",
  "litellm",
  "mistral",
  "replicate",
  "watsonx",
  "nim",
  "nvcf",
  "ggml",
  "langchain",
  "langchain_serve",
];

const GARAK_PROBE_MODES = [
  ["owasp", "OWASP probes"],
  ["all", "All probes"],
  ["specific", "Specific probe"],
  ["tag", "Probe tag"],
];

const GARAK_COMMON_PROBES = [
  "lmrc.Profanity",
  "dan.DanInTheWild",
  "promptinject.HijackHateHumans",
  "encoding.InjectBase64",
  "malwaregen.TopLevel",
  "xss.MarkdownExfilBasic",
];

function ToolScan({ targets, setNotice }) {
  const [selectedTool, setSelectedTool] = useState("garak");
  const [connectors, setConnectors] = useState(TOOL_SCAN_TOOLS);
  const [selectedTarget, setSelectedTarget] = useState(targets[0]?.filename || "");
  const [profile, setProfile] = useState("standard");
  const [options, setOptions] = useState("");
  const [timeoutSeconds, setTimeoutSeconds] = useState(120);
  const [garakTargetType, setGarakTargetType] = useState("ollama");
  const [garakTargetName, setGarakTargetName] = useState("llama3.2");
  const [garakProbeMode, setGarakProbeMode] = useState("owasp");
  const [garakProbeValue, setGarakProbeValue] = useState("lmrc.Profanity");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [job, setJob] = useState(null);
  const [queue, setQueue] = useState(null);
  const tool = connectors.find(item => item.id === selectedTool) || connectors[0] || TOOL_SCAN_TOOLS[0];
  const isGarak = selectedTool === "garak";
  const isWorkerMode = tool.execution_mode === "worker_queue";
  const targetItem = targets.find(item => item.filename === selectedTarget) || targets[0];
  const target = targetItem?.target || emptyTarget;
  const garakTargetTypes = tool.target_types?.length ? tool.target_types : GARAK_TARGET_TYPES;
  const commandText = result?.command?.length ? result.command.join(" ") : isGarak ? garakCommandPreview({ garakTargetType, garakTargetName, garakProbeMode, garakProbeValue }) : (tool.command_template || tool.command);

  useEffect(() => {
    if (!selectedTarget && targets[0]?.filename) {
      setSelectedTarget(targets[0].filename);
    }
  }, [selectedTarget, targets]);

  useEffect(() => {
    let active = true;
    api("/tool-scans/tools")
      .then(data => {
        if (active) {
          setConnectors(data.tools || TOOL_SCAN_TOOLS);
          setQueue(data.queue || null);
        }
      })
      .catch(error => setNotice(error.message));
    return () => {
      active = false;
    };
  }, [setNotice]);

  const submit = async dryRun => {
    setRunning(true);
    setResult(null);
    setJob(null);
    try {
      const body = {
        tool_id: selectedTool,
        target: isGarak ? undefined : target,
        profile,
        options,
        timeout_seconds: Number(timeoutSeconds) || 120,
        dry_run: dryRun,
        garak_target_type: garakTargetType,
        garak_target_name: garakTargetName,
        garak_probe_mode: garakProbeMode,
        garak_probe_value: garakProbeValue,
      };
      const queued = await api("/tool-scans/submit", {
        method: "POST",
        body,
      });
      setJob(queued);
      setNotice(dryRun ? `${queued.tool_name} validation queued.` : `${queued.tool_name} scan queued.`);
      const finished = await pollToolScanJob(queued.job_id, setJob);
      if (finished.result) {
        setResult(finished.result);
        setNotice(dryRun ? `${finished.result.tool_name} command validated on worker.` : `${finished.result.tool_name} scan finished with status ${finished.result.status}.`);
      } else {
        setNotice(`${queued.tool_name} job finished with status ${finished.status}.`);
      }
    } catch (error) {
      setNotice(error.message);
    } finally {
      setRunning(false);
    }
  };

  return (
    <section>
      <h1>Tool scan</h1>
      <PageIntro title="External Tool Scan" subtitle="Run Garak CLI scans or saved-target scans for PyRIT and DeepTeam." chips={["Garak CLI", "PyRIT", "DeepTeam"]} />
      <div className="tool-scan-grid">
        {connectors.map(item => (
          <button key={item.id} className={selectedTool === item.id ? "tool-scan-card active" : "tool-scan-card"} onClick={() => setSelectedTool(item.id)} type="button">
            <span>{item.available ? "Available" : item.status || "Not installed"}</span>
            <strong>{item.name}</strong>
            <p>{item.purpose}</p>
          </button>
        ))}
      </div>

      <div className="form-panel">
        <div className="tool-scan-header">
          <div>
            <h2>{tool.name} scan setup</h2>
            <p className="muted">{tool.purpose}</p>
          </div>
          <span className={`status-pill ${tool.available ? "complete" : "failed"}`}>{tool.status || (tool.available ? "Connector ready" : "Tool missing")}</span>
        </div>
        {queue && (
          <div className="alert info">
            <RefreshCw size={18} />
            <span>Execution mode: {isWorkerMode ? "EC2 worker queue" : "local process"} via {queue.queue}.</span>
          </div>
        )}
        {!isGarak && !targets.length && <div className="alert info">Create or save a target before running this external tool scan. The form is showing the mock target as a placeholder.</div>}
        {isGarak ? (
          <>
            <div className="form-grid three-cols">
              <Field label="Model type">
                <select value={garakTargetType} onChange={event => setGarakTargetType(event.target.value)}>
                  {garakTargetTypes.map(item => <option key={item} value={item}>{titleCase(item)}</option>)}
                </select>
              </Field>
              <Field label="Model name"><input value={garakTargetName} onChange={event => setGarakTargetName(event.target.value)} placeholder="llama3.2, gpt-4.1, deployment name..." /></Field>
              <Field label="Probe type">
                <select value={garakProbeMode} onChange={event => {
                  const nextMode = event.target.value;
                  setGarakProbeMode(nextMode);
                  if (nextMode === "specific") setGarakProbeValue("lmrc.Profanity");
                  if (nextMode === "tag") setGarakProbeValue("owasp");
                }}>
                  {GARAK_PROBE_MODES.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
                </select>
              </Field>
            </div>
            {(garakProbeMode === "specific" || garakProbeMode === "tag") && (
              <Field label={garakProbeMode === "specific" ? "Probe" : "Probe tag"}>
                <input list={garakProbeMode === "specific" ? "garak-common-probes" : undefined} value={garakProbeValue} onChange={event => setGarakProbeValue(event.target.value)} placeholder={garakProbeMode === "specific" ? "lmrc.Profanity" : "owasp"} />
                <datalist id="garak-common-probes">
                  {GARAK_COMMON_PROBES.map(item => <option key={item} value={item} />)}
                </datalist>
              </Field>
            )}
          </>
        ) : (
          <div className="form-grid">
            <Field label="Target source">
              <select value={selectedTarget} onChange={event => setSelectedTarget(event.target.value)} disabled={!targets.length}>
                {targets.map(item => <option key={item.filename} value={item.filename}>{item.target.name}</option>)}
                {!targets.length && <option value="">Mock target placeholder</option>}
              </select>
            </Field>
            <Field label="Scan profile">
              <select value={profile} onChange={event => setProfile(event.target.value)}>
                {(tool.profiles || ["quick", "standard", "deep"]).map(item => <option key={item} value={item}>{titleCase(item)}</option>)}
              </select>
            </Field>
          </div>
        )}
        <div className="form-grid">
          <Field label="Timeout seconds"><input type="number" min="5" max="1800" value={timeoutSeconds} onChange={event => setTimeoutSeconds(event.target.value)} /></Field>
          <Field label="Execution target"><input readOnly value={isWorkerMode ? "EC2 Celery worker" : (tool.executable_path || tool.executable || "not found")} /></Field>
        </div>
        <Field label="Command template"><input readOnly value={commandText} /></Field>
        <Field label="Tool-specific options"><textarea rows={5} value={options} onChange={event => setOptions(event.target.value)} placeholder="Add CLI flags, plugin names, scorer settings, or dataset paths for this tool." /></Field>
        <div className="action-row">
          <button className="secondary-button" type="button" onClick={() => submit(true)} disabled={running}>Validate configuration</button>
          <button className="primary-button" type="button" onClick={() => submit(false)} disabled={running || (!isGarak && !targets.length) || (isGarak && !garakTargetName.trim())}><Play size={16} />{running ? "Queued..." : "Run tool scan"}</button>
        </div>
        {tool.install_hint && !tool.available && <p className="muted">{tool.install_hint}</p>}
        {job && (
          <div className="alert info">
            <RefreshCw size={18} />
            <span>Worker job {job.job_id} is {job.status}.</span>
          </div>
        )}
        {result && <ToolScanResult result={result} />}
      </div>
    </section>
  );
}

async function pollToolScanJob(jobId, onUpdate) {
  const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
  for (let attempt = 0; attempt < 600; attempt += 1) {
    const status = await api(`/tool-scans/jobs/${jobId}`);
    onUpdate(status);
    if (status.ready || status.result) return status;
    await wait(2000);
  }
  throw new Error("Tool scan job polling timed out.");
}

function ToolScanResult({ result }) {
  return (
    <div className="tool-scan-result">
      <div className="tool-scan-result-header">
        <strong>{result.tool_name} result</strong>
        <span className={`status-pill ${result.status === "COMPLETED" || result.status === "VALIDATED" ? "complete" : "failed"}`}>{result.status}</span>
      </div>
      {result.error && <div className="alert error"><AlertTriangle size={18} /><span>{result.error}</span></div>}
      {result.install_hint && <p className="muted">{result.install_hint}</p>}
      <Field label="Executed command"><input readOnly value={(result.command || []).join(" ")} /></Field>
      {!!result.report_paths?.length && (
        <Field label="Generated reports">
          <textarea readOnly rows={Math.min(6, result.report_paths.length + 1)} value={result.report_paths.join("\n")} />
        </Field>
      )}
      <div className="form-grid">
        <Field label="Return code"><input readOnly value={result.return_code ?? "-"} /></Field>
        <Field label="Scan ID"><input readOnly value={result.scan_id} /></Field>
      </div>
      {(result.stdout || result.stderr) && (
        <div className="form-grid">
          <Field label="stdout"><textarea readOnly rows={8} value={result.stdout || ""} /></Field>
          <Field label="stderr"><textarea readOnly rows={8} value={result.stderr || ""} /></Field>
        </div>
      )}
    </div>
  );
}

function garakCommandPreview({ garakTargetType, garakTargetName, garakProbeMode, garakProbeValue }) {
  const command = ["garak", "--target_type", garakTargetType, "--target_name", garakTargetName || "<model_name>"];
  if (garakProbeMode === "all") {
    command.push("--probes", "all");
  } else if (garakProbeMode === "specific") {
    command.push("--probes", garakProbeValue || "<probe>");
  } else if (garakProbeMode === "tag") {
    command.push("--probe_tags", garakProbeValue || "<probe_tag>");
  } else {
    command.push("--probe_tags", "owasp");
  }
  command.push("--report_prefix", "reports/tool-scans/garak-<scan_id>");
  return command.join(" ");
}

const LLM_PROVIDER_OPTIONS = [
  ["azure_openai", "Azure OpenAI"],
  ["openai", "OpenAI"],
  ["aws_bedrock", "AWS Bedrock"],
  ["ollama", "Ollama Localhost"],
  ["huggingface", "Hugging Face"],
  ["anthropic", "Anthropic"],
];

function Configurations({ settings, setSettings, setNotice }) {
  const [form, setForm] = useState(settingsToForm(settings));
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setForm(settingsToForm(settings));
  }, [settings]);

  const update = patch => setForm(current => ({ ...current, ...patch }));

  const save = async () => {
    setSaving(true);
    try {
      const payload = {
        ...form,
        azure_openai_api_key: form.azure_openai_api_key || undefined,
        openai_api_key: form.openai_api_key || undefined,
        anthropic_api_key: form.anthropic_api_key || undefined,
        huggingface_api_key: form.huggingface_api_key || undefined,
      };
      const updated = await api("/settings/runtime", { method: "PUT", body: payload });
      setSettings(updated);
      setNotice(`LLM provider updated to ${providerLabel(updated.llm_provider)}.`);
    } catch (error) {
      setNotice(error.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <section>
      <h1>Configurations</h1>
      <PageIntro title="Platform Configuration" subtitle="Select the model provider used by the judge, detectors, and target assistant." chips={["Providers", "Models", "Runtime"]} />
      {settings ? (
        <div className="form-panel">
          <div className="form-grid">
            <Field label="LLM provider">
              <select value={form.llm_provider} onChange={event => update({ llm_provider: event.target.value })}>
                {LLM_PROVIDER_OPTIONS.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
              </select>
            </Field>
            <Field label="Provider status"><input readOnly value={settings.llm_ready ? "Configured" : "Missing required configuration"} /></Field>
          </div>

          {form.llm_provider === "azure_openai" && (
            <>
              <Field label="Azure OpenAI endpoint"><input value={form.azure_openai_endpoint} onChange={e => update({ azure_openai_endpoint: e.target.value })} placeholder="https://resource.openai.azure.com" /></Field>
              <Field label="Azure OpenAI API key"><input type="password" value={form.azure_openai_api_key} onChange={e => update({ azure_openai_api_key: e.target.value })} placeholder={settings.azure_ready ? "***configured***" : "AZURE_OPENAI_API_KEY"} /></Field>
              <div className="form-grid">
                <Field label="Deployment name"><input value={form.azure_openai_deployment} onChange={e => update({ azure_openai_deployment: e.target.value })} /></Field>
                <Field label="API version"><input value={form.azure_openai_api_version} onChange={e => update({ azure_openai_api_version: e.target.value })} /></Field>
              </div>
            </>
          )}

          {form.llm_provider === "openai" && (
            <>
              <Field label="OpenAI API key"><input type="password" value={form.openai_api_key} onChange={e => update({ openai_api_key: e.target.value })} placeholder={settings.openai_ready ? "***configured***" : "OPENAI_API_KEY"} /></Field>
              <div className="form-grid">
                <Field label="Model"><input value={form.openai_model} onChange={e => update({ openai_model: e.target.value })} placeholder="gpt-4o-mini" /></Field>
                <Field label="Base URL"><input value={form.openai_base_url} onChange={e => update({ openai_base_url: e.target.value })} /></Field>
              </div>
            </>
          )}

          {form.llm_provider === "aws_bedrock" && (
            <div className="form-grid">
              <Field label="AWS region"><input value={form.aws_region} onChange={e => update({ aws_region: e.target.value })} placeholder="us-east-1" /></Field>
              <Field label="Bedrock model ID"><input value={form.aws_bedrock_model_id} onChange={e => update({ aws_bedrock_model_id: e.target.value })} placeholder="anthropic.claude-3-haiku-20240307-v1:0" /></Field>
            </div>
          )}

          {form.llm_provider === "ollama" && (
            <div className="form-grid">
              <Field label="Ollama base URL"><input value={form.ollama_base_url} onChange={e => update({ ollama_base_url: e.target.value })} placeholder="http://localhost:11434" /></Field>
              <Field label="Model"><input value={form.ollama_model} onChange={e => update({ ollama_model: e.target.value })} placeholder="llama3.1" /></Field>
            </div>
          )}

          {form.llm_provider === "huggingface" && (
            <>
              <Field label="Hugging Face API key"><input type="password" value={form.huggingface_api_key} onChange={e => update({ huggingface_api_key: e.target.value })} placeholder={settings.huggingface_ready ? "***configured***" : "HUGGINGFACE_API_KEY"} /></Field>
              <div className="form-grid">
                <Field label="Model"><input value={form.huggingface_model} onChange={e => update({ huggingface_model: e.target.value })} placeholder="mistralai/Mistral-7B-Instruct-v0.3" /></Field>
                <Field label="Base URL"><input value={form.huggingface_base_url} onChange={e => update({ huggingface_base_url: e.target.value })} /></Field>
              </div>
            </>
          )}

          {form.llm_provider === "anthropic" && (
            <>
              <Field label="Anthropic API key"><input type="password" value={form.anthropic_api_key} onChange={e => update({ anthropic_api_key: e.target.value })} placeholder={settings.anthropic_ready ? "***configured***" : "ANTHROPIC_API_KEY"} /></Field>
              <div className="form-grid">
                <Field label="Model"><input value={form.anthropic_model} onChange={e => update({ anthropic_model: e.target.value })} placeholder="claude-3-5-sonnet-latest" /></Field>
                <Field label="Base URL"><input value={form.anthropic_base_url} onChange={e => update({ anthropic_base_url: e.target.value })} /></Field>
              </div>
            </>
          )}

          <div className="form-grid">
            <Field label="Default temperature"><input readOnly value={settings.default_temperature} /></Field>
            <Field label="Logging level"><input readOnly value={settings.log_level} /></Field>
            <Field label="Retry configuration"><input readOnly value={settings.default_retry_count} /></Field>
          </div>
          <div className="action-row">
            <button className="primary-button" type="button" onClick={save} disabled={saving}><Save size={16} />{saving ? "Saving..." : "Save provider configuration"}</button>
          </div>
          <p className="muted">Changes apply to this running backend process immediately. Add the same values to .env if you want them restored after restart. API keys are never displayed back to the browser.</p>
        </div>
      ) : <EmptyText>Configuration could not be loaded.</EmptyText>}
    </section>
  );
}

function settingsToForm(settings) {
  return {
    llm_provider: settings?.llm_provider || "azure_openai",
    azure_openai_endpoint: settings?.azure_openai_endpoint || "",
    azure_openai_api_key: "",
    azure_openai_deployment: settings?.azure_openai_deployment || "",
    azure_openai_api_version: settings?.azure_openai_api_version || "2024-12-01-preview",
    openai_api_key: "",
    openai_model: settings?.openai_model || "gpt-4o-mini",
    openai_base_url: settings?.openai_base_url || "https://api.openai.com/v1",
    anthropic_api_key: "",
    anthropic_model: settings?.anthropic_model || "claude-3-5-sonnet-latest",
    anthropic_base_url: settings?.anthropic_base_url || "https://api.anthropic.com/v1",
    huggingface_api_key: "",
    huggingface_model: settings?.huggingface_model || "mistralai/Mistral-7B-Instruct-v0.3",
    huggingface_base_url: settings?.huggingface_base_url || "https://api-inference.huggingface.co/models",
    ollama_model: settings?.ollama_model || "llama3.1",
    ollama_base_url: settings?.ollama_base_url || "http://localhost:11434",
    aws_region: settings?.aws_region || "us-east-1",
    aws_bedrock_model_id: settings?.aws_bedrock_model_id || "anthropic.claude-3-haiku-20240307-v1:0",
  };
}

function providerLabel(provider) {
  return LLM_PROVIDER_OPTIONS.find(([id]) => id === provider)?.[1] || provider;
}

function titleCase(value) {
  return String(value || "").replace(/[_-]+/g, " ").replace(/\b\w/g, char => char.toUpperCase());
}

function PageIntro({ title, subtitle, chips }) {
  return <><div className="page-hero"><h3>{title}</h3><p>{subtitle}</p></div><div className="accent-strip">{chips.map(chip => <span className="accent-pill" key={chip}>{chip}</span>)}</div></>;
}

function Panel({ title, children }) {
  return <div className="panel"><h2>{title}</h2>{children}</div>;
}

function Field({ label, children }) {
  return <label className="field"><span>{label}</span>{children}</label>;
}

function Segmented({ value, onChange, options }) {
  return <div className="segmented">{options.map(([id, label]) => <button key={id} className={value === id ? "active" : ""} onClick={() => onChange(id)} type="button">{label}</button>)}</div>;
}

function Progress({ value, label }) {
  return <div className="progress-wrap">{label && <div className="progress-label">{label}</div>}<div className="progress"><span style={{ width: `${Math.min(100, Math.max(0, value))}%` }} /></div></div>;
}

function JsonBlock({ value }) {
  return <pre className="json-block">{JSON.stringify(value, null, 2)}</pre>;
}

function EmptyText({ children }) {
  return <div className="empty-text">{children}</div>;
}

function DownloadButton({ filename, label, text, type }) {
  const href = useMemo(() => URL.createObjectURL(new Blob([text], { type })), [text, type]);
  return <a className="secondary-button" href={href} download={filename}><Download size={16} />{label}</a>;
}

function ActivityRow({ report }) {
  const status = String(report.status || "").toUpperCase();
  const tone = status === "COMPLETED" ? "green" : status === "FAILED" ? "red" : "yellow";
  return <div className="activity-row"><span className={`dot ${tone}`} /><div><b>{report.scan_name}</b><small>{report.target_name} · {formatDate(report.completed_at || report.started_at)}</small></div><strong>{simulationPercent(report)}%</strong></div>;
}

function CoverageBar({ category, hits, max }) {
  const pct = Math.round((hits / max) * 100);
  return <div className="coverage-row"><div><b>{category.split("-")[0]}</b><span>{hits} scan{hits === 1 ? "" : "s"}</span></div><div className="coverage-track"><span style={{ width: `${pct}%` }} /></div></div>;
}

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: options.method || "GET",
    headers: { "Content-Type": "application/json" },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  if (!response.ok) {
    const text = await response.text();
    let message = text;
    try {
      const parsed = JSON.parse(text);
      if (Array.isArray(parsed.detail)) {
        message = parsed.detail.map(item => `${item.loc?.slice(1).join(".") || "field"}: ${item.msg}`).join("; ");
      } else if (parsed.detail) {
        message = String(parsed.detail);
      }
    } catch {
      // Fall back to the raw response text.
    }
    throw new Error(message || `Request failed: ${response.status}`);
  }
  return response.json();
}

function buildTargetTemplate({ deliveryMode, deliveryType, authType }) {
  const delivery = deliveryTemplate(deliveryMode, deliveryType);
  const auth = authTemplate(authType);
  const streaming = delivery.delivery.mode === "streaming";
  const headers = {
    "Content-Type": "application/json",
    ...(delivery.headers || {}),
    ...headersFromAuth(auth.auth),
  };
  const requestTemplate = {
    message: "{{prompt}}",
    conversation_id: "{{conversation_id}}",
    ...(delivery.request_overrides || {}),
  };
  const target = {
    name: "Internal HR Chatbot",
    url: "mock://internal-hr-chatbot",
    method: "POST",
    headers,
    request_template: requestTemplate,
    auth: scannerAuthFromTemplate(auth.auth, delivery, headers, requestTemplate),
    timeout_seconds: delivery.timeout_seconds,
  };
  target.auth.template_preview = {
    delivery_template: delivery,
    auth_template: auth,
    combination: `BASE_TARGET + Delivery Template (${delivery.delivery.mode}.${delivery.delivery.type}) + Auth Template (${auth.auth.type})`,
  };
  return target;
}

function deliveryTemplate(deliveryMode, deliveryType) {
  const streamingTemplates = {
    token: {
      delivery: { mode: "streaming", type: "token" },
      headers: { Accept: "text/event-stream" },
      request_overrides: { stream: true },
      timeout_seconds: 0,
    },
    chunk: {
      delivery: { mode: "streaming", type: "chunk" },
      headers: { Accept: "text/event-stream" },
      request_overrides: { stream: true, chunk_type: "paragraph" },
      timeout_seconds: 0,
    },
    event: {
      delivery: { mode: "streaming", type: "event" },
      headers: { Accept: "text/event-stream" },
      request_overrides: { stream: true, emit_events: true },
      timeout_seconds: 0,
    },
    sse: {
      delivery: { mode: "streaming", type: "sse" },
      headers: { Accept: "text/event-stream" },
      request_overrides: { stream: true },
      timeout_seconds: 0,
    },
    websocket: {
      delivery: { mode: "streaming", type: "websocket" },
      transport: { protocol: "ws" },
      timeout_seconds: 0,
    },
  };
  const nonStreamingTemplates = {
    synchronous: { delivery: { mode: "non-streaming", type: "synchronous" }, timeout_seconds: 120 },
    retrieval: { delivery: { mode: "non-streaming", type: "retrieval" }, timeout_seconds: 30 },
    generative: { delivery: { mode: "non-streaming", type: "generative" }, timeout_seconds: 120 },
    batch: { delivery: { mode: "non-streaming", type: "batch" }, timeout_seconds: 300 },
    workflow: { delivery: { mode: "non-streaming", type: "workflow" }, timeout_seconds: 180 },
  };
  return deliveryMode === "streaming" ? streamingTemplates[deliveryType] || streamingTemplates.token : nonStreamingTemplates[deliveryType] || nonStreamingTemplates.synchronous;
}

function authTemplate(authType) {
  const templates = {
    none: { auth: { type: "none" } },
    bearer_token_from_env: { auth: { type: "bearer_token_from_env", env_variable: "API_TOKEN" } },
    bearer_token_in_header: { auth: { type: "bearer_token_in_header", header_name: "Authorization", format: "Bearer {{token}}" } },
    api_key_header: { auth: { type: "api_key_header", header_name: "X-API-Key", env_variable: "API_KEY" } },
    basic_auth: { auth: { type: "basic_auth", username_env: "BASIC_USER", password_env: "BASIC_PASS" } },
    oauth2: {
      auth: {
        type: "oauth2_client_credentials",
        token_url: "https://example.com/oauth/token",
        client_id_env: "CLIENT_ID",
        client_secret_env: "CLIENT_SECRET",
        scope: "default",
      },
    },
    jwt: { auth: { type: "jwt_token_auth", jwt_env: "JWT_TOKEN" } },
  };
  return templates[authType] || templates.none;
}

function headersFromAuth(auth) {
  if (auth.type === "bearer_token_in_header") return { [auth.header_name]: auth.format };
  if (auth.type === "api_key_header") return { [auth.header_name]: `{{${auth.env_variable}}}` };
  if (auth.type === "jwt_token_auth") return { Authorization: `Bearer {{${auth.jwt_env}}}` };
  if (auth.type === "basic_auth") return { Authorization: "Basic {{BASIC_AUTH_BASE64}}" };
  return {};
}

function scannerAuthFromTemplate(auth, delivery, headers, requestTemplate) {
  const scannerAuth = {
    type: "none",
    template_type: auth.type,
    template: { auth },
    target_delivery: delivery.delivery,
  };
  if (auth.type === "bearer_token_from_env") {
    scannerAuth.type = "bearer";
    scannerAuth.token_env = auth.env_variable;
  }
  if (auth.type === "oauth2_client_credentials") {
    scannerAuth.type = "session";
    scannerAuth.workflow = {
      credential_authentication: {
        enabled: true,
        method: "POST",
        url: auth.token_url,
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body_encoding: "form",
        body: {
          grant_type: "client_credentials",
          client_id: `{{${auth.client_id_env}}}`,
          client_secret: `{{${auth.client_secret_env}}}`,
          scope: auth.scope,
        },
        access_token_path: "access_token",
      },
      next_turn: workflowNextTurn(delivery, { ...headers, Authorization: "Bearer {{access_token}}" }, requestTemplate),
    };
  }
  return scannerAuth;
}

function workflowNextTurn(delivery, headers, requestTemplate) {
  const isStreaming = delivery.delivery.mode === "streaming";
  return {
    enabled: true,
    method: "POST",
    url: "https://api.example.com/chat",
    headers,
    body: requestTemplate,
    response_message_path: isStreaming ? "delta.content" : "response",
    ...(isStreaming
      ? {
          streaming: {
            enabled: true,
            response_message_path: "delta.content",
            stop_conditions: delivery.delivery.type === "token" || delivery.delivery.type === "sse" ? [{ value: "[DONE]" }] : [{ path: "done", value: "true" }],
          },
        }
      : {}),
  };
}

function normalizeTarget(value) {
  return {
    name: String(value.name || "Internal HR Chatbot"),
    url: String(value.url || "mock://internal-hr-chatbot"),
    method: String(value.method || "POST").toUpperCase(),
    headers: value.headers && typeof value.headers === "object" ? value.headers : { "Content-Type": "application/json" },
    request_template: value.request_template && typeof value.request_template === "object" ? value.request_template : { message: "{{prompt}}" },
    auth: value.auth && typeof value.auth === "object" ? value.auth : { type: "none" },
    timeout_seconds: value.timeout_seconds ?? null,
  };
}

function assistantOpeningMessage(deliveryMode, deliveryType, authType) {
  const modeLabel = deliveryMode === "streaming" ? `streaming ${deliveryType}` : `non-streaming ${deliveryType}`;
  const authLabel = AUTH_OPTIONS.find(([id]) => id === authType)?.[1] || authType;
  return `Let us create your target JSON step by step. I will use ${modeLabel} delivery and ${authLabel}. What is the application or target name?`;
}

function assistantSteps(authType) {
  const steps = [
    { id: "name", question: "What is the chatbot endpoint URL? Include the full path, for example http://host:8001/chat." },
    { id: "url", question: "Which HTTP method should the scanner use? Most chatbot APIs use POST." },
    { id: "method", question: "What request body should send the attack prompt? You can answer with a field name like message, or a JSON body using {{prompt}}." },
    { id: "request", question: "Any extra headers besides the selected template headers? Reply none or paste a JSON object." },
    { id: "headers", question: authQuestion(authType) },
    { id: "auth", question: "What timeout in seconds should the scanner use? For streaming you can say 0; otherwise 30, 60, or 120 are common." },
    { id: "timeout", question: "I have enough details. Say generate final JSON, or tell me anything else to adjust first." },
  ];
  return authType === "none" ? steps.filter(step => step.id !== "auth") : steps;
}

function authQuestion(authType) {
  if (authType === "bearer_token_from_env") return "What environment variable stores the bearer token? For example API_TOKEN.";
  if (authType === "bearer_token_in_header") return "What Authorization header format should be used? For example Bearer {{token}}.";
  if (authType === "api_key_header") return "What API key header name and environment variable should be used? For example X-API-Key from API_KEY.";
  if (authType === "basic_auth") return "What environment variables store the basic auth username and password? For example BASIC_USER and BASIC_PASS.";
  if (authType === "oauth2") return "What OAuth token URL, client ID env, client secret env, and scope should be used?";
  if (authType === "jwt") return "What environment variable stores the JWT token? For example JWT_TOKEN.";
  return "What authentication details should be used?";
}

function nextAssistantStep(answers, authType) {
  return assistantSteps(authType).find(step => !(step.id in answers));
}

function nextAssistantQuestion(answers, authType) {
  return nextAssistantStep(answers, authType)?.question || "";
}

function inferTargetFromAssistantAnswers(answers, current, selection) {
  const next = normalizeTarget({
    ...buildTargetTemplate(selection),
    ...current,
    headers: { ...(current.headers || {}) },
    request_template: { ...(current.request_template || {}) },
    auth: { ...(current.auth || {}) },
  });
  if (answers.name) next.name = cleanSentence(answers.name, next.name);
  if (answers.url) next.url = extractUrl(answers.url) || answers.url.trim();
  if (answers.method) next.method = extractMethod(answers.method);
  if (answers.request) next.request_template = parseRequestTemplateAnswer(answers.request);
  if (answers.headers) next.headers = { ...(next.headers || {}), ...parseHeadersAnswer(answers.headers) };
  if (answers.timeout) next.timeout_seconds = parseTimeoutAnswer(answers.timeout, next.timeout_seconds);
  if (answers.auth) next.auth = applyAuthAnswer(selection.authType, next.auth, answers.auth);
  return normalizeTarget(next);
}

function extractUrl(text) {
  return text.match(/https?:\/\/[^\s"'<>]+|wss?:\/\/[^\s"'<>]+|mock:\/\/[^\s"'<>]+/)?.[0]?.replace(/[),.;]+$/, "") || "";
}

function extractMethod(text) {
  return text.match(/\b(GET|POST|PUT|PATCH|DELETE)\b/i)?.[1]?.toUpperCase() || "POST";
}

function cleanSentence(text, fallback) {
  const value = text.replace(/^(name|application|app|target)\s*(is|:)?\s*/i, "").trim().replace(/^["']|["']$/g, "");
  return value || fallback;
}

function parseRequestTemplateAnswer(text) {
  const trimmed = text.trim();
  const json = parseJsonObject(trimmed);
  if (json) return ensurePromptPlaceholder(json);
  const key = trimmed.match(/[a-zA-Z_][\w.-]*/)?.[0] || "message";
  return { [key]: "{{prompt}}" };
}

function ensurePromptPlaceholder(value) {
  const text = JSON.stringify(value);
  if (text.includes("{{prompt}}")) return value;
  return { ...value, message: "{{prompt}}" };
}

function parseHeadersAnswer(text) {
  if (/^(none|no|nothing|n\/a)$/i.test(text.trim())) return {};
  return parseJsonObject(text) || {};
}

function parseJsonObject(text) {
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function parseTimeoutAnswer(text, fallback) {
  const value = Number(text.match(/\d+/)?.[0]);
  return Number.isFinite(value) ? value : fallback;
}

function applyAuthAnswer(authType, auth, text) {
  const next = { ...(auth || {}) };
  const envNames = text.match(/\b[A-Z][A-Z0-9_]{2,}\b/g) || [];
  if (authType === "bearer_token_from_env") {
    next.type = "bearer";
    next.token_env = envNames[0] || next.token_env || "API_TOKEN";
  }
  if (authType === "bearer_token_in_header") {
    next.type = "bearer";
    next.header_name = text.match(/\bAuthorization\b/i)?.[0] || next.header_name || "Authorization";
    next.format = text.includes("{{token}}") ? text.trim() : next.format || "Bearer {{token}}";
  }
  if (authType === "api_key_header") {
    next.type = "api_key";
    next.header_name = text.match(/\b[A-Za-z][A-Za-z0-9-]*-Key\b/)?.[0] || next.header_name || "X-API-Key";
    next.env_variable = envNames[0] || next.env_variable || "API_KEY";
  }
  if (authType === "basic_auth") {
    next.type = "basic";
    next.username_env = envNames[0] || next.username_env || "BASIC_USER";
    next.password_env = envNames[1] || next.password_env || "BASIC_PASS";
  }
  if (authType === "jwt") {
    next.type = "bearer";
    next.token_env = envNames[0] || next.token_env || "JWT_TOKEN";
  }
  if (authType === "oauth2") {
    const url = extractUrl(text);
    next.type = "session";
    next.workflow = next.workflow || {};
    next.workflow.credential_authentication = {
      ...(next.workflow.credential_authentication || {}),
      url: url || next.workflow.credential_authentication?.url || "https://example.com/oauth/token",
      body: {
        ...(next.workflow.credential_authentication?.body || {}),
        client_id: `{{${envNames[0] || "CLIENT_ID"}}}`,
        client_secret: `{{${envNames[1] || "CLIENT_SECRET"}}}`,
      },
    };
  }
  return next;
}

function inferTargetFromPrompt(text, current, selection) {
  const url = text.match(/https?:\/\/[^\s"'<>]+|mock:\/\/[^\s"'<>]+/)?.[0]?.replace(/[),.;]+$/, "");
  const nameMatch = text.match(/(?:name|application|app|target)\s*(?:is|:)\s*["']?([^"',.]+)["']?/i);
  const next = {
    ...buildTargetTemplate(selection),
    ...current,
    headers: { ...(current.headers || {}) },
    request_template: { ...(current.request_template || {}) },
    auth: { ...(current.auth || {}) },
  };
  if (url) next.url = url;
  if (nameMatch?.[1]) next.name = nameMatch[1].trim();
  if (/\/chat\b/i.test(text) && !url && current.url && !current.url.endsWith("/chat") && !current.url.startsWith("mock://")) {
    next.url = `${current.url.replace(/\/$/, "")}/chat`;
  }
  return normalizeTarget(next);
}

function toggle(setter, value) {
  setter(current => current.includes(value) ? current.filter(item => item !== value) : [...current, value]);
}

function scenarioPercent(scenario) {
  const results = scenario.detector_results || [];
  if (!results.length) return 0;
  const top = Math.max(...results.map(item => item.vulnerable ? Number(item.confidence || 0) : 0));
  return Math.round(top * 100);
}

function scenarioMatchesTurnMode(scenario, turnMode) {
  if (turnMode === "Single-turn") {
    return scenario.type === "single_turn" || scenario.id === "llm01.prompt_injection";
  }
  if (scenario.id === "llm01.prompt_injection") return false;
  return scenario.type === "multi_turn";
}

function simulationPercent(report) {
  const scenarios = report.scenario_results || [];
  if (!scenarios.length) return 0;
  return Math.round(scenarios.reduce((sum, item) => sum + scenarioPercent(item), 0) / scenarios.length);
}

function vulnerabilityReason(scenario) {
  const vulnerable = (scenario.detector_results || []).filter(item => item.vulnerable);
  return vulnerable[0]?.reason || "No successful vulnerability behavior was detected in the observed transcript.";
}

function remediationText(scenario) {
  const high = (scenario.detector_results || []).some(item => item.vulnerable);
  return high ? "Strengthen instruction hierarchy enforcement, add output filtering, and add this transcript to regression tests." : "Continue monitoring with periodic adversarial regression scans.";
}

function chatbotText(body) {
  try {
    const parsed = JSON.parse(body);
    return parsed.response || parsed.text || body;
  } catch {
    return body;
  }
}

function enterpriseMarkdown(report) {
  return report.enterprise_report_markdown || `# Enterprise AI Red Teaming Report\n\n${JSON.stringify(report.enterprise_report || report, null, 2)}`;
}

function coverageRows(reports) {
  const counts = {};
  for (const { report } of reports) {
    for (const scenario of report.scenario_results || []) counts[scenario.owasp_category] = (counts[scenario.owasp_category] || 0) + 1;
  }
  const rows = Object.entries(counts).map(([category, hits]) => ({ category, hits }));
  const max = Math.max(1, ...rows.map(row => row.hits));
  return rows.sort((a, b) => b.hits - a.hits).slice(0, 6).map(row => ({ ...row, max }));
}

function firstCategory(report) {
  return (report?.scenario_results || []).map(s => s.owasp_category).find(Boolean);
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

createRoot(document.getElementById("root")).render(<App />);
