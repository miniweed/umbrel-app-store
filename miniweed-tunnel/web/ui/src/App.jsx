import { useEffect, useMemo, useState } from 'preact/hooks';
import {
  getConfig,
  getKillSwitchScript,
  getStatus,
  getVpsSetupScript,
  keygen,
  refreshHealth,
  rotateConfirm,
  rotatePrepare,
  saveConfig
} from './api.js';

const TAB_ITEMS = [
  { key: 'dashboard', label: 'Dashboard' },
  { key: 'services', label: 'Services' },
  { key: 'config', label: 'Configuration' },
  { key: 'vps', label: 'VPS Setup' },
  { key: 'advanced', label: 'Advanced' }
];

const EMPTY_SERVICE = { name: '', subdomain: '', target: '', enabled: true };

function serviceKey(svc) {
  const subdomain = (svc?.subdomain || '').trim().toLowerCase() || '@root';
  const target = (svc?.target || '').trim().toLowerCase();
  return `${subdomain}|${target}`;
}

function formatHealth(health) {
  if (!health || !health.checked) return { cls: '', text: 'Not checked' };
  if (health.ok) return { cls: 'ok', text: 'Connected' };
  return { cls: 'error', text: 'No connection' };
}

function initialState() {
  return {
    publicKey: '',
    vpsIp: '',
    vpsPort: 51820,
    vpsPubKey: '',
    vpsPubKeyFingerprint: '',
    domain: '',
    acmeEmail: '',
    services: [],
    serviceHealth: {}
  };
}

function normalizeConfig(cfg) {
  const out = { ...(cfg || {}) };
  out.services = Array.isArray(out.services) ? out.services : [];
  out.serviceHealth = out.serviceHealth && typeof out.serviceHealth === 'object' ? out.serviceHealth : {};
  return out;
}

export function App() {
  const [tab, setTab] = useState('dashboard');
  const [cfg, setCfg] = useState(initialState());
  const [status, setStatus] = useState({ connected: false, raw: 'Loading...' });
  const [message, setMessage] = useState({ text: '', kind: '' });
  const [loading, setLoading] = useState(false);
  const [vpsScriptWithCrowdsec, setVpsScriptWithCrowdsec] = useState(false);
  const [scriptMeta, setScriptMeta] = useState(null);
  const [scriptReloadMsg, setScriptReloadMsg] = useState('');
  const [scriptCopied, setScriptCopied] = useState(false);
  const [healthBusy, setHealthBusy] = useState(false);
  const [rotation, setRotation] = useState(null);
  const [rotationBusy, setRotationBusy] = useState(false);
  const [killSwitch, setKillSwitch] = useState(null);
  const [killSwitchBusy, setKillSwitchBusy] = useState(false);

  const setupIncomplete = !cfg.publicKey || !cfg.vpsPubKey || !cfg.vpsIp;
  const scriptMissingPublicKey = !cfg.publicKey;
  const scriptMissingVpsIp = !(cfg.vpsIp || '').trim();
  const scriptPrereqMissing = scriptMissingPublicKey || scriptMissingVpsIp;
  const saveSuccessMsg = message.kind === 'success' && message.text.includes('Saved.') ? message.text : '';

  async function refreshStatusOnly() {
    try {
      const data = await getStatus();
      setStatus(data || { connected: false, raw: 'No information' });
    } catch {
      setStatus({ connected: false, raw: 'Error fetching status' });
    }
  }

  async function refreshConfigOnly() {
    const loaded = normalizeConfig(await getConfig());
    setCfg(loaded);
  }

  async function refreshAll() {
    try {
      setLoading(true);
      await Promise.all([refreshConfigOnly(), refreshStatusOnly()]);
      setMessage({ text: '', kind: '' });
    } catch (err) {
      setMessage({ text: err.message || 'Could not load configuration.', kind: 'error' });
    } finally {
      setLoading(false);
    }
  }

  async function loadVpsScript(source = 'auto') {
    try {
      const data = await getVpsSetupScript({ withCrowdsec: vpsScriptWithCrowdsec });
      setScriptMeta(data);
      if (source === 'manual' && vpsScriptWithCrowdsec) setScriptReloadMsg('Script reloaded with CrowdSec');
      else setScriptReloadMsg('');
      setScriptCopied(false);
    } catch {
      setScriptMeta(null);
      setScriptReloadMsg('');
      setScriptCopied(false);
    }
  }

  async function onRefreshHealth() {
    setHealthBusy(true);
    setMessage({ text: '', kind: '' });
    try {
      await refreshHealth();
      await refreshConfigOnly();
      setMessage({ text: 'Service status updated.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'Could not refresh status.', kind: 'error' });
    } finally {
      setHealthBusy(false);
    }
  }

  async function onRotatePrepare() {
    if (!window.confirm(
      'New keys and a VPS script will be generated. The tunnel does NOT change until ' +
      'you run the script on the VPS and confirm here. Continue?'
    )) return;
    setRotationBusy(true);
    setMessage({ text: '', kind: '' });
    try {
      const plan = await rotatePrepare();
      setRotation(plan);
      setMessage({ text: 'Rotation plan created. Run the script on the VPS and confirm.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'Could not prepare the rotation.', kind: 'error' });
    } finally {
      setRotationBusy(false);
    }
  }

  async function onRotateConfirm(apply) {
    if (!rotation?.planId) return;
    if (apply && !window.confirm('Apply the new keys? Only confirm if you already ran the script on the VPS.')) return;
    setRotationBusy(true);
    setMessage({ text: '', kind: '' });
    try {
      await rotateConfirm(rotation.planId, apply);
      setRotation(null);
      if (apply) await refreshConfigOnly();
      setMessage({ text: apply ? 'Keys rotated successfully.' : 'Rotation cancelled.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'Could not complete the rotation.', kind: 'error' });
    } finally {
      setRotationBusy(false);
    }
  }

  async function onLoadKillSwitch() {
    setKillSwitchBusy(true);
    setMessage({ text: '', kind: '' });
    try {
      setKillSwitch(await getKillSwitchScript());
    } catch (err) {
      setMessage({ text: err.message || 'Could not generate the kill-switch.', kind: 'error' });
    } finally {
      setKillSwitchBusy(false);
    }
  }

  function downloadText(filename, text) {
    const blob = new Blob([`${text}\n`], { type: 'text/x-shellscript;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  useEffect(() => {
    refreshAll();
    const timer = setInterval(refreshStatusOnly, 8000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (tab === 'vps') loadVpsScript();
  }, [tab, vpsScriptWithCrowdsec]);

  const statusBadge = useMemo(() => {
    if (status.connected) return { cls: 'connected', text: 'Connected' };
    if ((status.peerCount || 0) > 0) return { cls: 'waiting', text: 'Connecting...' };
    return { cls: 'disconnected', text: 'No tunnel' };
  }, [status]);

  function setField(field, value) {
    setCfg(current => ({ ...current, [field]: value }));
  }

  function setService(index, field, value) {
    setCfg(current => {
      const services = [...current.services];
      const item = { ...(services[index] || EMPTY_SERVICE), [field]: value };
      services[index] = item;
      return { ...current, services };
    });
  }

  function addServiceRow() {
    setCfg(current => ({ ...current, services: [...current.services, { ...EMPTY_SERVICE }] }));
  }

  function removeServiceRow(index) {
    const svc = (cfg.services || [])[index];
    const name = svc?.name || svc?.subdomain || svc?.target || 'this service';
    if (!window.confirm(`Delete ${name}? Save to apply the change.`)) return;
    setCfg(current => ({
      ...current,
      services: current.services.filter((_, i) => i !== index)
    }));
  }

  function buildConfigPayload() {
    return {
      vpsIp: (cfg.vpsIp || '').trim(),
      vpsPort: Number.parseInt(cfg.vpsPort, 10) || 51820,
      vpsPubKey: (cfg.vpsPubKey || '').trim(),
      domain: (cfg.domain || '').trim(),
      acmeEmail: (cfg.acmeEmail || '').trim(),
      privateKey: '••••',
      services: (cfg.services || [])
        .map(item => ({
          name: (item.name || '').trim(),
          subdomain: (item.subdomain || '').trim().toLowerCase(),
          target: (item.target || '').trim(),
          enabled: Boolean(item.enabled)
        }))
        .filter(item => item.subdomain || item.target)
    };
  }

  async function onSaveConfig() {
    setLoading(true);
    setMessage({ text: '', kind: '' });
    try {
      await saveConfig(buildConfigPayload());
      await refreshConfigOnly();
      if (tab === 'vps') await loadVpsScript();
      setMessage({ text: 'Saved. The tunnel reconfigures automatically.', kind: 'success' });
    } catch (err) {
      if (Array.isArray(err.payload?.errors) && err.payload.errors.length) {
        setMessage({ text: `Error: ${err.payload.errors.join(' | ')}`, kind: 'error' });
      } else if (Array.isArray(err.payload?.issues) && err.payload.issues.length) {
        const detail = err.payload.issues
          .map(item => {
            const path = Array.isArray(item?.path) && item.path.length ? `${item.path.join('.')}: ` : '';
            return `${path}${item?.message || 'validation issue'}`;
          })
          .join(' | ');
        setMessage({ text: `Validation: ${detail}`, kind: 'error' });
      } else {
        setMessage({ text: err.message || 'Save failed.', kind: 'error' });
      }
    } finally {
      setLoading(false);
    }
  }

  async function onGenerateKeys() {
    if (cfg.publicKey && !window.confirm(
      'Regenerating keys will invalidate the current connection with the VPS. ' +
      'You will need to run the script on the VPS again. Continue?'
    )) return;
    setLoading(true);
    try {
      const data = await keygen();
      setCfg(current => ({ ...current, publicKey: data.publicKey || current.publicKey }));
      setMessage({ text: 'Keys generated successfully.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'Could not generate keys.', kind: 'error' });
    } finally {
      setLoading(false);
    }
  }

  async function onCopyScript() {
    const script = scriptMeta?.script || '';
    if (!script) return;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(script);
      } else {
        const area = document.createElement('textarea');
        area.value = script;
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.focus();
        area.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(area);
        if (!ok) throw new Error('copy failed');
      }
      setMessage({ text: 'Script copied to clipboard.', kind: 'success' });
      setScriptCopied(true);
      window.setTimeout(() => setScriptCopied(false), 2200);
    } catch {
      setMessage({ text: 'Could not copy automatically.', kind: 'error' });
      setScriptCopied(false);
    }
  }

  function onDownloadScript() {
    const script = scriptMeta?.script || '';
    if (!script) return;
    downloadText(scriptMeta?.filename || 'miniweed-tunnel-vps-setup.sh', script);
  }

  function renderDashboard() {
    const enabled = (cfg.services || []).filter(s => s.enabled && s.target);
    const showServices = Boolean(cfg.domain && enabled.length);
    const seenHosts = new Set();
    return (
      <>
        {setupIncomplete ? (
          <div className="alert alert-info">Initial setup required. Go to Configuration to get started.</div>
        ) : null}
        <section className="panel">
          <h2>Tunnel status</h2>
          <pre className="code-box">{status.raw || 'No information'}</pre>
        </section>
        {showServices ? (
          <section className="panel">
            <h2>Exposed services</h2>
            <div className="service-links">
              {enabled.map(svc => {
                const host = svc.subdomain ? `${svc.subdomain}.${cfg.domain}` : cfg.domain;
                const lower = host.toLowerCase();
                const duplicated = seenHosts.has(lower);
                seenHosts.add(lower);
                return (
                  <div key={`${svc.subdomain}-${svc.target}`} className="service-link-row">
                    <span className="muted">{svc.name || svc.target}</span>
                    <div className="service-link-meta">
                      <a href={`https://${host}`} target="_blank" rel="noopener noreferrer">{`https://${host}`}</a>
                      {duplicated ? <span className="duplicate-badge">duplicate host</span> : null}
                    </div>
                  </div>
                );
              })}
            </div>
          </section>
        ) : null}
      </>
    );
  }

  function renderConfig() {
    return (
      <>
        <section className="panel">
          <h2>WireGuard keys</h2>
          <label className={scriptMissingPublicKey ? 'label-required-missing' : 'label-required-ok'}>
            Umbrel public key (required for script)
          </label>
          <input className={scriptMissingPublicKey ? 'input-required-missing' : ''} value={cfg.publicKey || ''} readOnly />
          <div className="actions-row">
            <button className="btn btn-primary" onClick={onGenerateKeys} disabled={loading}>
              {cfg.publicKey ? 'Regenerate keys' : 'Generate keys'}
            </button>
          </div>
          {cfg.publicKey ? (
            <div className="rotate-box">
              <h3>Secure key rotation</h3>
              <p className="muted">
                Unlike "Regenerate", rotation does not break the tunnel: it generates new keys
                and a VPS script, and only applies them once you confirm.
              </p>
              {!rotation ? (
                <div className="actions-row">
                  <button className="btn" onClick={onRotatePrepare} disabled={rotationBusy}>
                    {rotationBusy ? 'Preparing…' : 'Start rotation'}
                  </button>
                </div>
              ) : (
                <>
                  <p className="muted">
                    New fingerprint: <code>{rotation.nextPublicKeyFingerprint || '—'}</code>
                    {rotation.target?.ip ? ` · VPS ${rotation.target.name || rotation.target.id} (${rotation.target.ip})` : ''}
                  </p>
                  <ol className="steps">
                    <li>Run this script as root on the VPS.</li>
                    <li>When it finishes, click "Confirm and apply".</li>
                  </ol>
                  <pre className="code-box">{rotation.script}</pre>
                  <p className="muted">SHA-256: <code>{rotation.scriptSha256 || '-'}</code></p>
                  <div className="actions-row">
                    <button className="btn" onClick={() => downloadText('miniweed-rotate.sh', rotation.script)}>Download .sh</button>
                    <button className="btn btn-primary" onClick={() => onRotateConfirm(true)} disabled={rotationBusy}>
                      {rotationBusy ? 'Applying…' : 'Confirm and apply'}
                    </button>
                    <button className="btn btn-danger" onClick={() => onRotateConfirm(false)} disabled={rotationBusy}>Cancel</button>
                  </div>
                </>
              )}
            </div>
          ) : null}
        </section>

        <section className="panel">
          <h2>VPS server</h2>
          {scriptPrereqMissing ? (
            <div className="alert alert-warn">
              To generate the script, complete the fields marked in red.
            </div>
          ) : null}
          <label className={scriptMissingVpsIp ? 'label-required-missing' : 'label-required-ok'}>
            VPS public IP (required for script)
          </label>
          <input
            className={scriptMissingVpsIp ? 'input-required-missing' : ''}
            value={cfg.vpsIp || ''}
            onInput={e => setField('vpsIp', e.currentTarget.value)}
            placeholder="123.45.67.89"
          />
          <label>VPS WireGuard port</label>
          <input type="number" value={cfg.vpsPort || 51820} onInput={e => setField('vpsPort', e.currentTarget.value)} min="1" max="65535" />
          <label>VPS public key</label>
          <input value={cfg.vpsPubKey || ''} onInput={e => setField('vpsPubKey', e.currentTarget.value)} placeholder="Paste the VPS public key here" />
          <p className="muted">{cfg.vpsPubKey ? `VPS key synced (${cfg.vpsPubKeyFingerprint || 'no fingerprint'})` : 'Not synced'}</p>
        </section>

        <section className="panel">
          <h2>Domain & HTTPS</h2>
          <label>Main domain</label>
          <input value={cfg.domain || ''} onInput={e => setField('domain', e.currentTarget.value)} placeholder="home.yourdomain.com" />
          <label>Let's Encrypt email</label>
          <input type="email" value={cfg.acmeEmail || ''} onInput={e => setField('acmeEmail', e.currentTarget.value)} placeholder="you@email.com" />
        </section>

        <div className="actions-row">
          <button className="btn btn-primary" onClick={onSaveConfig} disabled={loading}>Save configuration</button>
          {saveSuccessMsg ? <span className="save-inline-msg">{saveSuccessMsg}</span> : null}
        </div>
      </>
    );
  }

  function renderAdvanced() {
    return (
      <>
        <section className="panel">
          <h2>Emergency kill-switch</h2>
          <p className="muted">
            Script to stop WireGuard and block the UDP port on the VPS if you need to cut the
            tunnel immediately. Run it as root on the VPS.
          </p>
          <div className="actions-row">
            <button className="btn" onClick={onLoadKillSwitch} disabled={killSwitchBusy}>
              {killSwitchBusy ? 'Generating…' : 'Generate kill-switch'}
            </button>
            {killSwitch ? (
              <button className="btn" onClick={() => downloadText(killSwitch.filename || 'miniweed-killswitch.sh', killSwitch.script)}>
                Download .sh
              </button>
            ) : null}
          </div>
          {killSwitch ? (
            <>
              <pre className="code-box">{killSwitch.script}</pre>
              <p className="muted">SHA-256: <code>{killSwitch.sha256 || '-'}</code></p>
            </>
          ) : null}
        </section>
      </>
    );
  }

  function renderServices() {
    return (
      <>
        <section className="panel">
          <h2>Services to expose</h2>
          <p className="muted">Each service needs a subdomain and an internal URL.</p>
          <div className="services-grid">
            {(cfg.services || []).map((svc, idx) => {
              const h = formatHealth(cfg.serviceHealth?.[serviceKey(svc)] || null);
              return (
                <div key={idx} className="service-card">
                  <input value={svc.name || ''} onInput={e => setService(idx, 'name', e.currentTarget.value)} placeholder="Name" />
                  <input value={svc.subdomain || ''} onInput={e => setService(idx, 'subdomain', e.currentTarget.value)} placeholder="Subdomain" />
                  <input value={svc.target || ''} onInput={e => setService(idx, 'target', e.currentTarget.value)} placeholder="http://IP:port" />
                  <label className="check-inline">
                    <input type="checkbox" checked={Boolean(svc.enabled)} onChange={e => setService(idx, 'enabled', e.currentTarget.checked)} />
                    Enabled
                  </label>
                  <span className={`health-pill ${h.cls}`}>{h.text}</span>
                  <button className="btn btn-danger" onClick={() => removeServiceRow(idx)}>Delete</button>
                </div>
              );
            })}
          </div>
          <div className="actions-row">
            <button className="btn" onClick={addServiceRow}>Add service</button>
            <button className="btn" onClick={onRefreshHealth} disabled={healthBusy}>
              {healthBusy ? 'Checking…' : 'Refresh status'}
            </button>
          </div>
        </section>
        <div className="actions-row">
          <button className="btn btn-primary" onClick={onSaveConfig} disabled={loading}>Save configuration</button>
          {saveSuccessMsg ? <span className="save-inline-msg">{saveSuccessMsg}</span> : null}
        </div>
      </>
    );
  }

  function renderVps() {
    return (
      <>
        <section className="panel">
          <h2>VPS installation script</h2>
          <p className="muted">Run this script as root on your VPS.</p>
          <div className="actions-row">
            <label className="check-inline">
              <input type="checkbox" checked={vpsScriptWithCrowdsec} onChange={e => setVpsScriptWithCrowdsec(e.currentTarget.checked)} />
              Include CrowdSec
            </label>
            <button className="btn" onClick={() => loadVpsScript('manual')}>Reload script</button>
            {scriptReloadMsg ? <span className="script-inline-msg">{scriptReloadMsg}</span> : null}
          </div>

          {!scriptMeta ? <div className="alert alert-warn">Configure the VPS IP and generate keys first.</div> : null}
          {scriptMeta ? (
            <>
              <pre className="code-box">{scriptMeta.script}</pre>
              <p className="muted">SHA-256: <code>{scriptMeta.sha256 || '-'}</code></p>
              <div className="actions-row">
                <button className={`btn ${scriptCopied ? 'btn-success' : ''}`} onClick={onCopyScript}>
                  {scriptCopied ? (
                    <span className="btn-copy-feedback">
                      <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
                        <path d="M6.2 11.4 3.3 8.5l-1 1 3.9 3.9L14 5.6l-1-1z" />
                      </svg>
                      Copied
                    </span>
                  ) : 'Copy script'}
                </button>
                <button className="btn" onClick={onDownloadScript}>Download .sh</button>
              </div>
            </>
          ) : null}
        </section>

        <section className="panel">
          <h2>Setup steps</h2>
          <ol className="steps">
            <li className={cfg.publicKey ? 'done' : ''}>Generate keys</li>
            <li className={cfg.publicKey && cfg.vpsIp ? 'done' : ''}>Configure VPS IP</li>
            <li className={cfg.publicKey && cfg.vpsIp ? 'done' : ''}>Run script on the VPS</li>
            <li className={cfg.publicKey && cfg.vpsIp && cfg.vpsPubKey && cfg.domain && cfg.acmeEmail ? 'done' : ''}>Save configuration and done</li>
          </ol>
        </section>
      </>
    );
  }

  let content = renderDashboard();
  if (tab === 'config') content = renderConfig();
  if (tab === 'advanced') content = renderAdvanced();
  if (tab === 'services') content = renderServices();
  if (tab === 'vps') content = renderVps();

  return (
    <main className="shell">
      <header className="hero">
        <div>
          <h1>Umbrel Tunnel</h1>
          <p className="muted">Secure channel for sovereign infrastructure.</p>
        </div>
        <div className={`status-badge ${statusBadge.cls}`}>
          <span className="dot" />
          <span>{statusBadge.text}</span>
        </div>
      </header>

      <nav className="tabbar" role="tablist" aria-label="Sections">
        {TAB_ITEMS.map(item => (
          <button
            key={item.key}
            role="tab"
            aria-selected={tab === item.key}
            className={`tab ${tab === item.key ? 'active' : ''}`}
            onClick={() => setTab(item.key)}
          >
            {item.label}
          </button>
        ))}
      </nav>

      <div aria-live="polite" role="status">
        {message.text ? <div className={`alert ${message.kind === 'error' ? 'alert-error' : 'alert-success'}`}>{message.text}</div> : null}
      </div>
      {loading ? <div className="muted">Loading...</div> : null}
      {content}
    </main>
  );
}
