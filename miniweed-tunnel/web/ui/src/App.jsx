import { useEffect, useMemo, useState } from 'preact/hooks';
import { getConfig, getStatus, getVpsSetupScript, keygen, saveConfig } from './api.js';

const TAB_ITEMS = [
  { key: 'dashboard', label: 'Panel' },
  { key: 'config', label: 'Configuracion' },
  { key: 'optional', label: 'Configuracion opcional' },
  { key: 'services', label: 'Servicios' },
  { key: 'vps', label: 'Setup VPS' }
];

const EMPTY_SERVICE = { name: '', subdomain: '', target: '', enabled: true };

function serviceKey(svc) {
  const subdomain = (svc?.subdomain || '').trim().toLowerCase() || '@root';
  const target = (svc?.target || '').trim().toLowerCase();
  return `${subdomain}|${target}`;
}

function formatHealth(health) {
  if (!health || !health.checked) return { cls: '', text: 'Sin comprobar' };
  if (health.ok) return { cls: 'ok', text: 'Conectado' };
  return { cls: 'error', text: 'Sin conexion' };
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
  const [status, setStatus] = useState({ connected: false, raw: 'Cargando...' });
  const [message, setMessage] = useState({ text: '', kind: '' });
  const [loading, setLoading] = useState(false);
  const [vpsScriptWithCrowdsec, setVpsScriptWithCrowdsec] = useState(false);
  const [scriptMeta, setScriptMeta] = useState(null);
  const [scriptReloadMsg, setScriptReloadMsg] = useState('');
  const [scriptCopied, setScriptCopied] = useState(false);

  const setupIncomplete = !cfg.publicKey || !cfg.vpsPubKey || !cfg.vpsIp;
  const scriptMissingPublicKey = !cfg.publicKey;
  const scriptMissingVpsIp = !(cfg.vpsIp || '').trim();
  const scriptPrereqMissing = scriptMissingPublicKey || scriptMissingVpsIp;
  const saveSuccessMsg = message.kind === 'success' && message.text.includes('Guardado.') ? message.text : '';

  async function refreshStatusOnly() {
    try {
      const data = await getStatus();
      setStatus(data || { connected: false, raw: 'Sin informacion' });
    } catch {
      setStatus({ connected: false, raw: 'Error obteniendo estado' });
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
      setMessage({ text: err.message || 'No se pudo cargar la configuracion.', kind: 'error' });
    } finally {
      setLoading(false);
    }
  }

  async function loadVpsScript(source = 'auto') {
    try {
      const data = await getVpsSetupScript({ withCrowdsec: vpsScriptWithCrowdsec });
      setScriptMeta(data);
      if (source === 'manual' && vpsScriptWithCrowdsec) setScriptReloadMsg('Script recargado con CrowdSec');
      else setScriptReloadMsg('');
      setScriptCopied(false);
    } catch {
      setScriptMeta(null);
      setScriptReloadMsg('');
      setScriptCopied(false);
    }
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
    if (status.connected) return { cls: 'connected', text: 'Conectado' };
    if ((status.peerCount || 0) > 0) return { cls: 'waiting', text: 'Conectando...' };
    return { cls: 'disconnected', text: 'Sin tunel' };
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
      setMessage({ text: 'Guardado. El tunel se reconfigura automaticamente.', kind: 'success' });
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
        setMessage({ text: err.message || 'Error al guardar.', kind: 'error' });
      }
    } finally {
      setLoading(false);
    }
  }

  async function onGenerateKeys() {
    setLoading(true);
    try {
      const data = await keygen();
      setCfg(current => ({ ...current, publicKey: data.publicKey || current.publicKey }));
      setMessage({ text: 'Claves generadas correctamente.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'No se pudieron generar las claves.', kind: 'error' });
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
      setMessage({ text: 'Script copiado al portapapeles.', kind: 'success' });
      setScriptCopied(true);
      window.setTimeout(() => setScriptCopied(false), 2200);
    } catch {
      setMessage({ text: 'No se pudo copiar automaticamente.', kind: 'error' });
      setScriptCopied(false);
    }
  }

  function onDownloadScript() {
    const script = scriptMeta?.script || '';
    if (!script) return;
    const blob = new Blob([`${script}\n`], { type: 'text/x-shellscript;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = scriptMeta?.filename || 'miniweed-tunnel-vps-setup.sh';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function renderDashboard() {
    const enabled = (cfg.services || []).filter(s => s.enabled && s.target);
    const showServices = Boolean(cfg.domain && enabled.length);
    const seenHosts = new Set();
    return (
      <>
        {setupIncomplete ? (
          <div className="alert alert-info">Primera configuracion necesaria. Ve a Configuracion para empezar.</div>
        ) : null}
        <section className="panel">
          <h2>Estado del tunel</h2>
          <pre className="code-box">{status.raw || 'Sin informacion'}</pre>
        </section>
        {showServices ? (
          <section className="panel">
            <h2>Servicios expuestos</h2>
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
                      <code>{`https://${host}`}</code>
                      {duplicated ? <span className="duplicate-badge">host duplicado</span> : null}
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
          <h2>Claves WireGuard</h2>
          <label className={scriptMissingPublicKey ? 'label-required-missing' : 'label-required-ok'}>
            Clave publica de Umbrel (requerido para script)
          </label>
          <input className={scriptMissingPublicKey ? 'input-required-missing' : ''} value={cfg.publicKey || ''} readOnly />
          <div className="actions-row">
            <button className="btn btn-primary" onClick={onGenerateKeys} disabled={loading}>Generar nuevas claves</button>
          </div>
        </section>

        <section className="panel">
          <h2>Servidor VPS</h2>
          {scriptPrereqMissing ? (
            <div className="alert alert-warn">
              Para generar el script, completa los campos marcados en rojo.
            </div>
          ) : null}
          <label className={scriptMissingVpsIp ? 'label-required-missing' : 'label-required-ok'}>
            IP publica del VPS (requerido para script)
          </label>
          <input
            className={scriptMissingVpsIp ? 'input-required-missing' : ''}
            value={cfg.vpsIp || ''}
            onInput={e => setField('vpsIp', e.currentTarget.value)}
            placeholder="123.45.67.89"
          />
          <label>Puerto WireGuard del VPS</label>
          <input type="number" value={cfg.vpsPort || 51820} onInput={e => setField('vpsPort', e.currentTarget.value)} min="1" max="65535" />
          <label>Clave publica del VPS</label>
          <input value={cfg.vpsPubKey || ''} onInput={e => setField('vpsPubKey', e.currentTarget.value)} placeholder="Pega aqui la clave publica del VPS" />
          <p className="muted">{cfg.vpsPubKey ? `Clave VPS sincronizada (${cfg.vpsPubKeyFingerprint || 'sin huella'})` : 'Sin sincronizar'}</p>
        </section>

        <section className="panel">
          <h2>Dominio y HTTPS</h2>
          <label>Dominio principal</label>
          <input value={cfg.domain || ''} onInput={e => setField('domain', e.currentTarget.value)} placeholder="home.tudominio.com" />
          <label>Email para Let's Encrypt</label>
          <input type="email" value={cfg.acmeEmail || ''} onInput={e => setField('acmeEmail', e.currentTarget.value)} placeholder="tu@email.com" />
        </section>

        <div className="actions-row">
          <button className="btn btn-primary" onClick={onSaveConfig} disabled={loading}>Guardar configuracion</button>
          {saveSuccessMsg ? <span className="save-inline-msg">{saveSuccessMsg}</span> : null}
        </div>
      </>
    );
  }

  function renderOptionalConfig() {
    return (
      <>
        <section className="panel">
          <h2>Configuracion opcional</h2>
          <p className="muted">Sin opciones adicionales por ahora.</p>
        </section>
      </>
    );
  }

  function renderServices() {
    return (
      <>
        <section className="panel">
          <h2>Servicios a exponer</h2>
          <p className="muted">Cada servicio necesita subdominio y URL interna.</p>
          <div className="services-grid">
            {(cfg.services || []).map((svc, idx) => {
              const h = formatHealth(cfg.serviceHealth?.[serviceKey(svc)] || null);
              return (
                <div key={idx} className="service-card">
                  <input value={svc.name || ''} onInput={e => setService(idx, 'name', e.currentTarget.value)} placeholder="Nombre" />
                  <input value={svc.subdomain || ''} onInput={e => setService(idx, 'subdomain', e.currentTarget.value)} placeholder="Subdominio" />
                  <input value={svc.target || ''} onInput={e => setService(idx, 'target', e.currentTarget.value)} placeholder="http://IP:puerto" />
                  <label className="check-inline">
                    <input type="checkbox" checked={Boolean(svc.enabled)} onChange={e => setService(idx, 'enabled', e.currentTarget.checked)} />
                    Activo
                  </label>
                  <span className={`health-pill ${h.cls}`}>{h.text}</span>
                  <button className="btn btn-danger" onClick={() => removeServiceRow(idx)}>Eliminar</button>
                </div>
              );
            })}
          </div>
          <div className="actions-row">
            <button className="btn" onClick={addServiceRow}>Anadir servicio</button>
          </div>
        </section>
        <div className="actions-row">
          <button className="btn btn-primary" onClick={onSaveConfig} disabled={loading}>Guardar configuracion</button>
          {saveSuccessMsg ? <span className="save-inline-msg">{saveSuccessMsg}</span> : null}
        </div>
      </>
    );
  }

  function renderVps() {
    return (
      <>
        <section className="panel">
          <h2>Script de instalacion del VPS</h2>
          <p className="muted">Ejecuta este script como root en tu VPS.</p>
          <div className="actions-row">
            <label className="check-inline">
              <input type="checkbox" checked={vpsScriptWithCrowdsec} onChange={e => setVpsScriptWithCrowdsec(e.currentTarget.checked)} />
              Incluir CrowdSec
            </label>
            <button className="btn" onClick={() => loadVpsScript('manual')}>Recargar script</button>
            {scriptReloadMsg ? <span className="script-inline-msg">{scriptReloadMsg}</span> : null}
          </div>

          {!scriptMeta ? <div className="alert alert-warn">Configura la IP del VPS y genera las claves primero.</div> : null}
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
                      Copiado
                    </span>
                  ) : 'Copiar script'}
                </button>
                <button className="btn" onClick={onDownloadScript}>Descargar .sh</button>
              </div>
            </>
          ) : null}
        </section>

        <section className="panel">
          <h2>Pasos de configuracion</h2>
          <ol className="steps">
            <li className={cfg.publicKey ? 'done' : ''}>Generar claves</li>
            <li className={cfg.publicKey && cfg.vpsIp ? 'done' : ''}>Configurar VPS IP</li>
            <li className={cfg.publicKey && cfg.vpsIp ? 'done' : ''}>Ejecutar script en el VPS</li>
            <li className={cfg.publicKey && cfg.vpsIp && cfg.vpsPubKey && cfg.domain && cfg.acmeEmail ? 'done' : ''}>Guardar configuracion y listo</li>
          </ol>
        </section>
      </>
    );
  }

  let content = renderDashboard();
  if (tab === 'config') content = renderConfig();
  if (tab === 'optional') content = renderOptionalConfig();
  if (tab === 'services') content = renderServices();
  if (tab === 'vps') content = renderVps();

  return (
    <main className="shell">
      <header className="hero">
        <div>
          <h1>Umbrel Tunnel</h1>
          <p className="muted">Canal seguro para infraestructura soberana.</p>
        </div>
        <div className={`status-badge ${statusBadge.cls}`}>
          <span className="dot" />
          <span>{statusBadge.text}</span>
        </div>
      </header>

      <nav className="tabbar">
        {TAB_ITEMS.map(item => (
          <button
            key={item.key}
            className={`tab ${tab === item.key ? 'active' : ''}`}
            onClick={() => setTab(item.key)}
          >
            {item.label}
          </button>
        ))}
      </nav>

      {message.text ? <div className={`alert ${message.kind === 'error' ? 'alert-error' : 'alert-success'}`}>{message.text}</div> : null}
      {loading ? <div className="muted">Cargando...</div> : null}
      {content}
    </main>
  );
}
