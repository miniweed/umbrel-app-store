import { useEffect, useMemo, useState } from 'preact/hooks';
import {
  addAuthPubkey,
  getAuthPubkeys,
  getAuthSessions,
  getConfig,
  getStatus,
  getVpsSetupScript,
  keygen,
  login,
  logout,
  removeAuthPubkey,
  revokeAuthSession,
  saveConfig,
  setUiPassword,
  triggerFailover
} from './api.js';

/** @typedef {import('../../api-spec/openapi').components['schemas']['ConfigResponse']} ConfigResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['ConfigUpdateRequest']} ConfigUpdateRequest */
/** @typedef {import('../../api-spec/openapi').components['schemas']['StatusResponse']} StatusResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['VpsSetupScriptResponse']} VpsSetupScriptResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['AuthPubkeysResponse']} AuthPubkeysResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['AuthSessionsResponse']} AuthSessionsResponse */

const TAB_ITEMS = [
  { key: 'dashboard', label: 'Panel' },
  { key: 'config', label: 'Configuracion' },
  { key: 'optional', label: 'Configuracion opcional' },
  { key: 'services', label: 'Servicios' },
  { key: 'vps', label: 'Setup VPS' }
];

const EMPTY_SERVICE = { name: '', subdomain: '', target: '', enabled: true };
const DEFAULT_FAILOVER_POLICY = {
  activeFailuresRequired: 2,
  candidateSuccessesRequired: 2,
  cooldownMs: 120000
};

function randomId(prefix = 'vps') {
  return `${prefix}-${Math.random().toString(16).slice(2, 10)}`;
}

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

function normalizeFailoverPolicy(policy) {
  const raw = policy && typeof policy === 'object' ? policy : {};
  return {
    activeFailuresRequired: Number.parseInt(raw.activeFailuresRequired, 10) || DEFAULT_FAILOVER_POLICY.activeFailuresRequired,
    candidateSuccessesRequired: Number.parseInt(raw.candidateSuccessesRequired, 10) || DEFAULT_FAILOVER_POLICY.candidateSuccessesRequired,
    cooldownMs: Number.parseInt(raw.cooldownMs, 10) || DEFAULT_FAILOVER_POLICY.cooldownMs
  };
}

/**
 * @param {Partial<ConfigResponse> | null | undefined} cfg
 * @returns {ConfigResponse}
 */
function normalizeConfig(cfg) {
  const out = { ...(cfg || {}) };
  const rawTargets = Array.isArray(out.vpsTargets) ? out.vpsTargets : [];
  const primary = rawTargets.find(t => String(t?.id || '').trim() === 'primary') || null;
  if (!(out.vpsIp || '').trim() && (primary?.ip || '').trim()) out.vpsIp = primary.ip;
  if (!Number.isFinite(Number.parseInt(out.vpsPort, 10)) && Number.isFinite(Number.parseInt(primary?.port, 10))) out.vpsPort = primary.port;
  if (!(out.vpsPubKey || '').trim() && (primary?.pubKey || '').trim()) out.vpsPubKey = primary.pubKey;
  out.vpsTargets = rawTargets.filter(t => String(t?.id || '').trim() !== 'primary');
  out.services = Array.isArray(out.services) ? out.services : [];
  out.serviceHealth = out.serviceHealth && typeof out.serviceHealth === 'object' ? out.serviceHealth : {};
  out.failoverPolicy = normalizeFailoverPolicy(out.failoverPolicy);
  const hasPrimary = Boolean((out.vpsIp || '').trim() || (out.vpsPubKey || '').trim());
  const availableIds = new Set(out.vpsTargets.map(t => t.id));
  if (hasPrimary) availableIds.add('primary');
  const preferred = String(out.activeVpsId || '').trim();
  out.activeVpsId = availableIds.has(preferred)
    ? preferred
    : (hasPrimary ? 'primary' : out.vpsTargets[0]?.id || '');
  return /** @type {ConfigResponse} */ (out);
}

/** @returns {ConfigResponse} */
function initialState() {
  return {
    publicKey: '',
    vpsIp: '',
    vpsPort: 51820,
    vpsPubKey: '',
    vpsPubKeyFingerprint: '',
    vpsFingerprints: {},
    vpsTargets: [],
    activeVpsId: '',
    domain: '',
    acmeEmail: '',
    services: [],
    serviceHealth: {},
    failoverPolicy: { ...DEFAULT_FAILOVER_POLICY },
    auth: { passwordEnabled: false, sessionCount: 0 }
  };
}

export function App() {
  const [tab, setTab] = useState(/** @type {'dashboard' | 'config' | 'optional' | 'services' | 'vps'} */ ('dashboard'));
  const [cfg, setCfg] = useState(/** @type {ConfigResponse} */ (initialState()));
  const [status, setStatus] = useState(/** @type {StatusResponse} */ ({ connected: false, raw: 'Cargando...' }));
  const [message, setMessage] = useState({ text: '', kind: '' });
  const [loading, setLoading] = useState(false);
  const [authMsg, setAuthMsg] = useState('');
  const [uiPassword, setUiPasswordValue] = useState('');
  const [pubkeyName, setPubkeyName] = useState('');
  const [pubkeyValue, setPubkeyValue] = useState('');
  const [pubkeys, setPubkeys] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [vpsScriptWithCrowdsec, setVpsScriptWithCrowdsec] = useState(false);
  const [scriptMeta, setScriptMeta] = useState(/** @type {VpsSetupScriptResponse | null} */ (null));
  const [showLogin, setShowLogin] = useState(false);
  const [loginPassword, setLoginPassword] = useState('');

  const setupIncomplete = !cfg.publicKey || !cfg.vpsPubKey || !cfg.vpsIp;
  const scriptMissingPublicKey = !cfg.publicKey;
  const scriptMissingVpsIp = !(cfg.vpsIp || '').trim();
  const scriptPrereqMissing = scriptMissingPublicKey || scriptMissingVpsIp;

  async function refreshStatusOnly() {
    try {
      const data = await getStatus();
      setStatus(data || { connected: false, raw: 'Sin informacion' });
    } catch {
      setStatus({ connected: false, raw: 'Error obteniendo estado' });
    }
  }

  async function refreshConfigAndRelated() {
    const loaded = normalizeConfig(await getConfig());
    setCfg(loaded);

    const [keysRes, sessionsRes] = await Promise.all([
      getAuthPubkeys().catch(() => /** @type {AuthPubkeysResponse} */ ({ pubkeys: [] })),
      getAuthSessions().catch(() => /** @type {AuthSessionsResponse} */ ({ sessions: [] }))
    ]);
    setPubkeys(Array.isArray(keysRes.pubkeys) ? keysRes.pubkeys : []);
    setSessions(Array.isArray(sessionsRes.sessions) ? sessionsRes.sessions : []);
  }

  async function refreshAll() {
    try {
      setLoading(true);
      await Promise.all([refreshConfigAndRelated(), refreshStatusOnly()]);
      setMessage({ text: '', kind: '' });
      setShowLogin(false);
    } catch (err) {
      if (err.status === 401) {
        setShowLogin(true);
        setMessage({ text: 'Login requerido para acceder a la UI.', kind: 'error' });
        return;
      }
      setMessage({ text: err.message || 'No se pudo cargar la configuracion.', kind: 'error' });
    } finally {
      setLoading(false);
    }
  }

  async function loadVpsScript() {
    try {
      const selectedId = cfg.activeVpsId || '';
      const data = await getVpsSetupScript({ vpsId: selectedId, withCrowdsec: vpsScriptWithCrowdsec });
      setScriptMeta(data);
    } catch {
      setScriptMeta(null);
    }
  }

  useEffect(() => {
    refreshAll();
    const timer = setInterval(refreshStatusOnly, 8000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (tab === 'vps') loadVpsScript();
  }, [tab, cfg.activeVpsId, vpsScriptWithCrowdsec]);

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

  function setTarget(index, field, value) {
    setCfg(current => {
      const targets = [...current.vpsTargets];
      const item = {
        ...targets[index],
        id: targets[index]?.id || randomId(),
        [field]: value
      };
      targets[index] = item;
      return { ...current, vpsTargets: targets };
    });
  }

  function addTarget() {
    setCfg(current => {
      const targets = [...current.vpsTargets, {
        id: randomId(),
        name: `VPS ${current.vpsTargets.length + 1}`,
        ip: '',
        port: 51820,
        pubKey: '',
        enabled: true,
        priority: current.vpsTargets.length
      }];
      return { ...current, vpsTargets: targets, activeVpsId: current.activeVpsId || targets[0]?.id || '' };
    });
  }

  function removeTarget(index) {
    setCfg(current => {
      const removed = current.vpsTargets[index];
      const targets = current.vpsTargets.filter((_, i) => i !== index);
      const activeVpsId = current.activeVpsId === removed?.id ? (targets[0]?.id || '') : current.activeVpsId;
      return { ...current, vpsTargets: targets, activeVpsId };
    });
  }

  function collectTargets() {
    const values = [];
    const primaryIp = (cfg.vpsIp || '').trim();
    const primaryPubKey = (cfg.vpsPubKey || '').trim();
    if (primaryIp || primaryPubKey) {
      values.push({
        id: 'primary',
        name: 'VPS principal',
        ip: primaryIp,
        port: Number.parseInt(cfg.vpsPort, 10) || 51820,
        pubKey: primaryPubKey,
        enabled: true,
        priority: 0
      });
    }

    const additional = (cfg.vpsTargets || [])
      .map((t, i) => ({
        id: t.id || randomId(),
        name: (t.name || `VPS ${i + 1}`).trim(),
        ip: (t.ip || '').trim(),
        port: Number.parseInt(t.port, 10) || 51820,
        pubKey: (t.pubKey || '').trim(),
        enabled: t.enabled !== false,
        priority: Number.parseInt(t.priority, 10) || (i + 1)
      }))
      .filter(t => t.id !== 'primary')
      .filter(t => t.ip || t.pubKey);

    values.push(...additional);
    return /** @type {ConfigUpdateRequest['vpsTargets']} */ (values);
  }

  /** @returns {ConfigUpdateRequest} */
  function buildConfigPayload() {
    return {
      vpsIp: (cfg.vpsIp || '').trim(),
      vpsPort: Number.parseInt(cfg.vpsPort, 10) || 51820,
      vpsPubKey: (cfg.vpsPubKey || '').trim(),
      vpsTargets: collectTargets(),
      activeVpsId: cfg.activeVpsId || '',
      failoverPolicy: normalizeFailoverPolicy(cfg.failoverPolicy),
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
      const payload = buildConfigPayload();
      await saveConfig(payload);
      await refreshConfigAndRelated();
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

  async function onSetPassword() {
    if (!uiPassword || uiPassword.length < 12) {
      setAuthMsg('Usa al menos 12 caracteres.');
      return;
    }
    try {
      await setUiPassword(uiPassword);
      setUiPasswordValue('');
      setAuthMsg('Contrasena UI guardada.');
      await refreshConfigAndRelated();
    } catch (err) {
      setAuthMsg(err.message || 'Error al guardar contrasena.');
    }
  }

  async function onLogout() {
    try {
      await logout();
      setAuthMsg('Sesion cerrada.');
      setShowLogin(true);
    } catch (err) {
      setAuthMsg(err.message || 'No se pudo cerrar sesion.');
    }
  }

  async function onAddPubkey() {
    if (!pubkeyName.trim() || !pubkeyValue.trim()) {
      setAuthMsg('Nombre y clave son obligatorios.');
      return;
    }
    try {
      await addAuthPubkey(pubkeyName.trim(), pubkeyValue.trim());
      setPubkeyName('');
      setPubkeyValue('');
      setAuthMsg('Clave anadida.');
      const out = await getAuthPubkeys();
      setPubkeys(out.pubkeys || []);
    } catch (err) {
      setAuthMsg(err.message || 'No se pudo anadir la clave.');
    }
  }

  async function onDeletePubkey(id) {
    try {
      await removeAuthPubkey(id);
      const out = await getAuthPubkeys();
      setPubkeys(out.pubkeys || []);
    } catch (err) {
      setAuthMsg(err.message || 'No se pudo eliminar la clave.');
    }
  }

  async function onRevokeSession(id) {
    try {
      await revokeAuthSession(id);
      const out = await getAuthSessions();
      setSessions(out.sessions || []);
    } catch (err) {
      setAuthMsg(err.message || 'No se pudo revocar la sesion.');
    }
  }

  async function onFailoverAuto() {
    try {
      const out = await triggerFailover('');
      setMessage({
        text: out.switched
          ? `Failover aplicado a ${out.next?.name || out.next?.id}`
          : 'No fue necesario cambiar VPS.',
        kind: 'success'
      });
      await refreshConfigAndRelated();
      await loadVpsScript();
    } catch (err) {
      setMessage({ text: err.message || 'No se pudo ejecutar failover.', kind: 'error' });
    }
  }

  async function onFailoverManual() {
    if (!cfg.activeVpsId) {
      setMessage({ text: 'Selecciona un VPS.', kind: 'error' });
      return;
    }
    try {
      const out = await triggerFailover(cfg.activeVpsId);
      setMessage({ text: `VPS activo: ${out.next?.name || out.activeVpsId}`, kind: 'success' });
      await refreshConfigAndRelated();
      await loadVpsScript();
    } catch (err) {
      setMessage({ text: err.message || 'No se pudo cambiar de VPS.', kind: 'error' });
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
    } catch {
      setMessage({ text: 'No se pudo copiar automaticamente.', kind: 'error' });
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

  async function onLoginSubmit(e) {
    e.preventDefault();
    if (!loginPassword) return;
    try {
      await login(loginPassword);
      setLoginPassword('');
      setShowLogin(false);
      await refreshAll();
    } catch (err) {
      setMessage({ text: err.message || 'Login invalido.', kind: 'error' });
    }
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
        </div>
      </>
    );
  }

  function renderOptionalConfig() {
    return (
      <>
        <section className="panel">
          <h2>VPS adicionales y failover</h2>
          <p className="muted">Aqui configuras nodos de respaldo y la politica de cambio automatico.</p>
          <h3>VPS adicionales / failover</h3>
          <div className="target-list">
            {cfg.vpsTargets.length === 0 ? <p className="muted">Sin VPS adicionales</p> : null}
            {cfg.vpsTargets.map((t, i) => (
              <div className="target-card" key={t.id || i}>
                <div className="target-grid">
                  <input value={t.name || ''} onInput={e => setTarget(i, 'name', e.currentTarget.value)} placeholder="Nombre VPS" />
                  <input value={t.ip || ''} onInput={e => setTarget(i, 'ip', e.currentTarget.value)} placeholder="IP/host" />
                  <input type="number" value={t.port || 51820} onInput={e => setTarget(i, 'port', e.currentTarget.value)} min="1" max="65535" />
                  <input type="number" value={Number.isFinite(t.priority) ? t.priority : (i + 1)} onInput={e => setTarget(i, 'priority', e.currentTarget.value)} min="0" max="99" />
                  <label className="check-inline">
                    <input type="checkbox" checked={t.enabled !== false} onChange={e => setTarget(i, 'enabled', e.currentTarget.checked)} />
                    Activo
                  </label>
                  <button className="btn btn-danger" onClick={() => removeTarget(i)}>Eliminar</button>
                </div>
                <input value={t.pubKey || ''} onInput={e => setTarget(i, 'pubKey', e.currentTarget.value)} placeholder="Clave publica VPS" />
                {cfg.vpsFingerprints?.[t.id] ? <p className="muted">Huella: {cfg.vpsFingerprints[t.id]}</p> : null}
              </div>
            ))}
          </div>
          <div className="actions-row">
            <button className="btn" onClick={addTarget}>Anadir VPS</button>
          </div>

          <h3>Politica de failover</h3>
          <label>Fallos consecutivos del VPS activo para forzar cambio</label>
          <input
            type="number"
            min="1"
            max="10"
            value={cfg.failoverPolicy?.activeFailuresRequired ?? DEFAULT_FAILOVER_POLICY.activeFailuresRequired}
            onInput={e => setField('failoverPolicy', {
              ...(cfg.failoverPolicy || DEFAULT_FAILOVER_POLICY),
              activeFailuresRequired: e.currentTarget.value
            })}
          />
          <label>Exitos consecutivos del candidato para aceptar cambio</label>
          <input
            type="number"
            min="1"
            max="10"
            value={cfg.failoverPolicy?.candidateSuccessesRequired ?? DEFAULT_FAILOVER_POLICY.candidateSuccessesRequired}
            onInput={e => setField('failoverPolicy', {
              ...(cfg.failoverPolicy || DEFAULT_FAILOVER_POLICY),
              candidateSuccessesRequired: e.currentTarget.value
            })}
          />
          <label>Cooldown entre cambios automaticos (ms)</label>
          <input
            type="number"
            min="0"
            max="3600000"
            value={cfg.failoverPolicy?.cooldownMs ?? DEFAULT_FAILOVER_POLICY.cooldownMs}
            onInput={e => setField('failoverPolicy', {
              ...(cfg.failoverPolicy || DEFAULT_FAILOVER_POLICY),
              cooldownMs: e.currentTarget.value
            })}
          />
        </section>

        <section className="panel">
          <h2>Autenticacion web</h2>
          <label>Nueva contrasena (minimo 12 caracteres)</label>
          <input value={uiPassword} onInput={e => setUiPasswordValue(e.currentTarget.value)} placeholder="Introduce contrasena fuerte" />
          <div className="actions-row">
            <button className="btn" onClick={onSetPassword}>Guardar contrasena UI</button>
            <button className="btn" onClick={onLogout}>Cerrar sesion UI</button>
          </div>

          <label>Anadir clave publica Ed25519</label>
          <input value={pubkeyName} onInput={e => setPubkeyName(e.currentTarget.value)} placeholder="Nombre del dispositivo" />
          <input value={pubkeyValue} onInput={e => setPubkeyValue(e.currentTarget.value)} placeholder="Clave publica base64" />
          <div className="actions-row">
            <button className="btn" onClick={onAddPubkey}>Anadir clave publica</button>
            <button className="btn" onClick={async () => {
              const out = await getAuthPubkeys().catch(() => ({ pubkeys: [] }));
              setPubkeys(out.pubkeys || []);
            }}>Refrescar claves</button>
          </div>
          <div className="list-box">
            {pubkeys.length === 0 ? <p className="muted">Sin claves registradas</p> : null}
            {pubkeys.map(item => (
              <div key={item.id} className="list-row">
                <span>{item.name} ({item.id})</span>
                <button className="btn btn-danger" onClick={() => onDeletePubkey(item.id)}>Eliminar</button>
              </div>
            ))}
          </div>

          <div className="list-box">
            {sessions.length === 0 ? <p className="muted">Sin sesiones activas</p> : null}
            {sessions.map(s => (
              <div key={s.id} className="list-row">
                <span>{s.id}{s.current ? ' (actual)' : ''}</span>
                <button className="btn btn-danger" onClick={() => onRevokeSession(s.id)}>Revocar</button>
              </div>
            ))}
          </div>

          <div className="actions-row">
            <button className="btn" onClick={async () => {
              const out = await getAuthSessions().catch(() => ({ sessions: [] }));
              setSessions(out.sessions || []);
            }}>Refrescar sesiones</button>
          </div>

          {authMsg ? <p className="muted">{authMsg}</p> : null}
        </section>

        <div className="actions-row">
          <button className="btn btn-primary" onClick={onSaveConfig} disabled={loading}>Guardar configuracion</button>
        </div>
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
        </div>
      </>
    );
  }

  function renderVps() {
    const selectableTargets = [
      ...(((cfg.vpsIp || '').trim() || (cfg.vpsPubKey || '').trim())
        ? [{ id: 'primary', name: 'VPS principal', ip: (cfg.vpsIp || '').trim() }]
        : []),
      ...(cfg.vpsTargets || [])
    ];

    return (
      <>
        <section className="panel">
          <h2>Script de instalacion del VPS</h2>
          <p className="muted">Ejecuta este script como root en tu VPS.</p>
          <div className="actions-row">
            <select value={cfg.activeVpsId || ''} onChange={e => setField('activeVpsId', e.currentTarget.value)}>
              {selectableTargets.map(t => (
                <option key={t.id} value={t.id}>{`${t.name} (${t.ip || 'sin ip'})`}</option>
              ))}
            </select>
            <label className="check-inline">
              <input type="checkbox" checked={vpsScriptWithCrowdsec} onChange={e => setVpsScriptWithCrowdsec(e.currentTarget.checked)} />
              Incluir CrowdSec
            </label>
            <button className="btn" onClick={loadVpsScript}>Recargar script</button>
          </div>

          {!scriptMeta ? <div className="alert alert-warn">Configura la IP del VPS y genera las claves primero.</div> : null}
          {scriptMeta ? (
            <>
              <pre className="code-box">{scriptMeta.script}</pre>
              <p className="muted">SHA-256: <code>{scriptMeta.sha256 || '-'}</code></p>
              <div className="actions-row">
                <button className="btn" onClick={onCopyScript}>Copiar script</button>
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
          <div className="actions-row">
            <button className="btn" onClick={onFailoverAuto}>Failover automatico</button>
            <button className="btn" onClick={onFailoverManual}>Cambiar al VPS seleccionado</button>
          </div>
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
          <p className="muted">Canal seguro y failover activo para infraestructura soberana.</p>
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
      {showLogin ? (
        <section className="panel">
          <h2>Login requerido</h2>
          <p className="muted">Introduce la contrasena de la UI para continuar.</p>
          <form onSubmit={onLoginSubmit}>
            <input
              type="password"
              value={loginPassword}
              onInput={e => setLoginPassword(e.currentTarget.value)}
              placeholder="Contrasena UI"
            />
            <div className="actions-row">
              <button className="btn btn-primary" type="submit">Entrar</button>
            </div>
          </form>
        </section>
      ) : content}
    </main>
  );
}
