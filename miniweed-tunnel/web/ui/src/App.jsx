import { useEffect, useMemo, useState } from 'preact/hooks';
import {
  addPubkey,
  createBackup,
  getAuthStatus,
  getConfig,
  getKillSwitchScript,
  getPubkeys,
  getSessions,
  getStatus,
  getVpsSetupScript,
  getVpsTargets,
  keygen,
  login,
  logout,
  refreshHealth,
  removePubkey,
  restoreBackup,
  revokeSession,
  rotateConfirm,
  rotatePrepare,
  saveConfig,
  setPassword,
  triggerFailover
} from './api.js';

const TAB_ITEMS = [
  { key: 'dashboard', label: 'Panel' },
  { key: 'services', label: 'Servicios' },
  { key: 'config', label: 'Configuracion' },
  { key: 'vps', label: 'Setup VPS' },
  { key: 'optional', label: 'Configuracion opcional' }
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
  const [vpsTargets, setVpsTargets] = useState(null);
  const [activeVpsId, setActiveVpsId] = useState('');
  const [vpsBusy, setVpsBusy] = useState('');
  const [healthBusy, setHealthBusy] = useState(false);
  // Gating de sesión: 'loading' | 'login' | 'ready'
  const [gate, setGate] = useState('loading');
  const [authStatus, setAuthStatus] = useState({ hasPassword: false, authenticated: false });
  const [loginPassword, setLoginPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [sessions, setSessions] = useState(null);
  const [rotation, setRotation] = useState(null); // plan de rotación en curso
  const [rotationBusy, setRotationBusy] = useState(false);
  const [killSwitch, setKillSwitch] = useState(null);
  const [killSwitchBusy, setKillSwitchBusy] = useState(false);
  const [pubkeys, setPubkeys] = useState(null);
  const [newPubkeyName, setNewPubkeyName] = useState('');
  const [newPubkeyValue, setNewPubkeyValue] = useState('');
  const [pubkeyBusy, setPubkeyBusy] = useState(false);
  const [pwdCurrent, setPwdCurrent] = useState('');
  const [pwdNew, setPwdNew] = useState('');
  const [pwdBusy, setPwdBusy] = useState(false);
  const [backupPass, setBackupPass] = useState('');
  const [backupBusy, setBackupBusy] = useState(false);
  const [restorePass, setRestorePass] = useState('');
  const [restoreFile, setRestoreFile] = useState(null);
  const [restoreBusy, setRestoreBusy] = useState(false);

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

  async function loadVpsTargets() {
    try {
      const data = await getVpsTargets();
      setVpsTargets(Array.isArray(data?.targets) ? data.targets : []);
      setActiveVpsId(data?.activeVpsId || '');
    } catch (err) {
      setVpsTargets([]);
      setMessage({ text: err.message || 'No se pudieron cargar los VPS.', kind: 'error' });
    }
  }

  async function onFailover(targetId) {
    const label = targetId ? 'cambiar el VPS activo' : 'ejecutar failover automático';
    if (!window.confirm(`¿Seguro que quieres ${label}? El túnel se reconfigurará.`)) return;
    setVpsBusy(targetId || 'auto');
    setMessage({ text: '', kind: '' });
    try {
      const res = await triggerFailover(targetId);
      await loadVpsTargets();
      const to = res?.next?.name || res?.next?.id || res?.activeVpsId || '';
      setMessage({
        text: res?.switched === false
          ? 'No fue necesario cambiar de VPS.'
          : `VPS activo actualizado${to ? `: ${to}` : ''}.`,
        kind: 'success'
      });
    } catch (err) {
      setMessage({ text: err.message || 'No se pudo cambiar de VPS.', kind: 'error' });
    } finally {
      setVpsBusy('');
    }
  }

  async function onRefreshHealth() {
    setHealthBusy(true);
    setMessage({ text: '', kind: '' });
    try {
      await refreshHealth();
      await refreshConfigOnly();
      setMessage({ text: 'Estado de servicios actualizado.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'No se pudo actualizar el estado.', kind: 'error' });
    } finally {
      setHealthBusy(false);
    }
  }

  async function bootstrap() {
    try {
      setAuthStatus(await getAuthStatus());
    } catch {
      // status no disponible: seguimos, el gate lo decide la carga de config
    }
    try {
      await Promise.all([refreshConfigOnly(), refreshStatusOnly()]);
      setGate('ready');
    } catch (err) {
      if (err.status === 401) {
        setGate('login');
      } else {
        // Error no de auth (p.ej. backend caído): mostramos la app igual.
        setGate('ready');
        setMessage({ text: err.message || 'No se pudo cargar la configuración.', kind: 'error' });
      }
    }
  }

  async function onLogin(e) {
    if (e && e.preventDefault) e.preventDefault();
    setLoading(true);
    setMessage({ text: '', kind: '' });
    try {
      await login(loginPassword);
      setLoginPassword('');
      setGate('ready');
      setAuthStatus(s => ({ ...s, authenticated: true }));
      await refreshAll();
    } catch (err) {
      setMessage({ text: err.message || 'No se pudo iniciar sesión.', kind: 'error' });
    } finally {
      setLoading(false);
    }
  }

  async function onSetInitialPassword(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (loginPassword.length < 8) {
      setMessage({ text: 'La contraseña debe tener al menos 8 caracteres.', kind: 'error' });
      return;
    }
    if (loginPassword !== confirmPassword) {
      setMessage({ text: 'Las contraseñas no coinciden.', kind: 'error' });
      return;
    }
    setLoading(true);
    setMessage({ text: '', kind: '' });
    try {
      await setPassword(loginPassword);
      await login(loginPassword);
      setLoginPassword('');
      setConfirmPassword('');
      setGate('ready');
      setAuthStatus({ hasPassword: true, authenticated: true });
      await refreshAll();
    } catch (err) {
      setMessage({ text: err.message || 'No se pudo crear la contraseña.', kind: 'error' });
    } finally {
      setLoading(false);
    }
  }

  async function onLogout() {
    if (!window.confirm('¿Cerrar sesión?')) return;
    try {
      await logout();
    } catch {
      // ignoramos: igualmente volvemos al login
    }
    setAuthStatus(s => ({ ...s, authenticated: false }));
    setGate('login');
  }

  async function loadSessions() {
    try {
      const data = await getSessions();
      setSessions(Array.isArray(data?.sessions) ? data.sessions : []);
    } catch (err) {
      setSessions([]);
      setMessage({ text: err.message || 'No se pudieron cargar las sesiones.', kind: 'error' });
    }
  }

  async function onRevokeSession(id, isCurrent) {
    if (!window.confirm(isCurrent ? 'Esta es tu sesión actual. ¿Cerrarla?' : '¿Revocar esta sesión?')) return;
    try {
      await revokeSession(id);
      if (isCurrent) {
        setAuthStatus(s => ({ ...s, authenticated: false }));
        setGate('login');
        return;
      }
      await loadSessions();
      setMessage({ text: 'Sesión revocada.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'No se pudo revocar la sesión.', kind: 'error' });
    }
  }

  useEffect(() => {
    bootstrap();
  }, []);

  useEffect(() => {
    if (gate !== 'ready') return undefined;
    const timer = setInterval(refreshStatusOnly, 8000);
    return () => clearInterval(timer);
  }, [gate]);

  async function onRotatePrepare() {
    if (!window.confirm(
      'Se generarán claves nuevas y un script para el VPS. El túnel NO cambia hasta que ' +
      'ejecutes el script en el VPS y confirmes aquí. ¿Continuar?'
    )) return;
    setRotationBusy(true);
    setMessage({ text: '', kind: '' });
    try {
      const plan = await rotatePrepare();
      setRotation(plan);
      setMessage({ text: 'Plan de rotación creado. Ejecuta el script en el VPS y confirma.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'No se pudo preparar la rotación.', kind: 'error' });
    } finally {
      setRotationBusy(false);
    }
  }

  async function onRotateConfirm(apply) {
    if (!rotation?.planId) return;
    if (apply && !window.confirm('¿Aplicar las claves nuevas? Solo confirma si ya ejecutaste el script en el VPS.')) return;
    setRotationBusy(true);
    setMessage({ text: '', kind: '' });
    try {
      await rotateConfirm(rotation.planId, apply);
      setRotation(null);
      if (apply) await refreshConfigOnly();
      setMessage({ text: apply ? 'Claves rotadas correctamente.' : 'Rotación cancelada.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'No se pudo completar la rotación.', kind: 'error' });
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
      setMessage({ text: err.message || 'No se pudo generar el kill-switch.', kind: 'error' });
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

  async function loadPubkeys() {
    try {
      const data = await getPubkeys();
      setPubkeys(Array.isArray(data?.pubkeys) ? data.pubkeys : []);
    } catch (err) {
      setPubkeys([]);
      setMessage({ text: err.message || 'No se pudieron cargar las claves.', kind: 'error' });
    }
  }

  async function onAddPubkey(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (!newPubkeyName.trim() || !newPubkeyValue.trim()) return;
    setPubkeyBusy(true);
    setMessage({ text: '', kind: '' });
    try {
      await addPubkey(newPubkeyName.trim(), newPubkeyValue.trim());
      setNewPubkeyName('');
      setNewPubkeyValue('');
      await loadPubkeys();
      setMessage({ text: 'Clave añadida.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'No se pudo añadir la clave.', kind: 'error' });
    } finally {
      setPubkeyBusy(false);
    }
  }

  async function onRemovePubkey(id, name) {
    if (!window.confirm(`¿Revocar la clave "${name || id}"?`)) return;
    try {
      await removePubkey(id);
      await loadPubkeys();
      setMessage({ text: 'Clave revocada.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'No se pudo revocar la clave.', kind: 'error' });
    }
  }

  async function onChangePassword(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (pwdNew.length < 8) {
      setMessage({ text: 'La nueva contraseña debe tener al menos 8 caracteres.', kind: 'error' });
      return;
    }
    setPwdBusy(true);
    setMessage({ text: '', kind: '' });
    try {
      // Con sesión activa basta; enviamos currentPassword por si acaso.
      await setPassword(pwdNew, pwdCurrent || undefined);
      setPwdCurrent('');
      setPwdNew('');
      setMessage({ text: 'Contraseña actualizada. Se cerraron las demás sesiones.', kind: 'success' });
      await loadSessions();
    } catch (err) {
      setMessage({ text: err.message || 'No se pudo cambiar la contraseña.', kind: 'error' });
    } finally {
      setPwdBusy(false);
    }
  }

  async function onCreateBackup(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (backupPass.length < 12) {
      setMessage({ text: 'La passphrase del backup debe tener al menos 12 caracteres.', kind: 'error' });
      return;
    }
    setBackupBusy(true);
    setMessage({ text: '', kind: '' });
    try {
      const blob = await createBackup(backupPass, true);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `miniweed-backup-${Date.now()}.bak`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setBackupPass('');
      setMessage({ text: 'Backup descargado.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'No se pudo crear el backup.', kind: 'error' });
    } finally {
      setBackupBusy(false);
    }
  }

  async function onRestoreBackup(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (!restoreFile) {
      setMessage({ text: 'Selecciona un archivo de backup.', kind: 'error' });
      return;
    }
    if (restorePass.length < 12) {
      setMessage({ text: 'Introduce la passphrase del backup (mín. 12).', kind: 'error' });
      return;
    }
    if (!window.confirm('Restaurar sobrescribirá la configuración actual. ¿Continuar?')) return;
    setRestoreBusy(true);
    setMessage({ text: '', kind: '' });
    try {
      const buffer = await restoreFile.arrayBuffer();
      await restoreBackup(buffer, restorePass);
      setRestorePass('');
      setRestoreFile(null);
      await refreshAll();
      setMessage({ text: 'Backup restaurado correctamente.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'No se pudo restaurar el backup.', kind: 'error' });
    } finally {
      setRestoreBusy(false);
    }
  }

  useEffect(() => {
    if (gate !== 'ready') return;
    if (tab === 'vps') loadVpsScript();
    if (tab === 'optional') {
      loadVpsTargets();
      loadSessions();
      loadPubkeys();
    }
  }, [tab, vpsScriptWithCrowdsec, gate]);

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
    const svc = (cfg.services || [])[index];
    const name = svc?.name || svc?.subdomain || svc?.target || 'este servicio';
    if (!window.confirm(`¿Eliminar ${name}? Guarda para aplicar el cambio.`)) return;
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
    if (cfg.publicKey && !window.confirm(
      'Regenerar las claves invalidará la conexión actual con el VPS. ' +
      'Tendrás que volver a ejecutar el script en el VPS. ¿Continuar?'
    )) return;
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
                      <a href={`https://${host}`} target="_blank" rel="noopener noreferrer">{`https://${host}`}</a>
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
            <button className="btn btn-primary" onClick={onGenerateKeys} disabled={loading}>
              {cfg.publicKey ? 'Regenerar claves' : 'Generar claves'}
            </button>
          </div>
          {cfg.publicKey ? (
            <div className="rotate-box">
              <h3>Rotación segura de claves</h3>
              <p className="muted">
                A diferencia de «Regenerar», la rotación no corta el túnel: genera claves
                nuevas y un script para el VPS, y solo las aplica cuando confirmas.
              </p>
              {!rotation ? (
                <div className="actions-row">
                  <button className="btn" onClick={onRotatePrepare} disabled={rotationBusy}>
                    {rotationBusy ? 'Preparando…' : 'Iniciar rotación'}
                  </button>
                </div>
              ) : (
                <>
                  <p className="muted">
                    Nueva huella: <code>{rotation.nextPublicKeyFingerprint || '—'}</code>
                    {rotation.target?.ip ? ` · VPS ${rotation.target.name || rotation.target.id} (${rotation.target.ip})` : ''}
                  </p>
                  <ol className="steps">
                    <li>Ejecuta este script como root en el VPS.</li>
                    <li>Cuando termine, pulsa «Confirmar y aplicar».</li>
                  </ol>
                  <pre className="code-box">{rotation.script}</pre>
                  <p className="muted">SHA-256: <code>{rotation.scriptSha256 || '-'}</code></p>
                  <div className="actions-row">
                    <button className="btn" onClick={() => downloadText('miniweed-rotate.sh', rotation.script)}>Descargar .sh</button>
                    <button className="btn btn-primary" onClick={() => onRotateConfirm(true)} disabled={rotationBusy}>
                      {rotationBusy ? 'Aplicando…' : 'Confirmar y aplicar'}
                    </button>
                    <button className="btn btn-danger" onClick={() => onRotateConfirm(false)} disabled={rotationBusy}>Cancelar</button>
                  </div>
                </>
              )}
            </div>
          ) : null}
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

  function renderVpsHealth(health) {
    if (!health) return <span className="health-pill">Sin datos</span>;
    if (health.ok) return <span className="health-pill ok">Saludable</span>;
    return <span className="health-pill error">{health.message || 'Sin conexión'}</span>;
  }

  function renderOptionalConfig() {
    return (
      <>
        <section className="panel">
          <h2>Failover y VPS múltiples</h2>
          <p className="muted">
            Estado de los VPS candidatos. Puedes forzar el VPS activo o lanzar un
            failover automático al candidato saludable de mayor prioridad.
          </p>
          <div className="actions-row">
            <button className="btn" onClick={loadVpsTargets} disabled={Boolean(vpsBusy)}>Actualizar estado</button>
            <button
              className="btn btn-primary"
              onClick={() => onFailover('')}
              disabled={Boolean(vpsBusy)}
            >
              {vpsBusy === 'auto' ? 'Evaluando…' : 'Failover automático'}
            </button>
          </div>

          {vpsTargets === null ? (
            <p className="muted">Cargando VPS…</p>
          ) : vpsTargets.length === 0 ? (
            <div className="alert alert-info">
              No hay VPS configurados. Añade la IP y la clave del VPS en Configuración.
            </div>
          ) : (
            <div className="vps-list">
              {vpsTargets.map(t => {
                const isActive = t.id === activeVpsId;
                return (
                  <div key={t.id} className={`vps-row ${isActive ? 'active' : ''}`}>
                    <div className="vps-row-main">
                      <strong>{t.name || t.id}</strong>
                      {isActive ? <span className="duplicate-badge">activo</span> : null}
                      <span className="muted">{t.ip || 'sin IP'}:{t.port || 51820}</span>
                    </div>
                    <div className="vps-row-meta">
                      {renderVpsHealth(t.health)}
                      <span className="muted">prioridad {typeof t.priority === 'number' ? t.priority : '—'}</span>
                      <button
                        className="btn"
                        disabled={isActive || Boolean(vpsBusy) || !t.enabled || !t.ip || !t.pubKey}
                        onClick={() => onFailover(t.id)}
                      >
                        {vpsBusy === t.id ? 'Cambiando…' : 'Activar'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        <section className="panel">
          <h2>Kill-switch de emergencia</h2>
          <p className="muted">
            Script para detener WireGuard y bloquear el puerto UDP en el VPS si necesitas
            cortar el túnel de inmediato. Ejecútalo como root en el VPS.
          </p>
          <div className="actions-row">
            <button className="btn" onClick={onLoadKillSwitch} disabled={killSwitchBusy}>
              {killSwitchBusy ? 'Generando…' : 'Generar kill-switch'}
            </button>
            {killSwitch ? (
              <button className="btn" onClick={() => downloadText(killSwitch.filename || 'miniweed-killswitch.sh', killSwitch.script)}>
                Descargar .sh
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

        <section className="panel">
          <h2>Sesiones activas</h2>
          <p className="muted">Dispositivos con sesión iniciada. Puedes revocar cualquiera.</p>
          <div className="actions-row">
            <button className="btn" onClick={loadSessions}>Actualizar</button>
          </div>
          {sessions === null ? (
            <p className="muted">Cargando sesiones…</p>
          ) : sessions.length === 0 ? (
            <p className="muted">Sin sesiones activas (o la autenticación está deshabilitada).</p>
          ) : (
            <div className="vps-list">
              {sessions.map(s => (
                <div key={s.id} className={`vps-row ${s.current ? 'active' : ''}`}>
                  <div className="vps-row-main">
                    <strong>{s.source || 'sesión'}</strong>
                    {s.current ? <span className="duplicate-badge">esta sesión</span> : null}
                    <span className="muted">{s.ip || 'ip desconocida'}</span>
                  </div>
                  <div className="vps-row-meta">
                    <span className="muted">expira {new Date(s.expiresAt).toLocaleString()}</span>
                    <button className="btn btn-danger" onClick={() => onRevokeSession(s.id, s.current)}>
                      {s.current ? 'Cerrar sesión' : 'Revocar'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="panel">
          <h2>Cambiar contraseña</h2>
          <form onSubmit={onChangePassword}>
            <label htmlFor="pwd-current">Contraseña actual (opcional si hay sesión)</label>
            <input id="pwd-current" type="password" autoComplete="current-password" value={pwdCurrent} onInput={e => setPwdCurrent(e.currentTarget.value)} />
            <label htmlFor="pwd-new">Nueva contraseña</label>
            <input id="pwd-new" type="password" autoComplete="new-password" value={pwdNew} onInput={e => setPwdNew(e.currentTarget.value)} />
            <p className="muted">Mínimo 8 caracteres. Al cambiarla se cerrarán las demás sesiones.</p>
            <div className="actions-row">
              <button className="btn btn-primary" type="submit" disabled={pwdBusy || !pwdNew}>
                {pwdBusy ? 'Guardando…' : 'Cambiar contraseña'}
              </button>
            </div>
          </form>
        </section>

        <section className="panel">
          <h2>Claves de acceso CLI</h2>
          <p className="muted">Claves públicas (ed25519) autorizadas para autenticación por línea de comandos.</p>
          <form onSubmit={onAddPubkey}>
            <label htmlFor="pk-name">Nombre</label>
            <input id="pk-name" value={newPubkeyName} onInput={e => setNewPubkeyName(e.currentTarget.value)} placeholder="laptop-cli" />
            <label htmlFor="pk-value">Clave pública</label>
            <input id="pk-value" value={newPubkeyValue} onInput={e => setNewPubkeyValue(e.currentTarget.value)} placeholder="ssh-ed25519 AAAA… o DER base64" />
            <div className="actions-row">
              <button className="btn" type="submit" disabled={pubkeyBusy || !newPubkeyName || !newPubkeyValue}>
                {pubkeyBusy ? 'Añadiendo…' : 'Añadir clave'}
              </button>
            </div>
          </form>
          {pubkeys === null ? (
            <p className="muted">Cargando claves…</p>
          ) : pubkeys.length === 0 ? (
            <p className="muted">Sin claves CLI registradas.</p>
          ) : (
            <div className="vps-list">
              {pubkeys.map(k => (
                <div key={k.id} className="vps-row">
                  <div className="vps-row-main">
                    <strong>{k.name || k.id}</strong>
                    <span className="muted">id {k.id}</span>
                  </div>
                  <div className="vps-row-meta">
                    {k.addedAt ? <span className="muted">añadida {new Date(k.addedAt).toLocaleDateString()}</span> : null}
                    <button className="btn btn-danger" onClick={() => onRemovePubkey(k.id, k.name)}>Revocar</button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="panel">
          <h2>Backup y restauración</h2>
          <p className="muted">Copia cifrada de tu configuración. Guarda la passphrase: sin ella el backup no se puede restaurar.</p>
          <form onSubmit={onCreateBackup}>
            <label htmlFor="backup-pass">Passphrase del backup (mín. 12)</label>
            <input id="backup-pass" type="password" value={backupPass} onInput={e => setBackupPass(e.currentTarget.value)} />
            <div className="actions-row">
              <button className="btn btn-primary" type="submit" disabled={backupBusy || backupPass.length < 12}>
                {backupBusy ? 'Generando…' : 'Descargar backup'}
              </button>
            </div>
          </form>
          <hr className="sep" />
          <form onSubmit={onRestoreBackup}>
            <label htmlFor="restore-file">Archivo de backup (.bak)</label>
            <input id="restore-file" type="file" accept=".bak" onChange={e => setRestoreFile(e.currentTarget.files?.[0] || null)} />
            <label htmlFor="restore-pass">Passphrase del backup</label>
            <input id="restore-pass" type="password" value={restorePass} onInput={e => setRestorePass(e.currentTarget.value)} />
            <div className="actions-row">
              <button className="btn btn-danger" type="submit" disabled={restoreBusy || !restoreFile}>
                {restoreBusy ? 'Restaurando…' : 'Restaurar'}
              </button>
            </div>
          </form>
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
            <button className="btn" onClick={onRefreshHealth} disabled={healthBusy}>
              {healthBusy ? 'Comprobando…' : 'Refrescar estado'}
            </button>
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

  function renderLogin() {
    const firstRun = !authStatus.hasPassword;
    return (
      <main className="shell">
        <header className="hero">
          <div>
            <h1>Umbrel Tunnel</h1>
            <p className="muted">Canal seguro para infraestructura soberana.</p>
          </div>
        </header>
        <div aria-live="polite" role="status">
          {message.text ? <div className={`alert ${message.kind === 'error' ? 'alert-error' : 'alert-success'}`}>{message.text}</div> : null}
        </div>
        <section className="panel">
          <h2>{firstRun ? 'Crea una contraseña' : 'Iniciar sesión'}</h2>
          <form onSubmit={firstRun ? onSetInitialPassword : onLogin}>
            <label htmlFor="login-password">Contraseña</label>
            <input
              id="login-password"
              type="password"
              autoComplete={firstRun ? 'new-password' : 'current-password'}
              value={loginPassword}
              onInput={e => setLoginPassword(e.currentTarget.value)}
            />
            {firstRun ? (
              <>
                <label htmlFor="login-confirm">Repite la contraseña</label>
                <input
                  id="login-confirm"
                  type="password"
                  autoComplete="new-password"
                  value={confirmPassword}
                  onInput={e => setConfirmPassword(e.currentTarget.value)}
                />
                <p className="muted">Mínimo 8 caracteres. Será necesaria para acceder al panel.</p>
              </>
            ) : null}
            <div className="actions-row">
              <button className="btn btn-primary" type="submit" disabled={loading || !loginPassword}>
                {loading ? 'Procesando…' : (firstRun ? 'Crear y entrar' : 'Entrar')}
              </button>
            </div>
          </form>
        </section>
      </main>
    );
  }

  if (gate === 'loading') {
    return (
      <main className="shell">
        <div className="muted">Cargando…</div>
      </main>
    );
  }

  if (gate === 'login') {
    return renderLogin();
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
        <div className="hero-right">
          <div className={`status-badge ${statusBadge.cls}`}>
            <span className="dot" />
            <span>{statusBadge.text}</span>
          </div>
          {authStatus.authenticated ? (
            <button className="btn btn-logout" onClick={onLogout}>Salir</button>
          ) : null}
        </div>
      </header>

      <nav className="tabbar" role="tablist" aria-label="Secciones">
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
      {loading ? <div className="muted">Cargando...</div> : null}
      {content}
    </main>
  );
}
