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
  { key: 'dashboard', label: 'Dashboard' },
  { key: 'services', label: 'Services' },
  { key: 'config', label: 'Configuration' },
  { key: 'vps', label: 'VPS Setup' },
  { key: 'optional', label: 'Advanced' }
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
  const [vpsTargets, setVpsTargets] = useState(null);
  const [activeVpsId, setActiveVpsId] = useState('');
  const [vpsBusy, setVpsBusy] = useState('');
  const [healthBusy, setHealthBusy] = useState(false);
  // Session gating: 'loading' | 'login' | 'ready'
  const [gate, setGate] = useState('loading');
  const [authStatus, setAuthStatus] = useState({ hasPassword: false, authenticated: false });
  const [loginPassword, setLoginPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [sessions, setSessions] = useState(null);
  const [rotation, setRotation] = useState(null); // rotation plan in progress
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

  async function loadVpsTargets() {
    try {
      const data = await getVpsTargets();
      setVpsTargets(Array.isArray(data?.targets) ? data.targets : []);
      setActiveVpsId(data?.activeVpsId || '');
    } catch (err) {
      setVpsTargets([]);
      setMessage({ text: err.message || 'Could not load VPS targets.', kind: 'error' });
    }
  }

  async function onFailover(targetId) {
    const label = targetId ? 'change the active VPS' : 'run automatic failover';
    if (!window.confirm(`Are you sure you want to ${label}? The tunnel will be reconfigured.`)) return;
    setVpsBusy(targetId || 'auto');
    setMessage({ text: '', kind: '' });
    try {
      const res = await triggerFailover(targetId);
      await loadVpsTargets();
      const to = res?.next?.name || res?.next?.id || res?.activeVpsId || '';
      setMessage({
        text: res?.switched === false
          ? 'No VPS switch was needed.'
          : `Active VPS updated${to ? `: ${to}` : ''}.`,
        kind: 'success'
      });
    } catch (err) {
      setMessage({ text: err.message || 'Could not switch VPS.', kind: 'error' });
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
      setMessage({ text: 'Service status updated.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'Could not refresh status.', kind: 'error' });
    } finally {
      setHealthBusy(false);
    }
  }

  async function bootstrap() {
    try {
      setAuthStatus(await getAuthStatus());
    } catch {
      // status unavailable: continue, the gate is decided by the config load
    }
    try {
      await Promise.all([refreshConfigOnly(), refreshStatusOnly()]);
      setGate('ready');
    } catch (err) {
      if (err.status === 401) {
        setGate('login');
      } else {
        // Non-auth error (e.g. backend down): show the app anyway.
        setGate('ready');
        setMessage({ text: err.message || 'Could not load configuration.', kind: 'error' });
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
      setMessage({ text: err.message || 'Could not sign in.', kind: 'error' });
    } finally {
      setLoading(false);
    }
  }

  async function onSetInitialPassword(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (loginPassword.length < 8) {
      setMessage({ text: 'The password must be at least 8 characters.', kind: 'error' });
      return;
    }
    if (loginPassword !== confirmPassword) {
      setMessage({ text: 'Passwords do not match.', kind: 'error' });
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
      setMessage({ text: err.message || 'Could not create the password.', kind: 'error' });
    } finally {
      setLoading(false);
    }
  }

  async function onLogout() {
    if (!window.confirm('Sign out?')) return;
    try {
      await logout();
    } catch {
      // ignore: we go back to login regardless
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
      setMessage({ text: err.message || 'Could not load sessions.', kind: 'error' });
    }
  }

  async function onRevokeSession(id, isCurrent) {
    if (!window.confirm(isCurrent ? 'This is your current session. Close it?' : 'Revoke this session?')) return;
    try {
      await revokeSession(id);
      if (isCurrent) {
        setAuthStatus(s => ({ ...s, authenticated: false }));
        setGate('login');
        return;
      }
      await loadSessions();
      setMessage({ text: 'Session revoked.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'Could not revoke the session.', kind: 'error' });
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

  async function loadPubkeys() {
    try {
      const data = await getPubkeys();
      setPubkeys(Array.isArray(data?.pubkeys) ? data.pubkeys : []);
    } catch (err) {
      setPubkeys([]);
      setMessage({ text: err.message || 'Could not load keys.', kind: 'error' });
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
      setMessage({ text: 'Key added.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'Could not add the key.', kind: 'error' });
    } finally {
      setPubkeyBusy(false);
    }
  }

  async function onRemovePubkey(id, name) {
    if (!window.confirm(`Revoke the key "${name || id}"?`)) return;
    try {
      await removePubkey(id);
      await loadPubkeys();
      setMessage({ text: 'Key revoked.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'Could not revoke the key.', kind: 'error' });
    }
  }

  async function onChangePassword(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (pwdNew.length < 8) {
      setMessage({ text: 'The new password must be at least 8 characters.', kind: 'error' });
      return;
    }
    setPwdBusy(true);
    setMessage({ text: '', kind: '' });
    try {
      // An active session is enough; we send currentPassword just in case.
      await setPassword(pwdNew, pwdCurrent || undefined);
      setPwdCurrent('');
      setPwdNew('');
      setMessage({ text: 'Password updated. All other sessions were signed out.', kind: 'success' });
      await loadSessions();
    } catch (err) {
      setMessage({ text: err.message || 'Could not change the password.', kind: 'error' });
    } finally {
      setPwdBusy(false);
    }
  }

  async function onCreateBackup(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (backupPass.length < 12) {
      setMessage({ text: 'The backup passphrase must be at least 12 characters.', kind: 'error' });
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
      setMessage({ text: 'Backup downloaded.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'Could not create the backup.', kind: 'error' });
    } finally {
      setBackupBusy(false);
    }
  }

  async function onRestoreBackup(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (!restoreFile) {
      setMessage({ text: 'Select a backup file.', kind: 'error' });
      return;
    }
    if (restorePass.length < 12) {
      setMessage({ text: 'Enter the backup passphrase (min. 12).', kind: 'error' });
      return;
    }
    if (!window.confirm('Restoring will overwrite the current configuration. Continue?')) return;
    setRestoreBusy(true);
    setMessage({ text: '', kind: '' });
    try {
      const buffer = await restoreFile.arrayBuffer();
      await restoreBackup(buffer, restorePass);
      setRestorePass('');
      setRestoreFile(null);
      await refreshAll();
      setMessage({ text: 'Backup restored successfully.', kind: 'success' });
    } catch (err) {
      setMessage({ text: err.message || 'Could not restore the backup.', kind: 'error' });
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

  function renderVpsHealth(health) {
    if (!health) return <span className="health-pill">No data</span>;
    if (health.ok) return <span className="health-pill ok">Healthy</span>;
    return <span className="health-pill error">{health.message || 'No connection'}</span>;
  }

  function renderOptionalConfig() {
    return (
      <>
        <section className="panel">
          <h2>Failover & multiple VPS</h2>
          <p className="muted">
            Status of candidate VPS targets. You can force the active VPS or trigger automatic
            failover to the healthy candidate with the highest priority.
          </p>
          <div className="actions-row">
            <button className="btn" onClick={loadVpsTargets} disabled={Boolean(vpsBusy)}>Refresh status</button>
            <button
              className="btn btn-primary"
              onClick={() => onFailover('')}
              disabled={Boolean(vpsBusy)}
            >
              {vpsBusy === 'auto' ? 'Evaluating…' : 'Automatic failover'}
            </button>
          </div>

          {vpsTargets === null ? (
            <p className="muted">Loading VPS…</p>
          ) : vpsTargets.length === 0 ? (
            <div className="alert alert-info">
              No VPS configured. Add the VPS IP and key in Configuration.
            </div>
          ) : (
            <div className="vps-list">
              {vpsTargets.map(t => {
                const isActive = t.id === activeVpsId;
                return (
                  <div key={t.id} className={`vps-row ${isActive ? 'active' : ''}`}>
                    <div className="vps-row-main">
                      <strong>{t.name || t.id}</strong>
                      {isActive ? <span className="duplicate-badge">active</span> : null}
                      <span className="muted">{t.ip || 'no IP'}:{t.port || 51820}</span>
                    </div>
                    <div className="vps-row-meta">
                      {renderVpsHealth(t.health)}
                      <span className="muted">priority {typeof t.priority === 'number' ? t.priority : '—'}</span>
                      <button
                        className="btn"
                        disabled={isActive || Boolean(vpsBusy) || !t.enabled || !t.ip || !t.pubKey}
                        onClick={() => onFailover(t.id)}
                      >
                        {vpsBusy === t.id ? 'Switching…' : 'Activate'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

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

        <section className="panel">
          <h2>Active sessions</h2>
          <p className="muted">Devices with an active session. You can revoke any of them.</p>
          <div className="actions-row">
            <button className="btn" onClick={loadSessions}>Refresh</button>
          </div>
          {sessions === null ? (
            <p className="muted">Loading sessions…</p>
          ) : sessions.length === 0 ? (
            <p className="muted">No active sessions (or authentication is disabled).</p>
          ) : (
            <div className="vps-list">
              {sessions.map(s => (
                <div key={s.id} className={`vps-row ${s.current ? 'active' : ''}`}>
                  <div className="vps-row-main">
                    <strong>{s.source || 'session'}</strong>
                    {s.current ? <span className="duplicate-badge">this session</span> : null}
                    <span className="muted">{s.ip || 'unknown ip'}</span>
                  </div>
                  <div className="vps-row-meta">
                    <span className="muted">expires {new Date(s.expiresAt).toLocaleString()}</span>
                    <button className="btn btn-danger" onClick={() => onRevokeSession(s.id, s.current)}>
                      {s.current ? 'Sign out' : 'Revoke'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="panel">
          <h2>Change password</h2>
          <form onSubmit={onChangePassword}>
            <label htmlFor="pwd-current">Current password (optional if signed in)</label>
            <input id="pwd-current" type="password" autoComplete="current-password" value={pwdCurrent} onInput={e => setPwdCurrent(e.currentTarget.value)} />
            <label htmlFor="pwd-new">New password</label>
            <input id="pwd-new" type="password" autoComplete="new-password" value={pwdNew} onInput={e => setPwdNew(e.currentTarget.value)} />
            <p className="muted">Minimum 8 characters. Changing it signs out all other sessions.</p>
            <div className="actions-row">
              <button className="btn btn-primary" type="submit" disabled={pwdBusy || !pwdNew}>
                {pwdBusy ? 'Saving…' : 'Change password'}
              </button>
            </div>
          </form>
        </section>

        <section className="panel">
          <h2>CLI access keys</h2>
          <p className="muted">Public keys (ed25519) authorized for command-line authentication.</p>
          <form onSubmit={onAddPubkey}>
            <label htmlFor="pk-name">Name</label>
            <input id="pk-name" value={newPubkeyName} onInput={e => setNewPubkeyName(e.currentTarget.value)} placeholder="laptop-cli" />
            <label htmlFor="pk-value">Public key</label>
            <input id="pk-value" value={newPubkeyValue} onInput={e => setNewPubkeyValue(e.currentTarget.value)} placeholder="ssh-ed25519 AAAA… or DER base64" />
            <div className="actions-row">
              <button className="btn" type="submit" disabled={pubkeyBusy || !newPubkeyName || !newPubkeyValue}>
                {pubkeyBusy ? 'Adding…' : 'Add key'}
              </button>
            </div>
          </form>
          {pubkeys === null ? (
            <p className="muted">Loading keys…</p>
          ) : pubkeys.length === 0 ? (
            <p className="muted">No CLI keys registered.</p>
          ) : (
            <div className="vps-list">
              {pubkeys.map(k => (
                <div key={k.id} className="vps-row">
                  <div className="vps-row-main">
                    <strong>{k.name || k.id}</strong>
                    <span className="muted">id {k.id}</span>
                  </div>
                  <div className="vps-row-meta">
                    {k.addedAt ? <span className="muted">added {new Date(k.addedAt).toLocaleDateString()}</span> : null}
                    <button className="btn btn-danger" onClick={() => onRemovePubkey(k.id, k.name)}>Revoke</button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="panel">
          <h2>Backup & restore</h2>
          <p className="muted">Encrypted copy of your configuration. Keep the passphrase: without it the backup cannot be restored.</p>
          <form onSubmit={onCreateBackup}>
            <label htmlFor="backup-pass">Backup passphrase (min. 12)</label>
            <input id="backup-pass" type="password" value={backupPass} onInput={e => setBackupPass(e.currentTarget.value)} />
            <div className="actions-row">
              <button className="btn btn-primary" type="submit" disabled={backupBusy || backupPass.length < 12}>
                {backupBusy ? 'Generating…' : 'Download backup'}
              </button>
            </div>
          </form>
          <hr className="sep" />
          <form onSubmit={onRestoreBackup}>
            <label htmlFor="restore-file">Backup file (.bak)</label>
            <input id="restore-file" type="file" accept=".bak" onChange={e => setRestoreFile(e.currentTarget.files?.[0] || null)} />
            <label htmlFor="restore-pass">Backup passphrase</label>
            <input id="restore-pass" type="password" value={restorePass} onInput={e => setRestorePass(e.currentTarget.value)} />
            <div className="actions-row">
              <button className="btn btn-danger" type="submit" disabled={restoreBusy || !restoreFile}>
                {restoreBusy ? 'Restoring…' : 'Restore'}
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

  function renderLogin() {
    const firstRun = !authStatus.hasPassword;
    return (
      <main className="shell">
        <header className="hero">
          <div>
            <h1>Umbrel Tunnel</h1>
            <p className="muted">Secure channel for sovereign infrastructure.</p>
          </div>
        </header>
        <div aria-live="polite" role="status">
          {message.text ? <div className={`alert ${message.kind === 'error' ? 'alert-error' : 'alert-success'}`}>{message.text}</div> : null}
        </div>
        <section className="panel">
          <h2>{firstRun ? 'Create a password' : 'Sign in'}</h2>
          <form onSubmit={firstRun ? onSetInitialPassword : onLogin}>
            <label htmlFor="login-password">Password</label>
            <input
              id="login-password"
              type="password"
              autoComplete={firstRun ? 'new-password' : 'current-password'}
              value={loginPassword}
              onInput={e => setLoginPassword(e.currentTarget.value)}
            />
            {firstRun ? (
              <>
                <label htmlFor="login-confirm">Repeat the password</label>
                <input
                  id="login-confirm"
                  type="password"
                  autoComplete="new-password"
                  value={confirmPassword}
                  onInput={e => setConfirmPassword(e.currentTarget.value)}
                />
                <p className="muted">Minimum 8 characters. It will be required to access the dashboard.</p>
              </>
            ) : null}
            <div className="actions-row">
              <button className="btn btn-primary" type="submit" disabled={loading || !loginPassword}>
                {loading ? 'Processing…' : (firstRun ? 'Create and enter' : 'Sign in')}
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
        <div className="muted">Loading…</div>
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
          <p className="muted">Secure channel for sovereign infrastructure.</p>
        </div>
        <div className="hero-right">
          <div className={`status-badge ${statusBadge.cls}`}>
            <span className="dot" />
            <span>{statusBadge.text}</span>
          </div>
          {authStatus.authenticated ? (
            <button className="btn btn-logout" onClick={onLogout}>Sign out</button>
          ) : null}
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
