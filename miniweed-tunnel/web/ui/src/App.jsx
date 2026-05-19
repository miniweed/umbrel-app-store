import { useEffect, useMemo, useState } from 'preact/hooks';
import { getJson } from './api.js';
import { Dashboard } from './pages/Dashboard.jsx';
import { Services } from './pages/Services.jsx';
import { Setup } from './pages/Setup.jsx';
import { VpsScript } from './pages/VpsScript.jsx';

const TABS = ['dashboard', 'services', 'setup', 'script'];

export function App() {
  const [tab, setTab] = useState('dashboard');
  const [config, setConfig] = useState({});
  const [status, setStatus] = useState({ connected: false, raw: '' });
  const [scriptMeta, setScriptMeta] = useState(null);
  const [error, setError] = useState('');

  async function refresh() {
    try {
      const [cfg, stat] = await Promise.all([getJson('/api/config'), getJson('/api/status')]);
      setConfig(cfg);
      setStatus(stat);

      const activeId = cfg.activeVpsId || '';
      const scriptPath = activeId ? `/api/vps-setup-script?vpsId=${encodeURIComponent(activeId)}` : '/api/vps-setup-script';
      const script = await getJson(scriptPath).catch(() => null);
      setScriptMeta(script);
      setError('');
    } catch (err) {
      setError(err.message || 'Failed to load data');
    }
  }

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 8000);
    return () => clearInterval(timer);
  }, []);

  const content = useMemo(() => {
    if (tab === 'dashboard') return <Dashboard status={status} error={error} />;
    if (tab === 'services') return <Services config={config} />;
    if (tab === 'setup') return <Setup config={config} />;
    return <VpsScript scriptMeta={scriptMeta} error={error} />;
  }, [config, error, scriptMeta, status, tab]);

  return (
    <main className="shell">
      <header className="hero">
        <div>
          <h1>Umbrel Tunnel SPA</h1>
          <p className="muted">P3-16 scaffold with live API data.</p>
        </div>
        <button className="btn" onClick={refresh}>Refresh</button>
      </header>

      <nav className="tabbar">
        {TABS.map(name => (
          <button
            key={name}
            className={`tab ${tab === name ? 'active' : ''}`}
            onClick={() => setTab(name)}
          >
            {name}
          </button>
        ))}
      </nav>

      {content}
    </main>
  );
}
