export function Setup({ config }) {
  return (
    <section className="panel">
      <h2>Setup</h2>
      <p className="muted">Domain: {config.domain || 'not configured'}</p>
      <p className="muted">VPS: {config.vpsIp || 'not configured'}:{config.vpsPort || 51820}</p>
      <p className="muted">Email: {config.acmeEmail || 'not configured'}</p>
    </section>
  );
}
