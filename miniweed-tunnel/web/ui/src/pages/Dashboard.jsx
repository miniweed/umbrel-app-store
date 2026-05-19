export function Dashboard({ status, error }) {
  return (
    <section className="panel">
      <h2>Dashboard</h2>
      {error ? <p className="text-error">{error}</p> : null}
      <p className="muted">Connected: {status.connected ? 'yes' : 'no'}</p>
      <pre className="code-box">{status.raw || 'No status yet'}</pre>
    </section>
  );
}
