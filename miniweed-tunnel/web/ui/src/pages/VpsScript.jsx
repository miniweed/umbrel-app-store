export function VpsScript({ scriptMeta, error }) {
  return (
    <section className="panel">
      <h2>VPS Script</h2>
      {error ? <p className="text-error">{error}</p> : null}
      {scriptMeta ? (
        <>
          <p className="muted">SHA-256: {scriptMeta.sha256}</p>
          <p className="muted">
            Target: {scriptMeta.vps?.name || scriptMeta.vps?.id || 'n/a'} ({scriptMeta.vps?.ip || 'n/a'})
          </p>
          <pre className="code-box">{scriptMeta.script}</pre>
        </>
      ) : (
        <p className="muted">No script available.</p>
      )}
    </section>
  );
}
