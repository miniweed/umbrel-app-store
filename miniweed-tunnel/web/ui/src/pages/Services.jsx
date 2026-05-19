export function Services({ config }) {
  const services = Array.isArray(config.services) ? config.services : [];
  return (
    <section className="panel">
      <h2>Services</h2>
      {services.length === 0 ? (
        <p className="muted">No configured services.</p>
      ) : (
        <ul className="simple-list">
          {services.map(service => (
            <li key={`${service.subdomain}-${service.target}`}>
              <strong>{service.name || service.subdomain || 'service'}</strong>
              <span className="muted"> {service.target}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
