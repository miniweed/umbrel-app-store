#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const specPath = path.resolve(__dirname, '..', 'api-spec', 'openapi.json');

if (!fs.existsSync(specPath)) {
  process.stderr.write(`Missing ${specPath}. Run npm run api:spec first.\n`);
  process.exit(1);
}

let spec;
try {
  spec = JSON.parse(fs.readFileSync(specPath, 'utf8'));
} catch (err) {
  process.stderr.write(`Invalid JSON in ${specPath}: ${err.message}\n`);
  process.exit(1);
}

const requiredPaths = [
  '/api/config',
  '/api/status',
  '/api/keygen',
  '/api/vps/targets',
  '/api/vps/failover',
  '/api/vps-setup-script',
  '/api/auth/login',
  '/api/auth/password',
  '/api/auth/pubkeys',
  '/api/auth/sessions',
  '/api/health/refresh'
];

const requiredSchemas = [
  'RotatePrepareRequest',
  'RotateConfirmRequest',
  'VpsTarget',
  'VpsFailoverResponse',
  'VpsSetupScriptResponse'
];

const missingPaths = requiredPaths.filter(p => !spec.paths || !spec.paths[p]);
const schemas = spec.components && spec.components.schemas ? spec.components.schemas : {};
const missingSchemas = requiredSchemas.filter(name => !schemas[name]);

if (missingPaths.length || missingSchemas.length) {
  if (missingPaths.length) {
    process.stderr.write(`Missing paths: ${missingPaths.join(', ')}\n`);
  }
  if (missingSchemas.length) {
    process.stderr.write(`Missing schemas: ${missingSchemas.join(', ')}\n`);
  }
  process.exit(1);
}

process.stdout.write('OpenAPI contract check OK\n');
