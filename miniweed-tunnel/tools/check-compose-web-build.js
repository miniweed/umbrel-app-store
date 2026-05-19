#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

function fail(msg) {
  process.stderr.write(`[compose-check] ${msg}\n`);
  process.exit(1);
}

const root = path.resolve(__dirname, '..');
const composePath = path.join(root, 'docker-compose.yml');
const manifestPath = path.join(root, 'umbrel-app.yml');

if (!fs.existsSync(composePath)) fail(`missing ${composePath}`);
if (!fs.existsSync(manifestPath)) fail(`missing ${manifestPath}`);

const compose = fs.readFileSync(composePath, 'utf8');
const manifest = fs.readFileSync(manifestPath, 'utf8');

const versionMatch = manifest.match(/^version:\s*"([^"]+)"/m);
if (!versionMatch) fail('could not parse version from umbrel-app.yml');
const appVersion = versionMatch[1].trim();

const webBlockMatch = compose.match(/(?:^|\n)\s{2}web:\n([\s\S]*?)(?:\n\s{2}[a-zA-Z0-9_-]+:|$)/);
if (!webBlockMatch) fail('could not find web service block in docker-compose.yml');
const webBlock = webBlockMatch[1];

if (!/\s+build:\s*(?:\n\s+context:\s*\.\/web\s*(?:\n|$)|\.\/web\s*(?:\n|$))/.test(webBlock)) {
  fail('web service must use local build context ./web');
}

if (/\n\s+image:\s+ghcr\.io\/miniweed\/umbrel-tunnel-web:[^\s]+@sha256:/m.test(webBlock)) {
  fail('web service image must not be pinned by digest when using local build');
}

const imageMatch = webBlock.match(/\n\s+image:\s+ghcr\.io\/miniweed\/umbrel-tunnel-web:([^\s]+)\s*(?:\n|$)/m);
if (imageMatch) {
  const imageVersion = imageMatch[1].trim();
  if (imageVersion !== appVersion) {
    fail(`web image tag (${imageVersion}) must match umbrel-app version (${appVersion})`);
  }
}

process.stdout.write('[compose-check] OK\n');
