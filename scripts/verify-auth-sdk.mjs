#!/usr/bin/env node
// Import validation only: never initialize a client or read provider credentials.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

try {
  const source = path.resolve(process.argv[2]);
  const installed = path.resolve(process.argv[3] || source);
  const manifest = JSON.parse(fs.readFileSync(path.join(source, 'auth/package.json'), 'utf8'));
  const lock = JSON.parse(fs.readFileSync(path.join(source, 'auth/package-lock.json'), 'utf8'));
  const expected = manifest.dependencies['@1password/sdk'];
  if (!/^\d+\.\d+\.\d+$/.test(expected) || lock.packages['node_modules/@1password/sdk'].version !== expected) throw new Error();
  for (const name of ['sdk', 'sdk-core']) {
    const actual = JSON.parse(fs.readFileSync(path.join(installed, 'auth/node_modules/@1password', name, 'package.json'), 'utf8'));
    if (actual.version !== lock.packages[`node_modules/@1password/${name}`].version) throw new Error();
  }
  const require = createRequire(path.join(installed, 'auth/package.json'));
  const sdk = require('@1password/sdk');
  const core = require('@1password/sdk-core');
  // Loading sdk-core instantiates its shipped WASM module. No authentication
  // or network call occurs until a client is explicitly created.
  if (typeof sdk.createClient !== 'function' || typeof core.init_client !== 'function') throw new Error();
} catch {
  console.error('The pinned authentication SDK or its runtime is missing or invalid.');
  process.exitCode = 1;
}
