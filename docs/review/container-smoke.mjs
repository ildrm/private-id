// Intended for the built review container; synthetic in-memory API/static smoke.
import assert from 'node:assert/strict';
import { buildApp } from '/app/dist/src/app.js';
import staticPlugin from '/app/node_modules/@fastify/static/index.js';
const app = await buildApp();
await app.register(staticPlugin, { root: '/app/web-dist', prefix: '/site/' });
try {
  const root = await app.inject('/');
  const health = await app.inject('/health');
  const site = await app.inject('/site/');
  const assets = [...site.body.matchAll(/(?:src|href)="(\/site\/assets\/[^\"]+)"/g)].map(m => m[1]);
  assert.equal(root.statusCode, 302); assert.equal(health.statusCode, 200); assert.equal(site.statusCode, 200); assert.ok(assets.length >= 2);
  for (const asset of assets) assert.equal((await app.inject(asset)).statusCode, 200);
  const account = await app.inject({ method: 'POST', url: '/accounts', payload: { email: 'container@review.test', password: 'synthetic container review password' } });
  assert.equal(account.statusCode, 200);
  console.log(JSON.stringify({ node: process.version, uid: process.getuid(), rootRedirect: root.statusCode, health: health.statusCode, site: site.statusCode, assetsLoaded: assets.length, syntheticRegistration: account.statusCode, persistenceAdapter: 'memory', productionDatabaseEntrypoint: false }, null, 2));
} finally { await app.close(); }
