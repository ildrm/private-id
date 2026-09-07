/** Component-render and Vite configuration probes; not a browser E2E test. */
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import ts from 'typescript';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import config from '../../vite.config.ts';

const source = readFileSync(new URL('../../web/src/main.tsx', import.meta.url), 'utf8').replace(/^import.*$/gm, '').replace(/^createRoot.*$/gm, '');
const output = ts.transpileModule(source, { compilerOptions: { jsx: ts.JsxEmit.React, target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
let hook = 0;
const oldSessionList = [{ id: 'synthetic-session-id', expiresAt: '2026-09-07T12:00:00Z' }];
const ctx = vm.createContext({ React, useState: () => [hook++ === 0 ? oldSessionList : '', () => {}], useEffect: () => {}, localStorage: { getItem: () => '' }, console });
vm.runInContext(output, ctx);
const element = vm.runInContext("CustomerSection({section:'Billing',session:{email:'review@test',roles:['USER']},token:''})", ctx);
let error: unknown;
try { renderToStaticMarkup(element); } catch (e) { error = e; }
assert.match(String(error), /map/);
const proxy = (config as any).server.proxy;
const missing = ['/customers/me', '/credentials', '/proof-requests', '/sessions', '/privacy-dashboard', '/verifier-applications', '/trust-registry', '/federation/proof'].filter(path => !Object.keys(proxy).some(prefix => path.startsWith(prefix)));
assert.equal(missing.length, 8);
console.log(JSON.stringify({ renderProbe: { scenario: 'Sessions data retained during navigation to Billing', componentRenderThrows: String(error), browserE2E: false }, developmentProxy: { missingRequiredPaths: missing } }, null, 2));
