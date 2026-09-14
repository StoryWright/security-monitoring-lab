import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import * as cli from '../src/monitor.js';
import {buildSite} from '../scripts/build-site.mjs';
await buildSite();const browser=await import('../_site/engine.js');
const raw=await readFile(new URL('../fixtures/events.jsonl',import.meta.url),'utf8');
const context=JSON.parse(await readFile(new URL('../fixtures/context.json',import.meta.url),'utf8'));
test('browser normalization and partial replay match the CLI engine',()=>{
 const loaded=browser.loadJSONL(raw);assert.deepEqual(loaded,cli.loadJSONL(raw));assert.equal(loaded.events.length,16);
 const events=loaded.events.sort((a,b)=>a.time-b.time||a.line-b.line);
 for(let n=0;n<=events.length;n++)assert.deepEqual(browser.correlate(events.slice(0,n),context),cli.correlate(events.slice(0,n),context));
});
test('browser approvals and rule settings change findings as expected',()=>{
 const {events}=browser.loadJSONL(raw);
 assert.equal(browser.correlate(events,context).incidents.length,3);
 assert.equal(browser.correlate(events,{approvedChanges:[]}).incidents.length,5);
 assert.equal(browser.correlate(events,{...context,threshold:6}).incidents.length,2);
 const quiet=events.filter(e=>e.agent==='lab-win-02');
 assert.equal(browser.correlate(quiet,context).incidents.length,0);
 assert.equal(browser.correlate(quiet,{...context,windowSeconds:1800}).incidents.length,1);
});
test('browser replay requires explicit IDs and rejects bad IPs',()=>{
 const first=JSON.parse(raw.split('\n')[0]);delete first.id;
 const noId=browser.loadJSONL(JSON.stringify(first));assert.equal(noId.errorCount,1);assert.match(noId.errors[0].reason,/explicit event ID/);
 first.id='invalid-ip';first.data.win.eventdata.ipAddress='999.0.0.1';assert.equal(browser.loadJSONL(JSON.stringify(first)).errorCount,1);
});
