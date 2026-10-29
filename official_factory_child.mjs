// Reviewed private offline entry. Never imports CLI/router/FromEnvironment/Pi/MCP.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { registerHooks } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve, sep } from 'node:path';

const root = dirname(fileURLToPath(import.meta.url));
const hash = b => createHash('sha256').update(b).digest('hex');
const lockBytes = readFileSync(resolve(root, 'OFFICIAL_SOURCE_LOCK.json'));
if (hash(lockBytes) !== process.argv[2] || process.version !== 'v24.14.0') throw new Error('Source/runtime pin refused.');
const lock = JSON.parse(lockBytes);
if (lock.harnessVersion !== '0.1.26' || lock.typeboxVersion !== '1.3.7' || lock.vendorModules !== 9 || lock.typeboxModules !== 656) throw new Error('Source closure refused.');
const source = new Map();
for (const [relative, expected] of Object.entries(lock.sources)) {
  const path = resolve(root, relative);
  if (!path.startsWith(root + sep)) throw new Error('Source path refused.');
  const bytes = readFileSync(path);
  if (hash(bytes) !== expected) throw new Error('Source pin refused.');
  source.set(pathToFileURL(path).href, bytes.toString('utf8'));
}

// Loader denies any dependency outside the audited literal import closure.
// Vendor config/log/file helpers are present but unusable, even if accidentally called.
const denied = `const deny=()=>{throw new Error('Unbrokered IO refused')};`;
const stubs = new Map([
 ['node:module', `${denied} export const createRequire=()=>deny;`],
 ['node:fs', `${denied} export const chmodSync=deny,mkdirSync=deny,readFileSync=deny,writeFileSync=deny;`],
 ['node:fs/promises', `${denied} export const appendFile=deny,mkdir=deny,chmod=deny;`],
 ['node:os', `${denied} export const homedir=deny;`],
]);
const pureBuiltins = new Set(['node:path','node:crypto']);
registerHooks({
 resolve(specifier, context, nextResolve) {
   if (stubs.has(specifier)) return {url:'qloo-denied:'+specifier, shortCircuit:true};
   if (pureBuiltins.has(specifier)) return nextResolve(specifier,context);
   let url;
   if (specifier === 'typebox') url = pathToFileURL(resolve(root,'dependency-review/typebox-1.3.7-source/build/index.mjs')).href;
   else if (specifier === 'typebox/value') url = pathToFileURL(resolve(root,'dependency-review/typebox-1.3.7-source/build/value/index.mjs')).href;
   else if (specifier.startsWith('.')) url = new URL(specifier,context.parentURL).href;
   else if (specifier.startsWith('file:')) url=specifier;
   if (!source.has(url)) throw new Error('Unaudited import refused.');
   return {url,shortCircuit:true};
 },
 load(url, context, nextLoad) {
   if (url.startsWith('qloo-denied:')) return {format:'module',source:stubs.get(url.slice(12)),shortCircuit:true};
   if (source.has(url)) return {format:'module',source:source.get(url),shortCircuit:true};
   if (pureBuiltins.has(url)) return nextLoad(url,context);
   throw new Error('Unaudited load refused.');
 }
});
const fail = () => { throw new Error('Unbrokered IO refused.'); };
globalThis.fetch = fail;
globalThis.WebSocket = fail;
globalThis.XMLHttpRequest = fail;
process.env = Object.freeze({});
console.log = console.info = console.warn = console.error = fail;

// Bound and parse protocol before importing vendor. Output/error contains no exception text.
let buffer=Buffer.alloc(0), queued=[], waiters=[], total=0;
process.stdin.on('data', chunk => {
  total+=chunk.length;
  if (total>2621440 || buffer.length+chunk.length>180224) process.exit(2);
  buffer=Buffer.concat([buffer,chunk]);
  while (true) {
    const i=buffer.indexOf(10); if(i<0)break;
    const line=buffer.subarray(0,i); buffer=buffer.subarray(i+1);
    let parsed;try{parsed=JSON.parse(line.toString('utf8'));}catch{process.exit(2);}
    if(waiters.length)waiters.shift()(parsed); else queued.push(parsed);
    if(queued.length>17)process.exit(2);
  }
});
const receive=()=>queued.length?Promise.resolve(queued.shift()):new Promise(r=>waiters.push(r));
const send=value=>process.stdout.write(JSON.stringify(value)+'\n');
const pending=new Map();let sequence=0, requestHash;
async function rpcFetch(url,options={}) {
  const u=new URL(String(url));
  if(u.origin!=='https://hackathon.api.qloo.com' || options.method!=='GET' || options.body!==undefined || !options.signal)fail();
  const headers=new Headers(options.headers);
  if(headers.get('X-Api-Key')!=='offline-placeholder-not-a-key')fail();
  if(sequence>=16)fail();
  const current=++sequence;
  // No credentials or arbitrary header/body values cross the RPC boundary.
  const response=new Promise((resolve,reject)=> {
    pending.set(current,{resolve,reject});
    options.signal.addEventListener('abort',()=>{pending.delete(current);reject(new Error('Cancelled'));},{once:true});
  });
  send({type:'raw_request',request_sha256:requestHash,sequence:current,method:'GET',url:u.href});
  return response;
}
async function responseLoop(){
  while(true){
    const frame=await receive();
    if(frame.type!=='raw_response'||!Number.isInteger(frame.sequence)||!pending.has(frame.sequence)||
       Object.keys(frame).sort().join(',')!=='body_b64,sequence,status,type'||!Number.isInteger(frame.status)||
       frame.status<200||frame.status>599||(frame.status>=300&&frame.status<=399)||typeof frame.body_b64!=='string')fail();
    const body=Buffer.from(frame.body_b64,'base64');
    if(body.length>131072||body.toString('base64')!==frame.body_b64)fail();
    const item=pending.get(frame.sequence);pending.delete(frame.sequence);
    item.resolve(new Response(body,{status:frame.status,headers:{'Content-Type':'application/json'}}));
  }
}
let stage='frame';
try {
  const frame=await receive();
  if(frame.type!=='workflow'||typeof frame.request_sha256!=='string'||!['describe','recommend'].includes(frame.request?.operation))fail();
  requestHash=frame.request_sha256;
  // Exact import closure verified before this point. All network-capable paths are injected or denied.
  stage='deny-guard-selfcheck';
  if(Object.keys(process.env).length!==0)fail();
  let deniedGlobal=false,deniedModule=false,deniedConfig=false;
  try{globalThis.fetch('https://must-never-be-requested.invalid');}catch{deniedGlobal=true;}
  try{await import('node:http');}catch{deniedModule=true;}
  try{(await import('node:fs')).readFileSync('must-never-be-read');}catch{deniedConfig=true;}
  if(!deniedGlobal||!deniedModule||!deniedConfig)fail();
  stage='client-import';
  const {QlooClient}=await import('./official-source/chunks/chunk-ESNY4EJL.js');
  stage='factory-import';
  const {createDirectQlooWorkflowExecutor}=await import('./official-source/qloo-tools.js');
  stage='resolver-import';
  const {createNativeQlooResolutionProvider}=await import('./official-source/resolution-provider.js');
  stage='client-construction';
  const client=new QlooClient({apiKey:'offline-placeholder-not-a-key',baseUrl:'https://hackathon.api.qloo.com',allowCustomBaseUrl:true,
    maxAttempts:1,timeoutMs:5000,maxResponseBytes:131072,maxRetryDelayMs:1,fetch:rpcFetch,
    sleep:async()=>fail(),random:()=>0,userAgent:'CommonGround-private-offline-qualification'});
  stage='resolver-construction';
  const resolver=createNativeQlooResolutionProvider(client,{cacheMaxEntries:0});
  stage='factory-construction';
  const executor=createDirectQlooWorkflowExecutor(client,undefined,resolver);
  responseLoop().catch(()=>process.exit(2));
  stage='execution';
  const execution=await executor.execute(frame.request.operation,frame.request.input,{correlationId:requestHash});
  const result=Buffer.from(JSON.stringify(execution.result));
  if(result.length>131072)fail();
  send({type:'result',request_sha256:requestHash,operation:frame.request.operation,body_b64:result.toString('base64')});
  process.stdin.pause();process.exit(0);
} catch {
  process.stderr.write('Offline stage failed: '+stage+'\n');
  process.exit(2);
}
