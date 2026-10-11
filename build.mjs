import fs from 'node:fs';
import crypto from 'node:crypto';
const root=new URL('./',import.meta.url);
const engine=fs.readFileSync(new URL('engine.js',root),'utf8');
const flags=Object.fromEntries([...engine.matchAll(/(\w+):'(CTF\{[^']+\})'/g)].map(m=>[m[1],crypto.createHash('sha256').update(m[2]).digest('hex')]));
if(Object.keys(flags).length!==26)throw Error('Expected exactly 26 authored flags');
fs.writeFileSync(new URL('validation.js',root),`/* Client-side checks are for personal practice, not secure competitive scoring. */\n(function(root){\n'use strict';\nconst hashes=${JSON.stringify(flags,null,2)};\nasync function capture(id,flag,solved){\n if(!Object.hasOwn(hashes,id))return 'invalid';\n const value=String(flag).trim();\n const bytes=new TextEncoder().encode(value);\n const digest=await crypto.subtle.digest('SHA-256',bytes);\n const hash=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');\n if(hash!==hashes[id])return 'invalid';\n if(solved.includes(id))return 'duplicate';\n solved.push(id);return 'captured';\n}\nconst api={capture};\nif(typeof module!=='undefined'&&module.exports)module.exports=api;else root.RelayValidation=api;\n})(typeof window!=='undefined'?window:globalThis);\n`);
console.log('Built 26 flag checks.');
