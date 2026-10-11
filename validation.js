/* Client-side checks are for personal practice, not secure competitive scoring. */
(function(root){
'use strict';
const hashes={
  "source": "17a5972f2e7bbb3f629fa0b38f9131e0c34eec3b0330b5b693bd46afffe831b6",
  "discovery": "e1567ad3487cde18ee3ecf837ff8a538cc4d3e9a3ca388d0a04e64dfa8f702b0",
  "encoding": "4fbf02b63c5c7dd0a8200afa293e613979441271c93b8fff1e034a631193884d",
  "git": "d9ffe4e102ea0690dc01f03fc1a0686fd767ccc86c7eda6c3e683bbd03a3deae",
  "debug": "7c13de97f6a7a31d4fa13ad14691b387ef654ac463a4122beb9109fb1e2d9952",
  "traversal": "bf44f906720e389d0f79d982105b6a6777b6af0d54e066dc29e4b95c96de469f",
  "redirect": "1996747dd670dc1e028962e3314ee40f744f71c2d68b1f29498f5ce0ad464086",
  "trust": "ed2dc6096a9a6a89a782ce13850af6f877b2c9394701f7101cb71dac967347d4",
  "idor": "fc87bbe49afb9879a1cc2cc6fb3dadcbc3f07378d61a1f71132585b406a0fa7b",
  "mass": "713d1697cbb4fff2849c2d6c551837d6f18c03ee552e099aceb6c3e16de48d3e",
  "sqli": "7b22e1541dabc626591bc001f4944560a1bbcf867e6704532f3fae8badf7b9e4",
  "xss": "d24610f7e8ec07777c483d63bff86f12ae416666477b8d242b767d759b5b0635",
  "csrf": "a817d0d17bff922d49ec050bab904b8b6ca84c09fe3e6397127027216527caf7",
  "cors": "7ea2574992b031df7e1d98c02ae19408c3a6c510cbd30231b7912c45d5857583",
  "upload": "3328d13f774642da5276b7f921294226c720e5b7057d161de995790fdcb251f4",
  "ssrf": "6fe72d28c3f853d8ba90dd6f093d6514f678c8ef99e82e6a7d0c760230cae895",
  "xxe": "478632d6868b69beb1f5b8e8f92e1e3652b1a7fc3baa772b31dad5300c2b9956",
  "ssti": "2636eb4c5cfa0e3cb70449deec8982e213f7d16f5b00b0e7716f64939e44d97f",
  "nosql": "e868e99b15bc4d4def175b0022216a3949d20c35abfb09ff5e0137defff4cb8d",
  "jwt": "78153517e2bc6cdaadbd5f6755b4f63ea0faa39ff56488f64292386a2d6d6f31",
  "user": "765615b36b3b8160066711b6505c2836db422dea0505e4361ef0323455db93b0",
  "capability": "cc1015bb3ffbc0fdcf3d863302988206f7204d1394deb41721681712f0232deb",
  "archive": "247cef5ba90c4988f557242d4a906ad55117b7d3d523129d767abe9187f42184",
  "race": "1d013b99611f62984db8699c4a12ecbbaa72de2952c54b5ef040013f5ba1b688",
  "cache": "cbba8c48a61272575499fa7740a765d41d58df67b0c35d0e5456ca5a5908b978",
  "root": "ee4a6e7e473565b206c47ba82e621954b74c774c181b22185640764202935daf"
};
async function capture(id,flag,solved){
 if(!Object.hasOwn(hashes,id))return 'invalid';
 const value=String(flag).trim();
 const bytes=new TextEncoder().encode(value);
 const digest=await crypto.subtle.digest('SHA-256',bytes);
 const hash=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');
 if(hash!==hashes[id])return 'invalid';
 if(solved.includes(id))return 'duplicate';
 solved.push(id);return 'captured';
}
const api={capture};
if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.RelayValidation=api;
})(typeof window!=='undefined'?window:globalThis);
