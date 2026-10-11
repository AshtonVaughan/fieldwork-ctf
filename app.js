/* UI for a fictional, entirely local training target. */
(() => {
  'use strict';
  const {Box,CHALLENGES,target,freshModel}=RelayEngine;
  const $=id=>document.getElementById(id), key='relay-ctf-v1';
  let saved={};try{saved=JSON.parse(localStorage.getItem(key)||'{}')||{};}catch{}
  const state={solved:Array.isArray(saved.solved)?saved.solved.filter(id=>CHALLENGES.some(c=>c.id===id)):[],hints:saved.hints&&typeof saved.hints==='object'?saved.hints:{},notes:typeof saved.notes==='string'?saved.notes:''};
  state.solved=[...new Set(state.solved)];
  const box=new Box();let view='page',history=[],historyIndex=0,lastResponse=target('/',box.session,false,box.model);
  function persist(){try{localStorage.setItem(key,JSON.stringify(state));$('save-status').textContent='Progress and notes saved in this browser.';}catch{$('save-status').textContent='Browser storage unavailable. Keep an exported copy of your notes.';}}
  function toast(message){$('toast').textContent=message;$('toast').classList.add('visible');clearTimeout(toast.timer);toast.timer=setTimeout(()=>$('toast').classList.remove('visible'),3500);}
  function score(){const points=CHALLENGES.filter(c=>state.solved.includes(c.id)).reduce((a,c)=>a+c.points,0);$('score').textContent=points.toLocaleString();$('progress').value=state.solved.length;$('captured').textContent=`${state.solved.length} / ${CHALLENGES.length} flags captured`;}
  function response(){const r=lastResponse;$('status').textContent=`HTTP ${r.status}`;$('response').hidden=['storage','request'].includes(view);$('storage').hidden=view!=='storage';$('request-form').hidden=view!=='request';$('response').className='response'+(view==='source'?' source':'');$('response').replaceChildren();if(['storage','request'].includes(view))return;
    const body=typeof r.body==='string'?r.body:JSON.stringify(r.body,null,2);
    if(view==='page'&&r.type==='html'){
      const parsed=new DOMParser().parseFromString(body,'text/html');
      for(const item of parsed.body.children){if(item.tagName==='A'){const a=document.createElement('a');a.href='#';a.textContent=item.textContent;a.addEventListener('click',e=>{e.preventDefault();navigate(item.getAttribute('href'));});$('response').append(a);}else{const el=document.createElement(['H1','P','PRE'].includes(item.tagName)?item.tagName.toLowerCase():'p');el.textContent=item.textContent;$('response').append(el);}}
    }else{const pre=document.createElement('pre');pre.textContent=body;$('response').append(pre);}
  }
  function send(options={}){lastResponse=target($('path').value,box.session,box.patched,box.model,options);view='page';updateTabs();response();}
  function navigate(path){$('path').value=path;send();}
  function updateTabs(){document.querySelectorAll('[data-view]').forEach(b=>{b.classList.toggle('active',b.dataset.view===view);b.setAttribute('aria-pressed',String(b.dataset.view===view));});}
  $('nav-form').addEventListener('submit',e=>{e.preventDefault();send();});
  document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>{view=b.dataset.view;updateTabs();response();}));
  document.querySelectorAll('[data-path]').forEach(b=>b.addEventListener('click',()=>navigate(b.dataset.path)));
  $('session').value=JSON.stringify(box.session,null,2);
  $('apply-session').addEventListener('click',()=>{try{const next=JSON.parse($('session').value);if(!next||next.user!=='alice'||typeof next.role!=='string')throw Error();box.session={user:'alice',role:next.role};$('session-message').textContent='Session applied. Press Go to repeat your request.';}catch{$('session-message').textContent='Use valid JSON with user "alice" and a string role.';}});
  $('request-form').addEventListener('submit',e=>{e.preventDefault();try{const headers=JSON.parse($('request-headers').value),body=JSON.parse($('request-body').value);if(!headers||Array.isArray(headers)||typeof headers!=='object'||!body||Array.isArray(body)||typeof body!=='object')throw Error();send({method:$('request-method').value,headers,body});$('request-message').textContent='Request model evaluated. Open Page to inspect the response.';}catch{$('request-message').textContent='Headers and body must be valid JSON objects.';}});
  $('mode').addEventListener('change',()=>{box.patched=$('mode').value==='patched';box.model=freshModel();box.passwordPrompt=false;$('command').type='text';updatePrompt();send();log('',box.patched?'Patched target enabled. Exercise state reset. Repeat the same test to compare the control.':'Vulnerable target enabled. Exercise state reset.');});
  $('reset-model').addEventListener('click',()=>{box.model=freshModel();send();toast('Exercise state reset. Captured flags preserved.');});
  function updatePrompt(){$('prompt').textContent=box.passwordPrompt?'Password:':`${box.user}@relay:${box.cwd==='/home/dev'?'~':box.cwd}$`;}
  function log(command,output){const entry=document.createElement('div');entry.className='entry';if(command){const line=document.createElement('div');line.className='command';line.textContent='› '+command;entry.append(line);}const body=document.createElement('div');body.textContent=output;entry.append(body);$('terminal-output').append(entry);$('terminal-output').scrollTop=$('terminal-output').scrollHeight;}
  function run(raw){const secret=box.passwordPrompt;if(!secret&&raw.trim()){history.push(raw);historyIndex=history.length;}if(!secret&&raw.trim()==='clear'){$('terminal-output').replaceChildren();}else if(!secret&&raw.trim()==='history'){log(raw,history.map((c,i)=>`${i+1}  ${c}`).join('\n'));}else{const result=box.execute(raw);log(secret?'[password hidden]':raw,result.output);}updatePrompt();$('command').type=box.passwordPrompt?'password':'text';$('command').value='';}
  $('terminal-form').addEventListener('submit',e=>{e.preventDefault();run($('command').value);});
  $('command').addEventListener('keydown',e=>{if(box.passwordPrompt)return;if(e.key==='ArrowUp'){e.preventDefault();historyIndex=Math.max(0,historyIndex-1);$('command').value=history[historyIndex]||'';}if(e.key==='ArrowDown'){e.preventDefault();historyIndex=Math.min(history.length,historyIndex+1);$('command').value=history[historyIndex]||'';}});
  $('terminal-help').addEventListener('click',()=>run('help'));
  log('','RELAY / INTERACTIVE TRAINING TERMINAL\n\nOne fictional host. 26 distinct flags to find.\nStart with: nmap -sV 10.10.10.42\nType help for the supported command models.');
  function card(c,i){const solved=state.solved.includes(c.id);const el=document.createElement('article');el.className='challenge'+(solved?' solved':'');el.id='challenge-'+c.id;
    el.dataset.level=c.level;el.innerHTML=`<div class="challenge-top"><span>${String(i+1).padStart(2,'0')} / ${solved?'CAPTURED':'OPEN'}</span><span>${c.points} PTS</span></div><h3>${c.title}</h3><div class="category">${c.level} · ${c.category}</div><p class="objective">${c.objective}</p><form class="flag-form"><input aria-label="Flag for ${c.title}" placeholder="CTF{...}" autocomplete="off" spellcheck="false" ${solved?'disabled':''}><button ${solved?'disabled':''}>${solved?'✓':'Submit'}</button></form><p class="challenge-message" role="status">${solved?'Flag captured. Read the lesson below.':''}</p><button class="hint-button">Reveal hint</button><div class="hints"></div>`;
    const hints=el.querySelector('.hints'),hintButton=el.querySelector('.hint-button');
    let count=Math.max(0,Math.min(3,Number(state.hints[c.id])||0));
    function drawHints(){hints.replaceChildren();for(let j=0;j<count;j++){const p=document.createElement('p');p.textContent=`${j+1}. ${c.hints[j]}`;hints.append(p);}hintButton.textContent=count===3?'All hints revealed':`Reveal hint (${count}/3)`;hintButton.disabled=count===3;}
    hintButton.addEventListener('click',()=>{count=Math.min(3,count+1);state.hints[c.id]=count;persist();drawHints();});drawHints();
    if(solved){const lesson=document.createElement('div');lesson.className='lesson';lesson.textContent=c.lesson;const link=document.createElement('a');link.href=c.reference;link.target='_blank';link.rel='noopener noreferrer';link.textContent='Read more ↗';lesson.append(link);el.append(lesson);}
    el.querySelector('form').addEventListener('submit',async e=>{e.preventDefault();const button=el.querySelector('form button'),message=el.querySelector('.challenge-message');button.disabled=true;try{const result=await RelayValidation.capture(c.id,el.querySelector('input').value,state.solved);message.textContent=result==='invalid'?'That flag does not match this challenge.':result==='duplicate'?'Already captured.':`Captured +${c.points} points.`;if(result==='captured'){persist();score();el.replaceWith(card(c,i));toast(state.solved.length===CHALLENGES.length?'All 26 flags captured. Box complete!':`${c.title}: +${c.points} points`);}}catch{message.textContent='Flag checking needs a secure browser context. Open the HTTPS Pages site.';}finally{if(el.isConnected)button.disabled=false;}});
    return el;
  }
  CHALLENGES.forEach((c,i)=>$('challenges').append(card(c,i)));
  document.querySelectorAll('[data-level]').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('[data-level]').forEach(btn=>{btn.classList.toggle('active',btn===b);btn.setAttribute('aria-pressed',String(btn===b));});document.querySelectorAll('.challenge').forEach(el=>el.hidden=b.dataset.level!=='all'&&el.dataset.level!==b.dataset.level);}));
  $('notes').value=state.notes;$('notes').addEventListener('input',()=>{state.notes=$('notes').value;persist();});
  $('guide-button').addEventListener('click',()=>{$('guide').hidden=!$('guide').hidden;$('guide-button').setAttribute('aria-expanded',String(!$('guide').hidden));});
  $('export').addEventListener('click',()=>{const text=`# Relay CTF investigation\n\nCaptured: ${state.solved.length}/${CHALLENGES.length}\n\n${CHALLENGES.map(c=>`- [${state.solved.includes(c.id)?'x':' '}] ${c.title} (${c.level}, ${c.category})`).join('\n')}\n\n## Evidence\n\n${state.notes}\n`;const url=URL.createObjectURL(new Blob([text],{type:'text/markdown'}));const a=document.createElement('a');a.href=url;a.download='relay-investigation.md';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  let resetArmed=false;
  $('reset').addEventListener('click',()=>{if(!resetArmed){resetArmed=true;$('reset').textContent='Confirm reset: clear flags, hints and notes';$('reset-cancel').hidden=false;toast('Export your notebook first if you want to keep it. Confirm reset or cancel below.');return;}try{localStorage.removeItem(key);}catch{}state.solved=[];state.hints={};state.notes='';persist();location.reload();});
  $('reset-cancel').addEventListener('click',()=>{resetArmed=false;$('reset').textContent='Reset all game progress';$('reset-cancel').hidden=true;});
  score();updatePrompt();updateTabs();response();
})();
