const $ = (id) => document.getElementById(id);
let state = {current:null, previous:null, local:null};
function notice(message, good=false){ const n=$('notice');n.textContent=message;n.classList.toggle('ok',good);n.hidden=false; }
function el(tag, cls, value){const node=document.createElement(tag);if(cls)node.className=cls;if(value!==undefined)node.textContent=value;return node;}
function comparable(a,b){return a&&b&&a.target===b.target&&JSON.stringify(a.ports)===JSON.stringify(b.ports)&&JSON.stringify(a.resolved_addresses)===JSON.stringify(b.resolved_addresses)&&a.timeout_seconds===b.timeout_seconds;}
function render(){
  const {current:c, previous:p, local:l}=state;
  $('export').disabled=!c;
  $('open-count').textContent=c?String(c.open_endpoints.length):'—';
  $('scan-status').textContent=c?(c.status==='complete'?'Vollständig':'Teilweise'):'—';
  $('scan-time').textContent=c?new Date(c.observed_at).toLocaleString('de-CH'):'Bereit';
  $('target-pill').textContent=c?c.target:'Noch kein Ziel';
  const comparableScans=comparable(c,p);
  const old=new Set(comparableScans?p.open_endpoints:[]);
  const latest=new Set(c?c.open_endpoints:[]);
  const added=comparableScans?[...latest].filter(x=>!old.has(x)):[];
  const removed=comparableScans?[...old].filter(x=>!latest.has(x)):[];
  $('open-delta').textContent=comparableScans?`${added.length} neu · ${removed.length} nicht mehr offen`:c?'Kein vergleichbarer Vorgänger':'Noch kein Scan';
  const sockets=l?(l.processes||[]).reduce((n,item)=>n+item.sockets.length,0):null;
  $('socket-count').textContent=l?String(sockets):'—';
  $('local-status').textContent=l?l.status==='complete'?'Vollständig geprüft':`Unvollständig · ${l.inaccessible_processes||0} Prozesse nicht lesbar`:'Nicht geprüft';
  const leads=l?(l.processes||[]).filter(x=>x.assessment==='investigate').length:0;
  $('lead-count').textContent=l?String(leads):'—';
  const view=$('network-view'), list=$('endpoint-list');view.replaceChildren();list.replaceChildren();
  if(!c){view.className='network-view empty';const box=el('div','empty-message');box.append(el('span','empty-symbol','⌁'),el('strong','', 'Keine Beobachtung vorhanden'),el('p','', 'Starte oben einen Scan. Offene Endpunkte erscheinen hier mit ihrem Ziel.'));view.append(box);list.append(el('div','row-muted','Noch keine Daten'));}
  else {view.className='network-view';const diagram=el('div','diagram');const hub=el('div','hub');hub.append(el('small','', 'ZIELSYSTEM'),el('strong','',c.target));diagram.append(hub);const nodes=el('div','nodes');if(c.open_endpoints.length){for(const endpoint of c.open_endpoints.slice(0,20))nodes.append(el('div','node'+(added.includes(endpoint)?' new':''),endpoint));if(c.open_endpoints.length>20)nodes.append(el('div','node',`+${c.open_endpoints.length-20} weitere`));}else nodes.append(el('div','node','Keine offenen Endpunkte beobachtet'));diagram.append(nodes);view.append(diagram);if(!c.open_endpoints.length)list.append(el('div','row-muted','In diesem Bereich wurde kein offener TCP-Endpunkt beobachtet.'));for(const endpoint of c.open_endpoints){const row=el('div','endpoint-row');row.append(el('span','',endpoint),el('span','', 'TCP offen'),el('span',added.includes(endpoint)?'tag-new':'',comparableScans?(added.includes(endpoint)?'Neu':'Bekannt'):'—'));list.append(row);}}
  const summary=$('local-summary'), processList=$('process-list');summary.replaceChildren();processList.replaceChildren();
  if(!l)summary.append(el('div','row-muted','Noch keine lokale Prüfung. Ohne Administratorrechte kann die Abdeckung unvollständig sein.'));
  else{const parts=[];parts.push(l.status==='complete'?'Sichtbare Packet-Sockets zugeordnet.':'Abdeckung unvollständig.');if(l.inaccessible_processes)parts.push(`${l.inaccessible_processes} Prozesse nicht lesbar.`);if(l.unattributed_packet_socket_inodes?.length)parts.push(`${l.unattributed_packet_socket_inodes.length} Sockets ohne Prozesszuordnung.`);summary.append(el('div','summary',parts.join(' ')));if(!l.processes?.length)processList.append(el('div','row-muted','Keine zugeordneten Packet-Socket-Prozesse.'));for(const proc of l.processes||[]){const card=el('div','process'+(proc.assessment==='investigate'?' investigate':''));const top=el('div','process-top');top.append(el('strong','',`PID ${proc.pid} · ${proc.process_name||'Unbekannt'}`),el('span','',proc.assessment==='investigate'?'Untersuchen':'Inventar'));card.append(top,el('small','',proc.executable||'Ausführbare Datei nicht lesbar'),el('small','',`${proc.sockets.length} Packet-Socket(s) · ${proc.signals.join(', ')}`));processList.append(card);}}
  const changes=$('changes');changes.replaceChildren();if(!comparableScans)changes.append(el('div','row-muted',p?'Scans unterscheiden sich in Ziel, Adressen, Bereich oder Timeout; kein direkter Vergleich.':'Nach zwei vergleichbaren Scans werden Veränderungen angezeigt.'));else if(!added.length&&!removed.length)changes.append(el('div','row-muted','Keine Änderung an beobachteten offenen Endpunkten.'));else{const wrap=el('div','change-list');for(const value of added)wrap.append(el('span','change-item added',`+ ${value} neu offen`));for(const value of removed)wrap.append(el('span','change-item removed',`− ${value} nicht mehr offen beobachtet`));changes.append(wrap);}
}
async function call(path, data){const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const payload=await response.json();if(!response.ok)throw new Error(payload.error||`HTTP ${response.status}`);return payload;}
$('scan-form').addEventListener('submit',async(e)=>{e.preventDefault();const button=$('run');button.disabled=true;button.textContent='Scan läuft…';try{state=await call('/api/scan',{host:$('host').value.trim(),start:$('start').value,end:$('end').value,timeout:$('timeout').value,authorized:$('authorized').checked});render();notice('Scan abgeschlossen. Beobachtung für den Vergleich gespeichert.',true);}catch(err){notice(err.message);}finally{button.disabled=false;button.innerHTML='TCP-Scan starten <span>→</span>';}});
$('local-run').addEventListener('click',async()=>{const button=$('local-run');button.disabled=true;button.textContent='Lokale Prüfung läuft…';try{state=await call('/api/local',{});render();notice(state.local.status==='complete'?'Lokale Prüfung abgeschlossen.':'Lokale Prüfung unvollständig: Ein Teil der Prozesse war nicht lesbar.',state.local.status==='complete');}catch(err){notice(err.message);}finally{button.disabled=false;button.innerHTML='Lokalen Check starten <span>↗</span>';}});
$('export').addEventListener('click',async()=>{try{const response=await fetch('/api/export');if(!response.ok)throw new Error('Kein Scan für den Export vorhanden.');const blob=await response.blob();const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=`t-nocker-${new Date().toISOString().replace(/[:.]/g,'-')}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(err){notice(err.message);}});
$('clock').textContent=new Date().toLocaleString('de-CH',{dateStyle:'medium',timeStyle:'short'});
fetch('/api/state').then(r=>r.json()).then(data=>{state=data;render();}).catch(()=>notice('Verbindung zur lokalen Anwendung fehlgeschlagen.'));
