import {loadJSONL,correlate} from './engine.js';
import {$,h,resource,save,status,fatal,clock} from './ui.js';
let events=[],context={},count=0,timer=null,report=null;
const names={auth_failure:'Failed sign-in',auth_success:'Successful sign-in',admin_group_change:'Administrator-group change',file_change:'Monitored file change',process:'Process execution'};
function stop(){if(timer)clearInterval(timer);timer=null;$('play').textContent=count>=events.length?'Replay again':'Play replay';}
function refresh(){
 try{
  const threshold=Number($('threshold').value),windowSeconds=Number($('window').value);
  if(!Number.isInteger(threshold)||threshold<2||threshold>1000||!Number.isInteger(windowSeconds)||windowSeconds<1||windowSeconds>86400)throw new Error('Use a threshold from 2 to 1,000 and a window from 1 to 86,400 seconds.');
  const seen=events.slice(0,count).filter(e=>$('host').value==='all'||e.agent===$('host').value);
  report=correlate(seen,{threshold,windowSeconds,approvedChanges:$('approvals').checked?context.approvedChanges:[]});
  report.provenance='Synthetic event replay in the browser. No live endpoint telemetry was collected.';
  report.replay={processed:count,total:events.length,hostFilter:$('host').value,reviewedApprovalsApplied:$('approvals').checked};
  $('event-count').textContent=`${count} / ${events.length}`;$('case-count').textContent=report.incidents.length;$('approved-count').textContent=report.benignChanges.length;$('host-count').textContent=new Set(seen.map(e=>e.agent)).size;
  $('progress').setAttribute('aria-valuenow',count);$('progress').setAttribute('aria-valuemax',events.length);$('progress-fill').style.width=`${100*count/events.length}%`;
  $('next-event').disabled=count>=events.length;$('show-all').disabled=count>=events.length;$('export-report').disabled=count===0;
  $('timeline').innerHTML=seen.slice().reverse().map(e=>`<div class="event"><time>${h(clock(e.time))}</time><div><strong>${h(names[e.type]??e.type)}</strong><span>${h(e.agent)} / ${h(e.id)}</span></div></div>`).join('')||'<p class="muted">No events in this view yet. Play the replay or change the host filter.</p>';
  $('cases').innerHTML=report.incidents.map(i=>`<article class="result-card"><div class="result-title"><h3>${h(i.title)}</h3><span class="badge ${h(i.severity)}">${h(i.severity)}</span></div><div class="meta">${h(i.id)} / ${h(i.agent)}<br>${h(i.firstSeen)}${i.ip?' / '+h(i.ip):''}</div><p>${h(i.finding)}</p>${i.user?`<p><strong>Affected member:</strong> ${h(i.user)}</p>`:''}${i.path?`<p><strong>Path:</strong> ${h(i.path)}</p>`:''}<details><summary>Evidence · ${i.evidenceIds.length} records / ${i.nearbyContext.length} context events</summary><pre>${h(JSON.stringify({evidence:seen.filter(e=>i.evidenceIds.includes(e.id)),nearbyContext:i.nearbyContext},null,2))}</pre></details><details><summary>Investigation steps</summary><ol>${i.nextSteps.map(s=>`<li>${h(s)}</li>`).join('')}</ol></details></article>`).join('')||`<div class="empty"><strong>${count?'No case in this view':'Ready to investigate'}</strong><span class="muted">${count?'No configured correlation rule matched the events shown.':'Replay events to build the case evidence.'}</span></div>`;
  status(`${count} of ${events.length} events replayed; ${seen.length} match the host filter. ${report.incidents.length} cases.`);
  return true;
 }catch(error){stop();report=null;$('export-report').disabled=true;for(const id of ['case-count','approved-count','host-count'])$(id).textContent='—';$('cases').innerHTML='<div class="empty">Correct the rule settings to update cases.</div>';status(error.message,true);return false;}
}
function advance(){count=Math.min(events.length,count+1);refresh();if(count===events.length)stop();}
$('play').addEventListener('click',()=>{if(timer){stop();status('Replay paused.');return;}if(count===events.length)count=0;if(!refresh())return;timer=setInterval(advance,650);$('play').textContent='Pause replay';});
$('next-event').addEventListener('click',()=>{stop();advance();});
$('show-all').addEventListener('click',()=>{stop();count=events.length;refresh();stop();});
$('reset').addEventListener('click',()=>{stop();count=0;$('threshold').value=5;$('window').value=300;$('host').value='all';$('approvals').checked=true;refresh();stop();});
for(const id of ['threshold','window','host','approvals'])$(id).addEventListener('change',refresh);
$('export-report').addEventListener('click',()=>{if(report)save('security-investigation.json',report);});
window.addEventListener('pagehide',stop);
try{
 const [raw,c]=await Promise.all([resource('events.jsonl'),resource('context.json','json')]);context=c;
 const loaded=loadJSONL(raw);if(loaded.errorCount)throw new Error('The sample fixture could not be parsed.');
 events=loaded.events.sort((a,b)=>a.time-b.time||a.line-b.line);
 $('host').innerHTML='<option value="all">All monitored hosts</option>'+[...new Set(events.map(e=>e.agent))].sort().map(host=>`<option value="${h(host)}">${h(host)}</option>`).join('');
 document.querySelectorAll('[data-ready]').forEach(b=>b.disabled=false);refresh();
}catch(error){fatal(error);}
