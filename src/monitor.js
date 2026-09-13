import {createHash} from 'node:crypto';
import {isIP} from 'node:net';

function parseTime(value) {
  if(typeof value!=='string')throw new Error('Missing timestamp');
  value=value.replace(/([+-]\d{2})(\d{2})$/,'$1:$2');
  const m=value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/);
  if(!m)throw new Error('Timestamp requires an ISO date and timezone');
  const [year,month,day,hour,minute,second]=m.slice(1).map(Number);
  const days=[31,year%4===0&&(year%100!==0||year%400===0)?29:28,31,30,31,30,31,31,30,31,30,31];
  const time=Date.parse(value);
  if(!Number.isFinite(time)||year<1||month<1||month>12||day<1||day>days[month-1]||hour>23||minute>59||second>59)throw new Error('Invalid timestamp');
  return time;
}
const string=value=>typeof value==='string'?value:'';
function sourceIP(value) {
  if(!isIP(value))throw new Error('Authentication event needs a valid source IP');
  return isIP(value)===6?new URL(`http://[${value}]/`).hostname.slice(1,-1):value;
}

export function normalizeRecord(record,line=1) {
  if(!record||typeof record!=='object'||Array.isArray(record))throw new Error('Expected JSON object');
  const data=record.data??record;
  const id=String(record.id??createHash('sha256').update(JSON.stringify(record)).digest('hex').slice(0,20));
  if(!id||id.length>256)throw new Error('Invalid event ID');
  const base={id,line,time:parseTime(record.timestamp??data.timestamp),agent:string(record.agent?.name??data.agent)||'unknown',origin:'wazuh-export'};
  let event;
  if(data.integration==='storylab') {
    const allowed=['auth_failure','auth_success','admin_group_change','file_change','process'];
    if(!allowed.includes(data.event))return null;
    event={...base,type:data.event,ip:string(data.srcip),user:string(data.user),actor:string(data.actor),path:string(data.path),command:string(data.command),origin:'storylab-json'};
  } else if(data.win?.system) {
    const system=data.win.system, detail=data.win.eventdata??{};
    const code=Number(system.eventID);
    if([4624,4625].includes(code))event={...base,type:code===4625?'auth_failure':'auth_success',ip:string(detail.ipAddress),user:string(detail.targetUserName)};
    else if([4732,4728].includes(code)) {
      const sid=string(detail.targetSid);
      if(sid!=='S-1-5-32-544' && !/^S-1-5-21-\d+-\d+-\d+-512$/.test(sid))return null;
      event={...base,type:'admin_group_change',user:string(detail.memberName),actor:string(detail.subjectUserName)};
    } else if(code===1 && /sysmon/i.test(string(system.providerName)))event={...base,type:'process',command:string(detail.commandLine),user:string(detail.user)};
    else return null;
  } else if(record.syscheck?.event==='modified')event={...base,type:'file_change',path:string(record.syscheck.path)};
  else if(data.srcip && Array.isArray(record.rule?.groups)) {
    const groups=record.rule.groups;
    if(groups.includes('authentication_failed'))event={...base,type:'auth_failure',ip:string(data.srcip),user:string(data.dstuser)};
    else if(groups.includes('authentication_success'))event={...base,type:'auth_success',ip:string(data.srcip),user:string(data.dstuser)};
    else return null;
  } else return null;
  if(event.type.startsWith('auth_'))event.ip=sourceIP(event.ip);
  if(event.type==='file_change' && !event.path)throw new Error('File-change event needs a path');
  return event;
}

export function loadJSONL(text) {
  const events=[], errors=[],seen=new Set();let ignored=0,duplicates=0,errorCount=0;
  for(const [i,raw] of text.split(/\r?\n/).entries()) {
    if(!raw.trim()||raw.trim().startsWith('#'))continue;
    try {
      if(raw.length>65536)throw new Error('Event line exceeds 64 KiB');
      const event=normalizeRecord(JSON.parse(raw),i+1);
      if(!event){ignored++;continue;}
      if(seen.has(event.id)){duplicates++;continue;}
      if(events.length>=100000)throw new RangeError('Input exceeds 100000 normalized events');
      seen.add(event.id);events.push(event);
    }catch(error){if(error instanceof RangeError)throw error;errorCount++;if(errors.length<20)errors.push({line:i+1,reason:error instanceof SyntaxError?'Invalid JSON syntax':error.message});}
  }
  return {events,ignored,duplicates,errorCount,errors};
}

export function correlate(events,{threshold=5,windowSeconds=300,approvedChanges=[]}={}) {
  if(!Number.isInteger(threshold)||threshold<2||!Number.isInteger(windowSeconds)||windowSeconds<1)throw new Error('Invalid correlation settings');
  if(!Array.isArray(approvedChanges)||approvedChanges.some(x=>typeof x!=='string'))throw new Error('approvedChanges must be event IDs from a reviewed change record');
  const approved=new Set(approvedChanges), incidents=[], benignChanges=[],states=new Map();
  const ordered=[...events].sort((a,b)=>a.time-b.time||a.line-b.line);
  const add=(rule,evidence,details)=>{
    const last=evidence.at(-1);
    const incident={id:`INC-${String(incidents.length+1).padStart(3,'0')}`,rule,severity:'medium',status:'Needs investigation',agent:last.agent,
      firstSeen:new Date(evidence[0].time).toISOString(),lastSeen:new Date(last.time).toISOString(),evidenceIds:evidence.map(e=>e.id),...details};
    incidents.push(incident);return incident;
  };
  for(const event of ordered) {
    if(event.type==='auth_failure') {
      const key=JSON.stringify([event.agent,event.ip]);
      let state=states.get(key);if(!state){state={queue:[],head:0,active:false};states.set(key,state);}
      while(state.head<state.queue.length&&state.queue[state.head].time<event.time-windowSeconds*1000)state.head++;
      if(state.queue.length-state.head<threshold)state.active=false;
      state.queue.push(event);
      if(state.queue.length-state.head>=threshold&&!state.active){
        add('AUTH-BURST',state.queue.slice(state.head),{ip:event.ip,title:'Repeated failed authentication',finding:`At least ${threshold} failed sign-ins from one source to one monitored host within ${windowSeconds} seconds.`,nextSteps:['Check whether this is a shared source IP or a user retrying a password.','Review affected accounts and nearby successful logins.','Confirm scope before proposing containment.']});state.active=true;
      }
      if(state.head>1024&&state.head*2>state.queue.length){state.queue=state.queue.slice(state.head);state.head=0;}
    } else if(['admin_group_change','file_change'].includes(event.type)) {
      if(approved.has(event.id)){benignChanges.push({id:event.id,type:event.type,reason:'Matches a reviewed approved-change record supplied separately.'});continue;}
      if(event.type==='admin_group_change')add('ADMIN-CHANGE',[event],{severity:'high',title:'Administrator-group membership changed',actor:event.actor,user:event.user,finding:'A privileged group change has no matching approval in the supplied change records. Missing approval is a review gap, not proof of malicious activity.',nextSteps:['Validate the actor and affected member against the change request.','Check the account owner and relevant authentication activity.','Escalate an unapproved change through the incident process.']});
      else add('FILE-CHANGE',[event],{title:'Monitored file changed',path:event.path,finding:'A monitored file changed without a matching supplied approval record.',nextSteps:['Compare file contents or hashes before and after the change.','Check the change window and responsible administrator.','Review nearby process activity and restore only after authorization.']});
    }
  }
  for(const incident of incidents) {
    const end=Date.parse(incident.lastSeen);
    incident.nearbyContext=ordered.filter(e=>e.agent===incident.agent&&e.time>=Date.parse(incident.firstSeen)-60000&&e.time<=end+600000&&['process','auth_success'].includes(e.type)).slice(0,20).map(e=>({id:e.id,type:e.type,timestamp:new Date(e.time).toISOString(),user:e.user??'',ip:e.ip??'',command:e.command??''}));
  }
  return {schemaVersion:1,settings:{threshold,windowSeconds},eventCount:events.length,incidents,benignChanges,
    limitations:['Offline analysis; this program does not collect endpoint telemetry.','Alerts are investigation leads, not confirmed compromises.','Missing/local-only authentication IPs cannot be source-IP correlated.','Time-window analysis uses event timestamps; synchronize endpoint clocks.','Only the documented event types are normalized.']};
}

export const escapeHTML=value=>String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
export function renderHTML(report) {
  const h=escapeHTML;
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Security monitoring investigation report</title><style>body{font:16px/1.6 system-ui;max-width:1100px;margin:40px auto;padding:0 24px;color:#18232f}.notice{padding:18px;background:#fff2ca}article{border-top:2px solid #ddd;margin-top:30px;padding-top:12px}table{border-collapse:collapse;width:100%}td,th{padding:9px;border-bottom:1px solid #ddd;text-align:left;overflow-wrap:anywhere}pre{overflow-wrap:anywhere;white-space:pre-wrap}h1{line-height:1.2}</style><h1>Security monitoring investigation report</h1><p class="notice">${h(report.provenance??'Input provenance has not been independently verified.')}</p><p>${report.eventCount} normalized events | ${report.incidents.length} investigation cases | ${report.benignChanges.length} changes matched reviewed approvals</p>${report.incidents.map(i=>`<article><h2>${h(i.id)} · ${h(i.title)}</h2><p><strong>${h(i.severity)}</strong> | ${h(i.status)} | ${h(i.agent)}</p><p>${h(i.finding)}</p><p>First: ${h(i.firstSeen)}<br>Last: ${h(i.lastSeen)}</p><p>Evidence IDs: ${h(i.evidenceIds.join(', '))}</p>${i.path?`<p>Path: ${h(i.path)}</p>`:''}${i.ip?`<p>Source: ${h(i.ip)}</p>`:''}${i.user?`<p>Affected member: ${h(i.user)}</p>`:''}${i.actor?`<p>Actor: ${h(i.actor)}</p>`:''}<h3>Investigation steps</h3><ol>${i.nextSteps.map(s=>`<li>${h(s)}</li>`).join('')}</ol><h3>Nearby context</h3><pre>${h(JSON.stringify(i.nearbyContext,null,2))}</pre></article>`).join('')||'<p>No configured correlation rule matched.</p>'}<h2>Coverage and limitations</h2><ul>${report.limitations.map(s=>`<li>${h(s)}</li>`).join('')}</ul><p>Rejected lines: ${report.ingestion?.errorCount??0}; ignored event types: ${report.ingestion?.ignored??0}; duplicate IDs: ${report.ingestion?.duplicates??0}.</p></html>`;
}

export function incidentMarkdown(incident,provenance) {
  const safe=value=>String(value??'').replace(/\r?\n/g,' ').replace(/[\\`*_{}\[\]()#+.!|<>-]/g,'\\$&');
  const details=[['Source IP',incident.ip],['Path',incident.path],['Actor',incident.actor],['Affected member',incident.user]].filter(([,value])=>value).map(([label,value])=>`- ${label}: ${safe(value)}`).join('\n');
  return `# ${safe(incident.id)} ${safe(incident.title)}\n\n${provenance}\n\n- Status: ${safe(incident.status)}\n- Severity: ${safe(incident.severity)}\n- Host: ${safe(incident.agent)}\n- First seen: ${incident.firstSeen}\n- Last seen: ${incident.lastSeen}\n- Evidence IDs: ${incident.evidenceIds.map(safe).join(', ')}\n${details}\n\n## Finding\n\n${safe(incident.finding)}\n\n## Next investigation steps\n\n${incident.nextSteps.map(s=>'- '+s).join('\n')}\n\n## Analyst conclusion\n\nThe available events justify investigation. No endpoint containment, account change, or confirmation of compromise was performed by this software. Corroborate the finding against original logs and approved change records.\n`;
}
