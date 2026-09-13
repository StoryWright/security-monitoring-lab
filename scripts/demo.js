import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {loadJSONL,correlate,renderHTML,incidentMarkdown} from '../src/monitor.js';
const root=new URL('../',import.meta.url);
await mkdir(new URL('fixtures/',root),{recursive:true});
await mkdir(new URL('reports/demo/',root),{recursive:true});
const t=s=>new Date(Date.parse('2026-08-01T12:00:00Z')+s*1000).toISOString();
const events=[];
const win=(id,s,eventID,eventdata,host='lab-win-01')=>({id,timestamp:t(s),agent:{name:host},data:{win:{system:{eventID:String(eventID),providerName:eventID===1?'Microsoft-Windows-Sysmon':'Microsoft-Windows-Security-Auditing'},eventdata}}});
for(const [i,s] of [0,20,40,60,80].entries())events.push(win(`burst-${i+1}`,s,4625,{ipAddress:'192.0.2.10',targetUserName:'lab_alex'}));
events.push(win('after-burst-success',90,4624,{ipAddress:'192.0.2.10',targetUserName:'lab_alex'}));
events.push(win('process-context',100,1,{commandLine:'C:\\Windows\\System32\\whoami.exe',user:'STORYLAB\\lab_alex'}));
events.push(win('unapproved-admin',300,4732,{targetSid:'S-1-5-32-544',memberName:'STORYLAB\\lab_alex',subjectUserName:'lab_operator'}));
events.push(win('approved-admin',600,4732,{targetSid:'S-1-5-32-544',memberName:'STORYLAB\\lab_admin',subjectUserName:'lab_operator'}));
events.push({id:'unapproved-file',timestamp:t(800),agent:{name:'lab-linux-01'},syscheck:{event:'modified',path:'/etc/ssh/sshd_config'}});
events.push({id:'approved-file',timestamp:t(1000),agent:{name:'lab-linux-01'},syscheck:{event:'modified',path:'/etc/example/app.conf'}});
for(const [i,s] of [0,400,800,1200,1600].entries())events.push(win(`normal-retry-${i+1}`,s,4625,{ipAddress:'192.0.2.20',targetUserName:'lab_morgan'},'lab-win-02'));
const source=events.map(x=>JSON.stringify(x)).join('\n')+'\n';
const context={approvedChanges:['approved-admin','approved-file']};
await writeFile(new URL('fixtures/events.jsonl',root),source);
await writeFile(new URL('fixtures/context.json',root),JSON.stringify(context,null,2));
const loaded=loadJSONL(source),report=correlate(loaded.events,context);
report.provenance='SYNTHETIC REPLAY. The input mimics documented Wazuh/Windows event structures. This report was produced by the local Node.js pipeline, not a live Wazuh installation.';
report.ingestion={...loaded,events:undefined};
await writeFile(new URL('reports/demo/report.json',root),JSON.stringify(report,null,2));
await writeFile(new URL('reports/demo/index.html',root),renderHTML(report));
for(const item of report.incidents)await writeFile(new URL(`reports/demo/${item.id}.md`,root),incidentMarkdown(item,report.provenance));
const expected=[{rule:'AUTH-BURST',evidence:'burst-5'},{rule:'ADMIN-CHANGE',evidence:'unapproved-admin'},{rule:'FILE-CHANGE',evidence:'unapproved-file'}];
const match=(incident,label)=>incident.rule===label.rule&&incident.evidenceIds.includes(label.evidence);
const tp=expected.filter(label=>report.incidents.some(i=>match(i,label))).length;
const fp=report.incidents.filter(i=>!expected.some(label=>match(i,label))).length;
const fn=expected.length-tp;
const evaluation={scope:'Three hand-labeled positive scenarios and three negative controls in a synthetic fixture. Not a real-world accuracy estimate.',expectedPositiveCases:expected,negativeControls:['spaced retries on lab-win-02','approved-admin','approved-file'],truePositives:tp,falsePositives:fp,falseNegatives:fn,pass:tp===3&&fp===0&&fn===0};
await writeFile(new URL('fixtures/expected.json',root),JSON.stringify({expected,negativeControls:evaluation.negativeControls},null,2));
await writeFile(new URL('reports/demo/evaluation.json',root),JSON.stringify(evaluation,null,2));

// Separate raw JSON events for the optional native Wazuh rule test.
const native=[
 {id:'native-failure',timestamp:t(0),integration:'storylab',event:'auth_failure',srcip:'192.0.2.10',user:'lab_alex',agent:'lab-win-01'},
 {id:'native-success',timestamp:t(1),integration:'storylab',event:'auth_success',srcip:'192.0.2.10',user:'lab_alex',agent:'lab-win-01'},
 {id:'native-admin',timestamp:t(2),integration:'storylab',event:'admin_group_change',user:'lab_alex',actor:'lab_operator',agent:'lab-win-01'},
 {id:'native-file',timestamp:t(3),integration:'storylab',event:'file_change',path:'/etc/ssh/sshd_config',agent:'lab-linux-01'},
 {id:'native-process',timestamp:t(4),integration:'storylab',event:'process',command:'whoami',agent:'lab-win-01'}
];
await writeFile(new URL('fixtures/wazuh-input.jsonl',root),native.map(x=>JSON.stringify(x)).join('\n')+'\n');
await writeFile(new URL('fixtures/wazuh-expected.json',root),JSON.stringify(native.map((x,i)=>({id:x.id,ruleId:String(100101+i)})),null,2));
if(!evaluation.pass)throw new Error('Controlled scenario evaluation failed');
console.log(`Replay: ${loaded.events.length} events, ${report.incidents.length} cases; TP=${tp}, FP=${fp}, FN=${fn}. Native Wazuh validation is separate and has not been run.`);
