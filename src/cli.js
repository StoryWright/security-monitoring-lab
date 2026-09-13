import {readFile,writeFile,mkdir,stat,readdir} from 'node:fs/promises';
import {join} from 'node:path';
import {loadJSONL,correlate,renderHTML,incidentMarkdown} from './monitor.js';
try {
 const opts={};
 for(let i=2;i<process.argv.length;i++){
  const key=process.argv[i];
  if(key==='--help'){console.log('node src/cli.js --input alerts.jsonl --output-dir reports/live [--context context.json] [--strict]\nReads Wazuh alerts or storylab JSON events. Reports are offline analysis, not live monitoring.');process.exit(0);}
  if(key==='--strict'){opts.strict=true;continue;}
  if(!['--input','--output-dir','--context'].includes(key)||!process.argv[i+1]||process.argv[i+1].startsWith('--'))throw new Error('Invalid or incomplete option');
  if(opts[key])throw new Error('Duplicate option');opts[key]=process.argv[++i];
 }
 if(!opts['--input']||!opts['--output-dir'])throw new Error('Specify --input and --output-dir');
 const existing=await readdir(opts['--output-dir']).catch(error=>{if(error.code==='ENOENT')return [];throw error;});
 if(existing.length)throw new Error('Use a new or empty output directory to preserve prior evidence and avoid stale reports');
 if((await stat(opts['--input'])).size>64*1024*1024)throw new Error('Input exceeds 64 MiB');
 const loaded=loadJSONL(await readFile(opts['--input'],'utf8'));
 if(opts.strict&&loaded.errorCount){console.error(JSON.stringify(loaded.errors));process.exit(3);}
 const context=opts['--context']?JSON.parse(await readFile(opts['--context'],'utf8')):{};
 const report=correlate(loaded.events,context);report.ingestion={...loaded,events:undefined};
 report.provenance='Offline analysis of the supplied event file. This tool does not independently establish whether input events are live or simulated.';
 await mkdir(opts['--output-dir'],{recursive:true});
 await writeFile(join(opts['--output-dir'],'report.json'),JSON.stringify(report,null,2));
 await writeFile(join(opts['--output-dir'],'index.html'),renderHTML(report));
 for(const item of report.incidents)await writeFile(join(opts['--output-dir'],`${item.id}.md`),incidentMarkdown(item,report.provenance));
 console.log(`Analyzed ${loaded.events.length} events; ${report.incidents.length} cases; ${loaded.errorCount} rejected lines.`);
}catch(error){console.error(`Error: ${error.message}`);process.exitCode=1;}
