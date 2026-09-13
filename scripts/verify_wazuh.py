"""Run the real Wazuh decoder/rule engine. This is deliberately separate from Node tests."""
import argparse, json, re, subprocess
from pathlib import Path
from datetime import datetime, timezone

root=Path(__file__).resolve().parent.parent
parser=argparse.ArgumentParser()
parser.add_argument('--binary',default='/var/ossec/bin/wazuh-logtest')
args=parser.parse_args()
binary=Path(args.binary)
if not binary.is_file():
    raise SystemExit('Native Wazuh validation NOT RUN: wazuh-logtest is not available. Run this inside the configured Wazuh manager VM.')
records=[json.loads(line) for line in (root/'fixtures/wazuh-input.jsonl').read_text().splitlines() if line.strip()]
expected={x['id']:x['ruleId'] for x in json.loads((root/'fixtures/wazuh-expected.json').read_text())}
results=[]
for record in records:
    process=subprocess.run([str(binary)],input=json.dumps(record)+'\n',capture_output=True,text=True,timeout=20)
    matched=re.findall(r"\bid:\s*['\"]?(\d+)",process.stdout+process.stderr)
    actual=matched[-1] if matched else None
    results.append({'eventId':record['id'],'expectedRule':expected[record['id']],'actualRule':actual,'exitCode':process.returncode,'passed':actual==expected[record['id']] and process.returncode==0})
report={'scope':'Actual Wazuh logtest subprocess results','capturedAt':datetime.now(timezone.utc).isoformat(),'binary':str(binary),'results':results,'passed':all(x['passed'] for x in results)}
(root/'reports').mkdir(exist_ok=True)
(root/'reports/native-wazuh-validation.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report,indent=2))
raise SystemExit(0 if report['passed'] else 1)
