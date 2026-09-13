# Live Wazuh and Sysmon setup

This guide is prepared for the dedicated VMs described in the [live-lab checklist](docs/LIVE-LAB-CHECKLIST.md). The native installation and rule-engine checks are pending. Keep the generated replay reports as synthetic examples.

## Install and connect

1. Install the all-in-one Wazuh manager, indexer, and dashboard on LAB-SOC01 using the current [official quickstart](https://documentation.wazuh.com/current/quickstart.html). Review the downloaded installer before running it. Record the installed version and keep generated credentials private.
2. While internet access is available, download the matching Windows agent through the dashboard's deployment instructions and install [Sysmon from Microsoft](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) inside LAB-WIN01. Review the Sysmon installation options and record the active configuration.
3. After the VMs use their internal addresses, enroll the Windows agent with manager address 192.168.56.30. Confirm a recent connected status in the dashboard. Use the Windows guest to open the dashboard; the internal network is not directly reachable from the host.
4. Synchronize guest clocks and verify timezones. Check the Windows Security log has the necessary events. Enable success/failure Logon auditing and success Security Group Management auditing in the **lab's** applicable policy if those events are missing. Confirm policy application rather than assuming installation enables all auditing.
5. In Event Viewer, verify `Microsoft-Windows-Sysmon/Operational` contains event 1 after running a harmless command such as `whoami` inside the lab guest.

## Merge collection settings

Back up each existing configuration before editing. The supplied XML files are fragments; preserve the manager connection and other existing settings.

- On the Windows agent, merge the localfile blocks from `wazuh/windows-agent.fragment.xml` into its existing `ossec.conf`. Avoid duplicate Security or Sysmon channel collection. Create the lab directory `C:\StoryLab\watch` and add the provided directory entry to the existing `syscheck` section.
- On the Linux manager, its existing local collection can also demonstrate Linux events and file monitoring. Merge the relevant entries from `wazuh/linux-agent.fragment.xml` into existing sections, checking whether journald is already collected. If existing journald blocks use filters, adapt those filters to include the intended SSH service; an unfiltered additional block may not override them.
- Restart only the affected lab service after reviewing configuration, and inspect its own log for collection errors. The fragments have been checked as XML, but their acceptance by your installed Wazuh version must still be verified.

The Windows fragment includes Security 4624/4625/4728/4732 and Sysmon 1. An event appearing in Windows Event Viewer is one check; that event appearing in Wazuh is a separate check. The Wazuh alert file contains events that generated alerts, not necessarily every raw collected event. If a required event is absent from the alert export, inspect collection, auditing, and the installed rules before claiming coverage. Do not disable useful default rules to force a result.

## Test the native custom rules

On the lab manager, inspect existing custom rule IDs for collisions. The supplied range is 100100–100105, within Wazuh's documented custom range. If a collision exists, select unused custom IDs and update both the XML and fixture expectations.

Place `wazuh/storylab_rules.xml` in `/var/ossec/etc/rules/storylab_rules.xml` using the same owner/permissions as the existing custom rule files. Back up a same-named file before replacing it. Do not change vendor rules under the ruleset directory.

From this project folder on LAB-SOC01:

```sh
sudo python3 scripts/verify_wazuh.py
```

The script invokes the actual `wazuh-logtest` program. Review `reports/native-wazuh-validation.json`; all five expected classifications must match. If the command reports an error, correct it before restarting the manager to activate the rules for collection. This check classifies synthetic raw JSON; it does not validate Windows agent enrollment or real endpoint telemetry.

For an end-to-end synthetic collection check, create `/var/log/storylab/events.jsonl` in the lab, merge `wazuh/demo-localfile.fragment.xml`, restart the appropriate collector, and then append the five fixture records. Confirm those five custom IDs in the dashboard. Continue labeling them as demonstration events even though Wazuh collected them.

## Perform bounded live exercises

Use only the isolated VMs and disposable lab accounts. Record each start/end time and the approved test change.

| Exercise | Evidence to retain | Validation |
|---|---|---|
| Authentication | A small number of manually entered failed sign-ins to a lab service, followed by a successful lab sign-in | Check the actual source IP and account. Review the account's lockout policy first; keep the attempt count bounded. The detector needs five failures within 300 seconds to match. |
| Process context | Run `whoami` inside LAB-WIN01; capture Sysmon event 1 and its corresponding Wazuh record | Verify host, timestamp, process path, and command line. Temporal proximity alone does not link the process to a specific logon session. |
| Group change | Add one disposable lab account to local Administrators on LAB-WIN01 under a documented lab change, then remove it | Capture the membership-change event, the approved change record, and proof that the temporary membership was removed. Do not use Domain Admins for this exercise. |
| File change | Create a harmless text file in `C:\StoryLab\watch`, let the baseline complete, then edit it | Retain before/after contents or hashes and the FIM event. Do not alter SSH access configuration merely to produce a screenshot. |

Export only the relevant records from `/var/ossec/logs/alerts/alerts.json` for the test hosts and recorded time window into a new JSONL file. Preserve originals privately and hash the export. If using a dashboard export, transform its structure into one full event object per line and document the transformation.

Transfer the authorized export into `evidence/live/` and run:

```text
node src/cli.js --input evidence/live/alerts.jsonl --output-dir reports/live/run-01 --strict
```

For approved changes, create a separate context file such as `{"approvedChanges":["actual-event-id"]}` only after matching that event to the recorded change approval; pass it with `--context`. Examine each case against the original events. Save analyst conclusions and restoration evidence. The software creates investigation leads; no automatic containment occurs.

## Done means

Retain installed versions, agent health, native rule-test results, original event evidence, exported data provenance, local analysis results, and an explanation of missed/ignored events. A passing synthetic replay alone does not complete this checklist.

References: [Custom rule workflow](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html), [JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html), [localfile configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html).
