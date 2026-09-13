# Live lab completion checklist

Deployment checklist for a dedicated educational lab. The portable programs have been tested with synthetic data; the unchecked live deployment tasks have not been represented as completed.

## 1. Prepare the virtual machines

This example uses a Windows host with roughly 32 GB of RAM and enough storage for the three guest disks. Install a suitable VM manager and confirm virtualization support before starting.

Use a Windows-compatible VM manager, such as Oracle VirtualBox, and legitimate installation media. Download installers from the vendor. Review license and evaluation terms. Choose Windows Server with Desktop Experience for the domain controller, a domain-capable Windows client edition for the workstation, and a Wazuh-supported Linux distribution for the manager. Microsoft provides [Server](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025) and [Windows Enterprise](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise) evaluation information; a school-provided licensed client is also suitable.

These are suggested lab allocations, not measured workload requirements:

| VM name | Role | RAM / vCPU / disk | Internal address |
|---|---|---|---|
| LAB-DC01 | Windows Server AD DS and DNS | 4 GB / 2 / 60 GB | 192.168.56.10/24 |
| LAB-WIN01 | Windows domain client and Wazuh agent | 6 GB / 2 / 80 GB | 192.168.56.20/24 |
| LAB-SOC01 | Linux Wazuh all-in-one manager | 8 GB / 4 / 80 GB | 192.168.56.30/24 |

The Wazuh allocation follows its small-deployment [quickstart guidance](https://documentation.wazuh.com/current/quickstart.html), with extra disk space. Confirm the selected operating systems' current VM requirements before creation, including the Windows client's firmware/TPM requirements.

- [ ] Install and open the VM manager; finish any requested host restart.
- [ ] Create all three VMs and install their operating systems.
- [ ] Use NAT initially for updates, activation, and downloading packages. Install Wazuh while internet access is available, following its current quickstart.
- [ ] Download the Windows agent, Sysmon, and this project bundle into the appropriate guests.
- [ ] Shut down the VMs, switch their adapter to the same **Internal Network** named `storylab`, and configure the addresses above inside the guests. Leave the default gateway blank for this isolated phase.
- [ ] Point the Windows client DNS to 192.168.56.10; point the domain controller DNS to itself. Choose a different unused subnet and update the project configuration if this example overlaps another lab network.
- [ ] Take a clean baseline snapshot of each VM before domain or telemetry changes.

Internal networking allows communication among the selected VMs without exposing the lab to the physical network. View the dashboard from the Windows guest at `https://192.168.56.30`; the host cannot directly reach an Internal Network. See [Oracle's networking guide](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/networkingdetails.html). Internet-dependent updates and cloud features will be unavailable while the lab is isolated. Use a planned maintenance period to reconnect a VM to NAT and restore its lab address afterward.

## 2. Deploy the Windows domain

Inside the new Windows Server VM, rename the machine to **LAB-DC01** and restart before running the scripts. Open an administrator PowerShell session in `windows-support-lab`.

```powershell
.\powershell\New-LabDomain.ps1
.\powershell\New-LabDomain.ps1 -Apply
```

Review the confirmation and supply the lab recovery password. After successful forest creation, restart this VM manually. Sign in to the lab domain and continue:

```powershell
.\powershell\Provision-LabUsers.ps1
.\powershell\Provision-LabUsers.ps1 -Apply
.\powershell\Set-LabScreenLock.ps1 -Apply
New-Item -ItemType Directory -Path evidence/live -Force
.\powershell\Test-LabConfiguration.ps1 | Set-Content -Encoding UTF8 evidence/live/ad-verification.json
```

Use a unique temporary password for these fictional lab accounts. Do not reuse a personal password. The script requires users to change it at first sign-in. Keep passwords out of saved transcripts.

- [ ] Confirm the domain is `storylab.test` and the StoryLab Users/Groups OUs exist.
- [ ] Run `dcdiag` and investigate any failed checks; save a redacted report.
- [ ] On LAB-WIN01, verify domain DNS resolution, join `storylab.test`, and restart.
- [ ] Sign in as a `lab_` account and complete the required password change.
- [ ] Run `gpupdate /force` and `gpresult /h` for that signed-in lab user. Verify the five-minute idle lock behavior.
- [ ] Complete actual tickets using the [support runbook](https://github.com/StoryWright/windows-support-lab/blob/main/RUNBOOK.md) and retain evidence.

The supplied scripts do not configure a file share, a printer, lockout thresholds, or a help-desk service. Those prerequisites are identified in the runbook where needed. The scripts require a recognized lab VM and refuse to run domain creation on a workstation.

## 3. Deploy monitoring and validate it

Follow the [monitoring setup guide](https://github.com/StoryWright/security-monitoring-lab/blob/main/LIVE-SETUP.md) to enroll the Windows agent, enable auditing and Sysmon, merge configuration, and test the rules in the actual manager.

- [ ] Record Wazuh, Windows agent, Sysmon, and operating-system versions.
- [ ] Confirm current agent connectivity and endpoint clock synchronization.
- [ ] Run the native rule-test script and retain its actual result.
- [ ] Capture an actual Windows authentication event and an actual Sysmon process event in Wazuh.
- [ ] Capture a controlled file modification and a reviewed lab group change.
- [ ] Export a bounded set of the lab events and run the offline investigator on that export.
- [ ] Write conclusions supported by those events, then restore the test changes.

## Completion record

For each checked item record the date, VM, action, result, evidence filename, and any limitation. Only change a project's status from “prepared” to “deployed and verified” after the corresponding live evidence exists. A screenshot of the supplied synthetic HTML report demonstrates the local software; it does not demonstrate AD or Wazuh deployment.
