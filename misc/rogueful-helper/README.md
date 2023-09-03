Rogueful Helper
============

**Category:** misc

**Difficulty:** medium

**Author:** Conletz

**Files:**
- [DUPWS213_investigation_package.enc.zip](https://bigfiles.duc.tf/DUPWS213_investigation_package.enc.zip)

The DUC Corp security team began receiving alerts for reconaissance activity from a newly installed workstation. 
Analysts have put together a brief investigation package for triage.

- What was the ICMP Payload used for the task that finished 2023-08-26 15:32:20?

Password for encrypted zip is `quooz6cuin5Aiw2aiRue9een2eimuviem2ibi2Ahr7Chiepeof9oxuz5oofeu1oo`

Flag format: 'DUCTF{args}'
---

## Solution

After some intial triage (windows event logs, MFT timeline or simple searching the investigation package) it becomes clear that nmap was the reconaissance tool being utilised.
There is a lack of appropriate windows event logging, therefore there is no capture of nmap being run at any point (only references to NPCAP).

Of note is the location of nmap (under the Kaseya VSA file structure). MOre research would show this is due to nmaps use in network discovery by Kaseya.
The nmap XML files are no longer present on the host. Poking around brings you across audit.s3db. OPening this database file will show a number of network discovery 'tasks' with a start and end time.
The answer is the the full args column under task 3.
