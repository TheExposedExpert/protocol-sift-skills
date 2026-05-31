# Skill: Loki-RS

## Installation
Neo23x0 Loki-RS downloaded from https://github.com/Neo23x0/Loki-RS/releases/<br>
Tool is extracted to /home/sansforensics/Tools/Loki-RS/loki-linux-x86_64-<version>/ directory.


## Overview
Use this skill for triaging raw memory images, mounted disk images, or folder paths<br>
with included set of YARA rules.


## Execution
The tool includes two binaries:

loki-util - For upgrading the tool and updating latest set of YARA-rules.<br>
loki - Running YARA scan against provided target.

ALWAYS run loki-util first for upgrading the tool to the latest version and updating<br>
include set of YARA rules to the latest ones.

ALWAYS run loki with --no-procs parameter to prevent scanning SANS SIFT host process memory.<br>
ALWAYS run loki with --cpu-limit 50 parameter to prevent system resource exhaustion.<br>
ALWAYS run loki against folder paths with --scan-all-files parameter to scan all files.<br>
ALWAYS run loki with --max-reasons 0 parameter to display all reasons.<br>
ALWAYS run loki with --no-tui parameter to disable graphical user interface.<br>
ALWAYS run loki with sudo privileges against mounted disk images.<br>
ALWAYS run loki with --jsonl parameter to include output file for automatic processing via command line tools.<br>
ALWAYS run loki with --log parameter to confirm that processing was successful.<br>
ALWAYS run loki without --no-html parameter to create an HTLM report from loki scan.


## Common loki-util parameters

| Parameter | Values | Information |
|-----------|--------|-------------|
| --help | none | Print tool help information |
| update | none | Update YARA rules (YARA-Forge Core) |
| upgrade | none | Update Loki-RS program and signatures |


## Common loki parameters

| Parameter | Values | Information |
|-----------|--------|-------------|
| --help | none | Print tool help information |
| --folder | <PATH_TO_FOLDER> | Folder to scan |
| --scan-all-files | none | Scan all files regardless of their file type / extension |
| --no-procs | none | Don't scan processes |
| --no-tui | none | Disable TUI and use standard command-line logging |
| --cpu-limit | 1-100 | CPU utilization limit percentage (1-100) [default: 100] |
| --max-file-size | <BYTES> |  Maximum file size to scan in bytes [default: 64000000] |
| --max-reasons | <MAX_REASONS> | Maximum number of match reasons to display per finding [default: 2] |
| --jsonl | <JSONL> | Specify JSONL output file (defaults to loki_<hostname>_<date>.jsonl) |
| --log | <LOG> | Specify log output file (defaults to loki_<hostname>_<date>.log) |
