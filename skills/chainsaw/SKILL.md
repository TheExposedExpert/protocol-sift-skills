# Skill: Chainsaw

## Installation
WithSecure Chainsaw downloaded from https://github.com/WithSecureLabs/chainsaw/releases/<br>
Tool is extracted to /home/sansforensics/Tools/Chainsaw/chainsaw/ directory.


## Overview
Use this skill for triaging Windows Event Log .evtx files with included set of Sigma rules.


## Execution
The tool includes a single binary:

| Tool | Description |
|------|-------------|
| chainsaw_x86_64-unknown-linux-gnu | Running Sigma scan against provided target folder |

The tool includes two main functions:

| Parameter | Function |
|-----------|----------|
| hunt | Hunt for threats using Sigma detection rules and custom Chainsaw detection rules |
| search | Search and extract forensic artefacts by string matching, and regex patterns |

ALWAYS verify that execution has completed succesfully.


## Common chainsaw_x86_64-unknown-linux-gnu parameters

| Parameter | Values | Information |
|-----------|--------|-------------|
| --help | none | Print tool help information |


## Common hunt function parameters

ALWAYS run chainsaw hunt with --timezone UTC parameter to output timestamps in UTC timezone.

| Parameter | Values | Information |
|-----------|--------|-------------|
| --help | none | Print tool help information |
| --sigma | <PATH_TO_FOLDER> | A path containing Sigma rules to hunt with [default: sigma/] |
| --mapping | <PATH_TO_FILE> | A mapping file to tell Chainsaw how to use third-party rules [default: mappings/sigma-event-logs-all.yml] |
| --rule | <PATH_TO_FOLDER> | A path containing additional rules to hunt with [default: rules/] |
| --from | "<YYYY-MM-ddTHH:mm:SS>" | The timestamp to hunt from. Drops any documents older than the value provided |
| --to | "<YYYY-MM-ddTHH:mm:SS>" | The timestamp to hunt up to. Drops any documents newer than the value provided |
| --output | <PATH_TO_FOLDER> | A path to output results to |
| --json | none | Print the output in json format |
| --jsonl | none | Print the output in jsonl format |
| --csv | none | Print the output in csv format |
| --timezone | <TIMEZONE> | Output the timestamp using the timezone provided |

Command Examples

Hunt through all evtx files using Sigma rules for detection logic:
```bash
./chainsaw hunt evtx_attack_samples/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml
```

Hunt through all evtx files using Sigma rules and Chainsaw rules for detection logic and output in CSV format to the results folder:
```bash
./chainsaw hunt evtx_attack_samples/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/ --csv --output results
```

Hunt through all evtx files using Sigma rules for detection logic, only search between specific timestamps, and output the results in JSON format:
```bash
./chainsaw hunt evtx_attack_samples/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml --from "2019-03-17T19:09:39" --to "2019-03-17T19:09:50" --json
```


## Common search function parameters

ALWAYS run chainsaw search with --timezone UTC parameter to output timestamps in UTC timezone.

| Parameter | Values | Information |
|-----------|--------|-------------|
| --help | none | Print tool help information |
| --regex | <pattern> | A string or regular expression pattern to search for |
| --ignore-case | none | Ignore the case when searching patterns |
| --tau | <TAU> | Tau expressions to search with. e.g. 'Event.System.EventID: =4104'. Multiple conditions are logical ANDs unless the 'match-any' flag is specified |
| --from | "<YYYY-MM-ddTHH:mm:SS>" | The timestamp to hunt from. Drops any documents older than the value provided |
| --to | "<YYYY-MM-ddTHH:mm:SS>" | The timestamp to hunt up to. Drops any documents newer than the value provided |
| --output | <PATH_TO_FOLDER> | A path to output results to |
| --json | none | Print the output in json format |
| --jsonl | none | Print the output in jsonl format |
| --csv | none | Print the output in csv format |
| --timezone | <TIMEZONE> | Output the timestamp using the timezone provided |

Example commands:

Search all .evtx files for the case-insensitive string "mimikatz":
```bash
./chainsaw search mimikatz -i evtx_attack_samples/
```

Search all .evtx files for powershell script block events (Event ID 4014):
```bash
./chainsaw search -t 'Event.System.EventID: =4104' evtx_attack_samples/
```

Search a specific evtx log for logon events, with a matching regex pattern, output in JSON format:
```bash
./chainsaw search -e "DC[0-9].insecurebank.local" evtx_attack_samples --json
```


## Using custom Sigma rules

Using the --sigma and --mapping parameters you can specify a directory containing a subset
of SIGMA detection rules (or just the entire SIGMA git repo) and chainsaw will automatically
load, convert and run these rules against the provided event logs. The mapping file tells
chainsaw which fields in the event logs to use for rule matching. See the mapping file for the
full list of fields that are used for rule detection, and feel free to extend it to your needs.


## Using custom rules

In addition to supporting sigma rules, Chainsaw also supports a custom rule format.
In the repository you will find a "rules" directory that contains various Chainsaw rules.
