# Skill: Timeline Generation (Plaso / log2timeline)

## Overview
Use this skill for all super-timeline creation, filtering, and analysis tasks using the
Plaso suite on the SANS SIFT workstation. Plaso parses hundreds of artifact types from
disk images, mounted filesystems, folder structures, and individual files into a unified
timeline.

Plaso super-timeline includes multitude of artefacts in a single file per evidence source.
Prefer full plaso super-timeline in JSONL format.
The JSONL files can be easily hunted against case IOCs with tools such as jq.


## Tools

| Tool | Purpose |
|------|---------|
| `log2timeline` | Parse evidence sources into a Plaso storage file (.plaso) |
| `psort` | Filter, sort, and export Plaso storage to CSV/JSON/JSONL/other formats |
| `pinfo` | Inspect Plaso storage file metadata and parser hit statistics |
| `psteal` | One-step: parse + export without creating an intermediate .plaso file |
| `image_export` | Extract specific files from disk images for targeted analysis |


## Available plaso tools

Always test that plaso tools are available and successfully return current version 
of the tool. If the tool is not available, please refer to the installation instructions.

| Tool | Docker |
| ---- | ------ |
| log2timeline | docker run log2timeline/plaso log2timeline.py --version |
| psort | docker run log2timeline/plaso psort.py --version |
| pinfo | docker run log2timeline/plaso pinfo.py --version |
| psteal | docker run log2timeline/plaso psteal.py --version |
| imageexport | docker run log2timeline/plaso image_export.py --version |


### Common log2timeline parameters

Always process evidence with hashers option none unless stated otherwise.
Hashing thousands of files is CPU intensive and takes significant amount of time.

Always process Windows disk image files with partitions option all unless stated otherwise.
Disk image files include multiple Windows partitions.

Always process Windows disk image files with volumes option all unless stated otherwise.
Windows partitions can include multiple volumes.

Always process Windows volumes with VSS stores option all unless stated otherwise.
Windows volumes can include files in VSS stores.

Always process Windows evidence items with parsers option win10,mft unless stated otherwise.

| Parameter | Values | Information |
|-----------|--------|-------------|
| --help | none | Print tool help information |
| --hashers | md5,sha1,sha256,none | Create hash value of processed files |
| --parsers | linux,macos,win10,win7,mft | Define plaso parsers to be used. Includes other options as well. Reference help if needed |
| --partitions | all | Define partitions to be processed. A range of partitions can be defined as: "3..5". Multiple partitions can be defined as: "1,3,5" (a list of comma separated values). All partitions can be specified with: "all". |
| --volumes | all | Define volumes to be processed. A range of volumes can be defined as: "3..5". Multiple volumes can be defined as: "1,3,5" (a list of comma separated values). All volumes can be specified with: "all". |
| --vss-stores | all | Define Volume Shadow Snapshots (VSS) (or stores) that need to be processed. A range of snapshots can be defined as: "3..5". Multiple snapshots can be defined as: "1,3,5" (a list of comma separated values). All snapshots can be defined as: "all" and no snapshots as: "none". |
| --credential | recovery_password:RECOVERY-KEY-GUID | Define a credentials that can be used to unlock encrypted volumes e.g. BitLocker. The credential is defined as type:data. Supported credential types are: key_data, password, recovery_password, startup_key. |
| --storage-file | <filename>.plaso | The path of the storage file, e.g. <timestamp>-<source>.plaso |


### Common pinfo parameters

Always verify created plaso files with pinfo utility.
Zero hits from expected parsers indicate wrong parser or a source evidence problem.

| Parameter | Values | Information |
|-----------|--------|-------------|
| --help | none | Print tool help information |


### Common psort parameters

Always output psort processed files as JSONL file type unless stated otherwise.

| Parameter | Values | Information |
|-----------|--------|-------------|
| --help | none | Print tool help information |
| --analysis | tagging | A comma separated list of analysis plugin names to be loaded |
| --tagging-file | /usr/share/plaso/tag_windows.txt,/usr/share/plaso/tag_linux.txt | Tagging file path location |
| -o | json,jsonl | The output format. |
| -w | <filename>.filetype | The path of the psort file, e.g. <timestamp>-<source>.jsonl |


## Workflow

### 1. Verify Evidence (Read-Only)

Determine first if the evidence item is:
- Disk image (VMDK, RAW, E01, etc.)
- Mount or folder path (mounted disk image, unzipped IR acquisition archive, log folder, etc.)
- Single file

```bash
# First check if provided evidence is a disk image file or a zip file.
file /path/to/evidence.filetype

# Verify that a mount or folder path includes forensic artefacts.
ls -alh /path/to/evidence/folder/
```


### 2a. Create Super-Timeline (E01)
```bash
log2timeline \
  --storage-file ./analysis/<CASE_ID>_<EVIDENCE_ID>.plaso \
  /path/to/evidence.E01
```

### 2b. Create Super-Timeline (unzipped folder path)
```bash
log2timeline \
  --storage-file ./analysis/<CASE_ID>.plaso \
  /path/to/unzipped/folder/
```


### 3. Inspect plaso file

```bash
# Show parser statistics, source info, and event count
pinfo.py ./analysis/<CASE_ID>.plaso >> ./analysis/<CASE_ID>.pinfo

# Verbose — show all parsers and their individual event counts
pinfo.py -v ./analysis/<CASE_ID>.plaso >> ./analysis/<CASE_ID>.pinfo
```


### 4. Filter & Export

```bash
# Export all events to CSV (l2tcsv — compatible with Timeline Explorer)
psort.py -o l2tcsv \
  -w ./exports/<CASE_ID>_timeline.csv \
  ./analysis/<CASE_ID>.plaso

# Export to dynamic CSV (more columns, better for script-based pivoting)
psort.py -o dynamic \
  -w ./exports/<CASE_ID>_dynamic.csv \
  ./analysis/<CASE_ID>.plaso

# Export to JSON (for scripted processing)
psort.py -o json \
  -w ./exports/<CASE_ID>_timeline.json \
  ./analysis/<CASE_ID>.plaso

# Filter by date/time range (UTC)
psort.py -o l2tcsv \
  -w ./exports/<CASE_ID>_filtered.csv \
  ./analysis/<CASE_ID>.plaso \
  "date > '2023-01-01 00:00:00' AND date < '2023-02-01 00:00:00'"

# Filter by keyword in the message/description field
psort.py -o l2tcsv \
  -w ./exports/<CASE_ID>_powershell.csv \
  ./analysis/<CASE_ID>.plaso \
  "message contains 'powershell'"

# Combined filter: time range AND keyword
psort.py -o l2tcsv \
  -w ./exports/<CASE_ID>_combined.csv \
  ./analysis/<CASE_ID>.plaso \
  "date > '2023-01-24 00:00:00' AND date < '2023-01-26 00:00:00' AND message contains 'cmd.exe'"

# Filter by parser/data source type
psort.py -o l2tcsv \
  -w ./exports/<CASE_ID>_evtx.csv \
  ./analysis/<CASE_ID>.plaso \
  "parser contains 'winevtx'"

# Quick pivot: events within 5 minutes of a known timestamp
psort.py -o l2tcsv \
  -w ./exports/<CASE_ID>_slice.csv \
  --slice '2023-01-25 14:52:00' \
  ./analysis/<CASE_ID>.plaso
```

### 5. Merging Multiple .plaso Files

When you've run separate ingest jobs (e.g., disk + evtx directory + memory bodyfile):

```bash
psort.py \
  -o l2tcsv \
  -w ./exports/<CASE_ID>_merged.csv \
  ./analysis/<CASE_ID>_disk.plaso \
  ./analysis/<CASE_ID>_evtx.plaso \
  ./analysis/<CASE_ID>_fls.plaso
```

`psort.py` accepts multiple `.plaso` files and outputs them in a single chronological export.

---

## Extract Files from Image (image_export.py)

Extract specific files from a disk image without mounting it:

```bash
# Export files matching a name pattern
image_export.py \
  --write ./exports/files/ \
  --name "*.evtx" \
  /mnt/ewf/ewf1

# Export files by extension
image_export.py \
  --write ./exports/files/ \
  --extension "pf,lnk" \
  /mnt/ewf/ewf1

# Export files using a filter file (one path pattern per line)
# Example filter.txt contents:
#   /Windows/System32/winevt/Logs/
#   /Windows/Prefetch/
#   /Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat
image_export.py \
  --write ./exports/files/ \
  --filter /path/to/filter.txt \
  /mnt/ewf/ewf1
```

---

## Key Flags Reference

**log2timeline.py:**
| Flag | Description |
|------|-------------|
| `--storage-file <file>` | Output .plaso storage file path |
| `--parsers <set>` | Parser preset or comma-separated list |
| `--hashers md5,sha256` | Hash all processed files |
| `--timezone UTC` | Always use UTC |
| `--vss-stores all` | Process all Volume Shadow Copies |
| `--vss-stores 1,2` | Process specific VSS store numbers |
| `--single-process` | Debug mode — slower, better error messages |
| `-q` | Quiet mode (suppress progress bar) |
| `--worker-memory-limit N` | Limit per-worker RAM in MB (default: 3072) |

**psort.py:**
| Flag | Description |
|------|-------------|
| `-o <format>` | Output format: `l2tcsv`, `dynamic`, `json` |
| `-w <file>` | Write output to file |
| `--slice <datetime>` | Events within 5 min of this timestamp (quick pivot) |
| `-z UTC` | Force UTC output timezone |

---

## Filtering in Timeline Explorer (GUI)

After exporting to CSV, open in Timeline Explorer (`wine` or Windows VM):

```bash
wine /opt/zimmermantools/TimelineExplorer/TimelineExplorer.exe
```

Key filtering strategy in Timeline Explorer:
- **Source** column — filter to artifact type (EVT, FILE, REG, WEBHIST, etc.)
- **Type** column — narrow to event sub-type (e.g., `Last Written Time`)
- **Message** column — primary search target; use Ctrl+F for keyword search
- **Tag** column — mark events of interest; export tagged-only subset

---

## Output Paths

| Output | Path |
|--------|------|
| Plaso storage | `./analysis/<CASE_ID>.plaso` |
| CSV timelines | `./exports/<CASE_ID>_timeline.csv` |
| Filtered CSVs | `./exports/<CASE_ID>_filtered.csv` |
| Extracted files | `./exports/files/` |

---

## Notes

- `win10` parser preset is the correct choice for Windows 10/11 and Windows Server 2016+
- `win7` parser still works on modern Windows images but may miss newer artifact types
- `--vss-stores all` is essential for intrusion cases — attackers often delete files VSS preserves
- NEVER write .plaso or CSV output to `/mnt/` or `/media/` — always use `./analysis/` or `./exports/`
- `pinfo.py` after ingest is mandatory — zero parser hits means configuration error, not a clean system
- Large images (>100 GB) can take hours; use targeted `--parsers` or path-scoped ingest to reduce time
- `psort.py` accepts multiple .plaso files — merge disk + memory bodyfile + log timelines into one export
- `--slice` in psort is invaluable for quick pivots around a known event timestamp
