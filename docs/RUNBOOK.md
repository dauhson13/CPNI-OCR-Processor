# CPNI OCR Processor runbook

piiscan scans a file share for sensitive data:

- **Scanned pages first.** It straightens scanned pages and reads them, typed and handwritten.
- **What it finds:** SSNs, customer accounts, driver's licenses, bank and card numbers, CPNI and more.
- **What it records:** the type of each finding and where it is, in a local database. It never stores the values themselves.

Everything runs on this machine. Scans never use the network, and the files on the share are only read, never changed.

## 1. Setup (once per machine)

| Step | macOS | Windows 10/11 |
|---|---|---|
| Install uv | `brew install uv` | `winget install astral-sh.uv` |
| Get the project | `git clone https://github.com/dauhson13/CPNI-OCR-Processor.git` | same |
| Install everything | `uv run scripts/setup.py` | `uv run scripts/setup.py` |
| Old Word/PowerPoint (.doc/.ppt), optional | `brew install --cask libreoffice` | `winget install TheDocumentFoundation.LibreOffice` |
| Point it at the share | `PIISCAN_ROOT=/Volumes/Share` in `.env` | `PIISCAN_ROOT=\\server\share` in `.env` |

**What setup does:**

- Installs Python 3.12 and all packages.
- Creates the dedupe key at `~/.piiscan/hmac.key`. **Back that key up**: a new key can't be matched against earlier results.
- Downloads the OCR models, the handwriting base model and the handwriting fonts into `models/`. This is the only time piiscan uses the network.

**Share access:**

- **macOS:** mount the share first (Finder → Go → Connect to Server).
- **Windows:** use the UNC path directly.
- **Either way:** give the account that runs the scan **read-only** access to the share.

## 2. Commands

Run these from the project folder. In VS Code, the Run button on `main.py` opens the labeling window.

| Command | What it does |
|---|---|
| `uv run main.py scan` | Scan `PIISCAN_ROOT`. Prints a total for each PII type. On re-runs, a file is skipped only if it's unchanged **and** was read by the current scanner. After an update to piiscan, a retrained handwriting model, or a change to your types, older files are re-read automatically; the scan says how many first. |
| `uv run main.py scan --changed-only` | Read only new or modified files, even if the scanner or your types changed since. Faster, but older results stay as they were. |
| `uv run main.py scan --full` | Re-read every file, whatever changed. |
| `uv run main.py scan <folder>` | Scan a different folder. |
| `uv run main.py totals` | Print the totals again without scanning. Applies the current bypass list first (see §4), so company info you just bypassed drops out at once. |
| `uv run main.py review` | Go through low-confidence findings: confirm or reject each one. Rejected findings stop counting. |
| `uv run main.py label` | Open the labeling window (see §4). |
| `uv run main.py train` | Retrain the handwriting model with your labels. About 30 min on a Mac GPU. |
| `uv run main.py eval` | Accuracy numbers (see §5). |
| `uv run main.py schedule --at 02:00` | Scan every night: Task Scheduler on Windows, launchd on macOS. `--remove` turns it off. Output goes to `data/logs/scan.log`. |

## 3. Reading the totals

```
last scan:       completed, started 2026-10-23T02:00:04+00:00, finished 2026-10-23T05:41:12+00:00 (ok 310, unchanged 18255)
files by status: corrupt 3, encrypted 12, ok 18340, unsupported 210
files by type:   image 4100, ooxml 6200, pdf 7900, text 2100, ...
scanned pages:   need rotation 2900, scanned 15800

PII type                 found   different     files
SSN                       1830        1204       611
CUSTOMER_ACCOUNT          5400        3100      2380
DRIVERS_LICENSE            410         395       390
...
```

- **last scan** says whether the most recent scan (including the nightly one) finished, and how many files it read or skipped. If it says `failed` or the date is old, the database isn't being updated: see §7.
- **found** is every occurrence.
- **different** is how many distinct values. The same SSN in five files counts once there.
- **files** is how many files contain that type. A member of a zip or an email attachment counts toward its container file.
- Findings that match your **bypass list** (company info) aren't counted. A line under the table says how many there were.
- Types you added yourself appear under the code shown when you added them (e.g. `EMPLOYEE_ID`).

**What the file statuses mean:**

| Status | Meaning |
|---|---|
| `ok` | Read and checked. |
| `encrypted` | Password-protected; it can't be read. Handle by hand. |
| `corrupt` | Damaged, or a format the reader choked on. |
| `unsupported` | Not a document type piiscan reads, or a .doc/.ppt without LibreOffice. |
| `too_large` | Over a safety limit, such as a zip bomb or a huge archive. |
| `timeout` / `error` | Something went wrong. These files are retried automatically on the next run. |

## 4. Labeling and training the handwriting model

1. Run `uv run main.py label` (or press Run on `main.py`). Pick a scan from the list on the left; its page opens already straightened.
   - **Find** narrows the list by file name. The drop-down switches between all scans and only those not complete yet.
   - The line above the list shows how many are complete.
   - **File → Open folder…** switches to another folder without restarting.
2. If the page still isn't straight, use the rotate buttons first. Your correction is saved and used to measure rotation accuracy.
   - While a page is being straightened and read, the bar at the bottom right moves and the window stays usable. Clicks on the page wait until it's ready.
3. **Zoom in to read small handwriting:** **+**, **Fit** and **−** above the page, or Cmd/Ctrl with the mouse wheel. When zoomed in, the wheel and the scrollbars move around the page. Boxes land in the right place at any zoom.
4. **Check what the scanner found.**
   - Its findings are drawn as **dashed** boxes, each in its type's colour (the coloured squares in the type list are the legend).
   - Click a dashed box: it loads with its type ticked and the text the scanner read.
   - If the type or text is wrong, fix it. If the field isn't sensitive at all, tick **None**. Then press Enter.
   - Your corrections are exactly what training needs.
5. For anything the scanner missed, drag a box around **one line** of a field.
   - **Tick every type that applies.** The list scrolls, and is grouped as follows:
     - **Identification:** driver's license #, state ID #, passport #, ITIN, date of birth.
     - **SSN.**
     - **Bank info:** account #, routing #, card #, card expiration / CVV.
     - **CPNI:** customer account #, phone #, call detail, usage, services/plan, billing amount, payment history, service/E911 address, IP address, MAC address, equipment serial/device ID, circuit ID, account password/PIN, security answer.
     - **Other:** name, address, email.
   - Tick **None** for handwriting with nothing sensitive in it; that still trains the reader and checks for false alarms. None and the other types switch each other off.
   - **Type exactly what's written**, including partial or missing digits.
   - **Tick "Handwritten"** if it is, then press Enter.
   - Saved labels are **solid** boxes with their types, and replace the scanner's suggestion.
   - **Cmd/Ctrl+Z** undoes the last label you saved. **Delete** removes a selected saved label (not while you're typing in the text box).
6. **Add your own types** with **+ Add type** (top of the type list):
   - Pick a group and give it a name (e.g. *Employee ID*, *Port-out PIN*).
   - List the words printed next to it on your forms, separated by commas (e.g. `employee id, emp #`). Left blank, the name is used.
   - It joins the list straight away, and scans find it after those words or under a column with that heading.
   - Run `uv run main.py scan --full` once, so files that were already scanned get checked for it.
7. **Bypass your company's own info:** your phone numbers, address, email and so on appear on every bill and form, and shouldn't count.
   - Click the scanner's dashed box on it, or tick its type and type it exactly as printed.
   - Press **Bypass: company info**. It stops counting in new scans, and earlier findings drop out the next time `scan` or `totals` runs.
   - Add each written variant once: the address with and without the suite, every toll-free and local number.
8. **Your types & bypass list…** shows both lists. Remove an entry there; you're asked first.
   - A type can only be removed once no saved label uses it.
   - A removed bypass value counts again from the next `scan` or `totals`.
9. Finish the document:
   - **Complete ✓** (Cmd/Ctrl+Return) marks it finished (✓ in the list) and opens the next unfinished document. Pages you viewed but didn't label count as having nothing to label, and their rotation is recorded.
   - **Next document ▶** (Cmd/Ctrl+→) moves on without marking it finished.
   - If you have a box with text you haven't saved, the window asks before it moves on or closes.
10. After you've labeled a batch, run `uv run main.py train`. Each run starts from the current model.

**Shortcuts** (Cmd on a Mac, Ctrl on Windows; also listed under **Help**):

| Keys | Does |
|---|---|
| Enter / Esc | Save the label / clear the box |
| PgUp / PgDn | Previous / next page |
| Cmd/Ctrl+Z | Undo the last label saved |
| Delete | Delete the selected saved label |
| Cmd/Ctrl+→ / Cmd/Ctrl+Return | Next document / complete |
| Cmd/Ctrl+= / − / 0 | Zoom in / out / fit |
| Cmd/Ctrl+O / Q | Open another folder / quit |

If something goes wrong in the window, the status line names the error type and where in the code it happened, never what the document says. The window keeps working.

**How training treats your labels:**

- **No overfitting:** each label is shown about 20 times per run at most, so a handful of labels can't be memorized. As you add more, more of each batch comes from them, up to 30%.
- **It never gets clearly worse:** while you have fewer than 20 held-out labels, a run is kept if its synthetic score stays within 0.01 of the current model's, so your labels get in. After that, it must beat the current model on your held-out labels. Otherwise training ends with "kept unchanged".
- **Scoring:** a fixed 10% of your labels is never trained on. Once 20+ of those exist, they decide which version is kept. Before that, synthetic handwriting decides.

**Where it goes:**

- Labels, crops and the list of completed documents go to `data/training/`. The trained model goes to `models/handwriting/`.
- Both contain real PII from your scans. Keep them on this machine and don't share them.

## 5. Measuring accuracy

`uv run main.py eval` prints:

- **Precision / recall / F1 for each PII type** on synthetic documents with planted values. The documents cover text, Word, PDF, crooked typed scans and handwritten forms. Recall is also broken down by kind of document.
- **Character error rate** for printed and handwritten text.
- **From your labels:**
  - the error rate on the held-out 10%;
  - how often automatic rotation matched your corrections;
  - how many fields you marked None the scanner would still flag, and as which types. If those are mostly your company's phone or address, add them to the bypass list.

All output is aggregate numbers, so it's safe to share.

## 6. Data handling and security

| What | Where | Notes |
|---|---|---|
| Findings, file list, scan history, audit log | `data/piiscan.db` | Holds no values: just type, location, confidence and a keyed hash. File paths can still be sensitive. |
| Your labels and crops | `data/training/` | Real PII from your own scans. |
| Your types and bypass list | `data/rules.json` | The types you added and your company's own info (phone numbers, addresses). Not customer data, but specific to your company, so it stays out of git. |
| Models and fonts | `models/` | The handwriting model is trained on your labels, so treat it as sensitive. |
| Dedupe key | `~/.piiscan/hmac.key` | Kept outside the project, so a copy of `data/` alone can't reverse the hashes. |

- **Never committed:** `data/`, `models/` and `.env` are excluded from git.
- **Encryption:** keep the machine's disk encrypted (FileVault / BitLocker).
- **Cloud sync:** keep the project out of cloud-synced folders (iCloud Desktop & Documents, OneDrive).
- **Backups:** exclude `data/` from any cloud backup.
- **Owner-only files:** everything piiscan creates can be read only by the account that created it.
- **No text kept:** extracted text exists only in memory while a file is processed, and scanned pages are straightened in memory.
- **Clean errors:** errors record the error type and code location, never the message, because messages can quote document content.
- **Audit log:** every scan, review decision and file read is in the database's audit log. The log can't be edited or deleted through SQL.
- **AI assistants:** don't open real scans in an editor while an AI assistant session is running: selected text can be sent to it.

## 7. Troubleshooting

| Symptom | Check |
|---|---|
| A scan finds nothing | Look at `files by status`. Mostly `unsupported` means unreadable formats (install LibreOffice for .doc/.ppt). Mostly `ok` means the PII may be written in a way the detector misses: run `eval`, label some examples, and tell the developer what the fields look like (no real values). |
| The database isn't updating | Run `uv run main.py totals` and look at **last scan**. If it's old, the nightly job didn't run: check `data/logs/scan.log`, and on a Mac that the share was mounted. If it says `failed`, the log shows why. If you scanned with `--changed-only`, files read by an older scanner kept their old results; run a plain `scan`. |
| Results look stale after an update | A plain `scan` re-reads files that an older scanner read. `--full` re-reads everything. |
| Your company's phone or address is counted | Add it to the bypass list in the labeling window (§4), then `uv run main.py totals`. Add each written variant once (with and without the suite, toll-free and local numbers). |
| A type you added finds nothing in old files | Files that haven't changed aren't re-read. Run `uv run main.py scan --full` once after adding types. |
| `OCR models are missing` | `uv run scripts/setup.py`. |
| The labeling window doesn't appear | Check behind other windows. Run `uv run main.py label` from a terminal to see any message. |
| Handwriting is read badly | Label more handwritten fields, then `uv run main.py train`. Use `eval` to check that the error rate goes down. |
| Scan is slow | On this Mac a scan reads about 2.5 scanned pages a second; text, Word and digital PDF files are much faster. Later runs only read changed files. The default is 4 parallel readers with a GPU (more just wait for the GPU) and one per CPU core without one. Change it with `--workers`. |
| `another scan is running` | One really is (each run holds a lock on the database). Wait for it to finish. A crashed run releases the lock and is marked `aborted` by the next scan. |
| Nightly run on macOS finds nothing | The share must be mounted when the job runs. Check `data/logs/scan.log`. |
