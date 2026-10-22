# CPNI OCR Processor

Finds where sensitive customer data lives on a file share (SSNs, customer account numbers, driver's licenses, bank and card numbers, CPNI and more) without storing the data itself. Everything runs on your own machine; scans never use the network.

- Reads PDFs, Word/Excel/PowerPoint (including legacy formats), email (EML, MSG, PST), ZIP archives, text, CSV, RTF and images.
- Straightens scanned pages at any angle and reads printed text and handwriting, with a handwriting model you can train on your own labeled scans.
- Records only the type, location and a keyed hash of each finding in a local SQLite database, and prints a total for each type.
- Never changes the files it scans.

Built for Windows and macOS; tested on macOS.

## Quick start

```
uv run scripts/setup.py
echo "PIISCAN_ROOT=/path/to/share" > .env
uv run main.py scan
```

See [docs/RUNBOOK.md](docs/RUNBOOK.md) for every command, labeling and training, security, and troubleshooting.
