# HDDkeeper

<img src = "https://raw.githubusercontent.com/avelender/HDDkeeper/refs/heads/main/sc.png"></img>

Windows utility to monitor physical disks presence and send email alerts when disks are added or removed. No Windows service is used — integration is done via Task Scheduler. A minimal Tray UI helps configure SMTP, accept a baseline, run scans, and manage tasks.

## Features
- Disk discovery via PowerShell WMI (Win32_DiskDrive), fallback WMIC (Win7-friendly), optional Get-PhysicalDisk (Win8+)
- Optional StorCLI (LSI/Broadcom) support to see physical drives behind RAID; results merged and deduplicated
- USB drives are ignored
- Baseline/compare model with email notifications (repeated on every scan until accepted)
- SMTP with DPAPI-protected password, up to 10 recipients, optional no-auth mode
- Task Scheduler integration: Startup scan, Tray on user logon, and scheduled scans (Periodic or Weekly/Monthly based on mode)
- Scheduling modes: interval (minutes/hours, immediate start) or calendar (time HH:MM with Days of Week and/or Days of Month)
- Portable settings.json next to EXE (auto-import at start), Export/Import from GUI or CLI; GUI/CLI import overwrites SMTP and schedule (no password)
- GUI with grouped sections, auto-resizing window, and an Accept Baseline preview dialog (sortable columns, correct sizes, Rescan; checkmark only for baseline; missing baseline disks shown grey; compact, symmetric Days of Week checkboxes)
- Dev mode: running the Python script without arguments opens the same GUI (no need to rebuild the EXE during development)

## Requirements
- Windows 7/10/Server
- PowerShell available (default on supported systems). WMIC used as fallback on Win7.
- No Python required when using the portable EXE. For running from source: Python 3.8+; tkinter is included, pystray and Pillow are needed only if you run Tray from the script.

## Quick start (GUI)
1) Run HDDkeeper.exe (or `py -3 hddkeeper.py`).
2) Configure SMTP (host, port, security, from, recipients). Set password (DPAPI protected).
3) Accept baseline. A dialog will show current disks; review and confirm.
4) Click Install tasks to register Startup/Periodic scans and Tray.

Portable settings: on a configured server, Export settings to produce `settings.json` near the EXE. Copy EXE + settings.json to a new server folder and run EXE — settings are auto-imported; then Install tasks.

## CLI
You can operate entirely from the command line (both from EXE or from the script).

Key flags:
- `--scan` — print current disks as JSON
- `--accept-baseline` — save current disks as the baseline
- `--compare` — compare with baseline
- `--notify-if-diff` — compare and send email if there are changes
- `--set-schedule 3h|180m|1d` — set periodic scan interval (interval mode)
- `--set-schedule-at --time HH:MM [--dow MON;TUE;...] [--dom 1,15,31]` — set calendar schedule (calendar mode)
- `--init` / `--install-tasks` — install Task Scheduler tasks
- `--run-now` — run the scheduled task(s) immediately (or fallback to direct compare)
- `--uninit` — remove Task Scheduler tasks
- `--tray` / `--gui` — run Tray UI or main GUI
- SMTP config: `--set-smtp --host ... --port ... --security none|starttls|ssl --user ... --from-addr ... --recipients "a@b;c@d" [--no-auth]`
  - You can repeat `--recipient email@x` multiple times instead of `--recipients`
- `--set-smtp-password` — prompt for SMTP password and store via DPAPI
- `--test-email` — send a test email
- Portable settings: `--export-settings [--include-password]` / `--import-settings`
- Output formatting: `--pretty`

Examples (from EXE):
```powershell
HDDkeeper.exe --set-smtp --host smtp.example.com --port 587 --security starttls --user user \
  --from-addr noreply@example.com --recipients "a@b;c@d"
HDDkeeper.exe --set-smtp-password
HDDkeeper.exe --accept-baseline
HDDkeeper.exe --init
HDDkeeper.exe --set-schedule-at --time 03:00 --dow MON;WED;FRI
HDDkeeper.exe --set-schedule 6h
HDDkeeper.exe --run-now
HDDkeeper.exe --scan --pretty
```

Examples (from script/dev):
```powershell
py -3 d:\wibe-coding\HDDkeeper\hddkeeper.py --set-smtp --host smtp.example.com --port 587 --security starttls --user user \
  --from-addr noreply@example.com --recipients "a@b;c@d"
py -3 d:\wibe-coding\HDDkeeper\hddkeeper.py --set-smtp-password
py -3 d:\wibe-coding\HDDkeeper\hddkeeper.py --accept-baseline
py -3 d:\wibe-coding\HDDkeeper\hddkeeper.py --init
py -3 d:\wibe-coding\HDDkeeper\hddkeeper.py --set-schedule-at --time 03:00 --dow MON;WED;FRI
py -3 d:\wibe-coding\HDDkeeper\hddkeeper.py --set-schedule 6h
py -3 d:\wibe-coding\HDDkeeper\hddkeeper.py --run-now
py -3 d:\wibe-coding\HDDkeeper\hddkeeper.py --scan --pretty
```

## Where things live
- Data and config: `%ProgramData%\HDDkeeper\`
  - `baseline.json`, `candidate.json`, `config.json`
- Portable settings (per-folder): `settings.json` next to the EXE/script
- Scheduled tasks: "HDDkeeper Startup Scan", "HDDkeeper Periodic Scan" (interval mode) or "HDDkeeper Weekly Scan"/"HDDkeeper Monthly Scan" (calendar mode), and "HDDkeeper Tray"

## Notes
- Tray autostarts without a console window (pythonw)
- USB drives are excluded from monitoring by design
- If you see no emails, check SMTP settings and run `--test-email`
