# HDDkeeper

Утилита для Windows, которая отслеживает присутствие физических дисков и отправляет письма при добавлении/удалении дисков. Служба Windows не используется — интеграция через Планировщик задач. Минимальный интерфейс в трее для настройки SMTP, принятия эталона, ручного сканирования и управления задачами.

## Возможности
- Обнаружение дисков через PowerShell WMI (Win32_DiskDrive), фолбэк WMIC (удобно для Win7), опционально Get-PhysicalDisk (Win8+)
- Опциональная поддержка StorCLI (LSI/Broadcom) для видимости физических дисков за RAID; объединение и дедупликация результатов
- USB исключаются
- Модель эталон/сравнение с почтовыми уведомлениями (повторяются при каждом скане, пока различия не подтверждены)
- SMTP с паролем, защищённым DPAPI, до 10 получателей, опция без авторизации
- Интеграция с ОС: скан при старте, Tray при входе, и плановые сканы (Periodic или Weekly/Monthly в зависимости от режима)
- Режимы расписания: interval (минуты/часы, немедленный старт) и calendar (время HH:MM с днями недели и/или днями месяца)
- Портативный `settings.json` рядом с EXE (авто‑импорт при старте), экспорт/импорт из GUI или CLI; импорт из GUI/CLI перезаписывает SMTP и расписание (без пароля)
- GUI с разделами, автоподгон окна, окно Accept Baseline (сортируемые столбцы, корректные размеры, Rescan; галочка только для baseline; отсутствующие baseline‑диски серым; компактные симметричные чекбоксы дней недели)
- Dev‑режим: при запуске скрипта без аргументов открывается тот же GUI (без сборки EXE)

## Требования
- Windows 7/10/Server
- Наличие PowerShell (по умолчанию есть). WMIC для Win7 как фолбэк.
- Python не нужен при использовании EXE. Для запуска из исходников: Python 3.8+; pystray и Pillow нужны только если запускаете Tray из скрипта.

## Быстрый старт (GUI)
1) Запустите HDDkeeper.exe (или `py -3 hddkeeper.py`).
2) Настройте SMTP (host, port, security, from, recipients). Установите пароль (DPAPI).
3) Примите эталон (Accept baseline). Диалог покажет текущие диски; проверьте и подтвердите.
4) Нажмите Install tasks для регистрации задач (Startup/Periodic/Tray).

Перенос настроек: на настроенном сервере сделайте Export settings — появится `settings.json` рядом с EXE. Скопируйте EXE + settings.json на новый сервер и запустите EXE — настройки импортируются автоматически; затем нажмите Install tasks.

## CLI
Можно работать полностью через командную строку (и из EXE, и из скрипта).

Ключевые флаги:
- `--scan` — вывод текущих дисков (JSON)
- `--accept-baseline` — принять текущий список как эталон
- `--compare` — сравнить с эталоном
- `--notify-if-diff` — сравнить и отправить письмо при изменениях
- `--set-schedule 3h|180m|1d` — задать период сканирования (режим interval)
- `--set-schedule-at --time HH:MM [--dow MON;TUE;...] [--dom 1,15,31]` — задать календарное расписание (режим calendar)
- `--init` / `--install-tasks` — установить задачи Планировщика
- `--run-now` — запустить задачи немедленно (или выполнить сравнение напрямую)
- `--uninit` — удалить задачи
- `--tray` / `--gui` — запустить трей или окно
- SMTP: `--set-smtp --host ... --port ... --security none|starttls|ssl --user ... --from-addr ... --recipients "a@b;c@d" [--no-auth]`
  - Можно повторять `--recipient email@x` вместо общего `--recipients`
- `--set-smtp-password` — запрос пароля SMTP и сохранение через DPAPI
- `--test-email` — отправить тестовое письмо
- Портативные настройки: `--export-settings [--include-password]` / `--import-settings`
- Формат вывода: `--pretty`

Примеры (EXE):
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

Примеры (скрипт/dev):
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

## Где что хранится
- Данные и конфиг: `%ProgramData%\HDDkeeper\`
  - `baseline.json`, `candidate.json`, `config.json`
- Портативные настройки: `settings.json` рядом с EXE/скриптом
- Задачи Планировщика: "HDDkeeper Startup Scan", "HDDkeeper Periodic Scan" (режим interval) или "HDDkeeper Weekly Scan"/"HDDkeeper Monthly Scan" (режим calendar), и "HDDkeeper Tray"

## Примечания
- Tray запускается без консольного окна (pythonw)
- USB-диски намеренно исключены из мониторинга
- Если письма не приходят — проверьте SMTP и запустите `--test-email`
