# data/

Put your CSV files here (this folder is ignored by git and set to mode 700 by the installer).

- `activity.csv` — REQUIRED (casino activity per day × player × provider)
- `games.csv`, `payments.csv`, `clients.csv` — optional

See `docs/CSV-CONTRACTS.md` for the exact columns, accepted header names and formats.
`sentinela demo` writes synthetic example files to `data/demo/`.
