# AuditLanes A3 PDF Findings Report Template

Use this template when the operator asks for a reusable AuditLanes report,
security PDF handoff, findings table, or an A3 landscape issue overview after a
completed AuditLanes run.

## Goal

Create a human-readable PDF handoff from AuditLanes reducer output. The report
must be suitable for repeated security-review handoffs: compact enough to scan,
but detailed enough to map every row back to the canonical AuditLanes finding.

## Preferred Input

Prefer merged or reducer-owned state, in this order:

1. `auditlanes/out/merged/<merge-id>/merged-findings.jsonl`
2. `auditlanes/out/runs/<run-id>/state/finding-inventory.jsonl`
3. `auditlanes/out/runs/<run-id>/final/pre-fix-findings.md` only as a fallback

Do not use lane sidecars as the primary source if reducer state exists. Do not
scan `auditlanes/out/**` as application evidence; use it only as report input.

## Output

Write the PDF next to the input report set:

- merged input: `auditlanes/out/merged/<merge-id>/security-findings-volledig-a3-landscape.pdf`
- single run input: `auditlanes/out/runs/<run-id>/final/security-findings-volledig-a3-landscape.pdf`

Also keep the source generator or source document only when it helps repeat the
report. Generated source can live in `/private/tmp` when the operator only asked
for the PDF.

## Deterministic Generator

Prefer the bundled generator over hand-written HTML or ad hoc PDF code:

```bash
python3 ${AUDITLANES_PLUGIN_ROOT}/scripts/render_a3_findings_pdf.py \
  --input auditlanes/out/merged/<merge-id>/merged-findings.jsonl \
  --project-name "<Project Name>" \
  --date <YYYY-MM-DD>
```

Claude environments may expose the plugin root as `${CLAUDE_PLUGIN_ROOT}`.
Codex environments may expose it as `${AUDITLANES_PLUGIN_ROOT}`. If neither
environment variable is present, resolve the script relative to the installed
AuditLanes plugin directory.

The generator is the source of truth for this layout. Use manual rendering only
when the generator cannot run, and then match its LaTeX layout exactly.

## Page Layout

- Paper: A3
- Orientation: landscape
- Columns: `id`, `omschrijving`, `severity`
- Title: `<Project Name> - security findings - volledige lijst - <YYYY-MM-DD>`
- Subtitle: include total deduped finding count and severity counts
- Row styling:
  - alternate row shading is allowed but subtle
  - add a thin line between rows
  - keep the table dense but readable
- Severity cell:
  - text labels, not P0/P1/P2/P3
  - allowed values: `critical`, `high`, `medium`, `low`
  - color-code the full severity cell
  - recommended colors:
    - critical: dark red `#B42318`
    - high: orange/red `#C2410C`
    - medium: blue `#1D4ED8`
    - low: gray `#4B5563`

## ID Column

The ID must be searchable in AuditLanes artifacts.

For merged reports:

- first line: `merged_finding_id`, for example `MF-0066`
- second line, smaller text: `primary_source_finding_id`

For single-run reports:

- first line: `finding_id`
- second line, smaller text: family or source lane when available

Never replace canonical IDs with custom numbering unless the canonical ID is
also shown in the same cell.

## Description Column

Write in short Dutch. Avoid raw scan prose and long English impact fragments.
Each row should have this structure:

```text
<Korte titel>
Route: <endpoint, function, file, or service>
Risico: <plain Dutch consequence>
Ontbreekt: <missing guard or recommended control>
Status: kandidaat; verifieer exploitbaarheid
```

Only include the `Status:` line for candidate findings. Omit it for
confirmed-static findings.

Keep each part concise:

- title: 5 to 12 words
- route: shortest useful route or file/function
- risk: one sentence in plain Dutch
- missing guard: one sentence with the concrete missing control

Examples:

```text
Ongeautoriseerde toegang tot GCS-bestanden
Route: GET /checkout/general/file_serve/service/download/
Risico: Gegevens van andere tenants kunnen worden gelezen of verwijderd.
Ontbreekt: vergelijk key namespace/eigenaar met de actieve connection voor lezen en schrijven.
```

```text
Admin-rolcheck ontbreekt bij sessies
Route: POST /api/session/get_sessions
Risico: Een gebruiker zonder echte admin- of developerrol kan beheerfunctionaliteit raken.
Ontbreekt: controleer de actuele NDB user.admin/user.developer, niet alleen sessieflags.
```

```text
Pickle-RCE bij cache-endpoint
Route: POST /third_parties/handle_cache/
Risico: Code-uitvoering op de server kan mogelijk worden bereikt als het endpoint of de sleutel misbruikt wordt.
Ontbreekt: verwijder het endpoint of vervang pickle door een veilig, gevalideerd formaat.
```

## Severity Ordering

Sort rows by severity first:

1. critical
2. high
3. medium
4. low

Within the same severity, put confirmed-static before candidate findings. Then
sort by canonical ID.

## Dutch Wording Rules

Prefer these recurring phrases:

- `Gegevens van andere tenants kunnen worden gelezen of verwijderd.`
- `Gegevens of status kunnen zonder juiste tenant- of eigenaarscheck worden aangepast.`
- `Een aangeleverde key wordt gebruikt zonder tenantbinding.`
- `Een gebruiker zonder echte admin- of developerrol kan beheerfunctionaliteit raken.`
- `Sessies of sessietokens kunnen worden gelekt, hergebruikt of te lang geldig blijven.`
- `Een ingelogde browser kan zonder bedoelde gebruikersactie een wijziging uitvoeren.`
- `vergelijk key namespace/eigenaar met de actieve connection voor lezen en schrijven.`
- `controleer de actuele NDB user.admin/user.developer, niet alleen sessieflags.`

Avoid:

- raw English evidence paragraphs
- `P0/P1/P2/P3` labels in the PDF table
- vague descriptions like `security issue`
- custom IDs that cannot be traced back

## Verification

Before handoff, verify:

- the PDF opens and is not encrypted
- page size is A3 landscape, around `1190.55 x 841.89 pts`
- the title contains the project name and date
- total row count matches the input finding count
- severity counts in subtitle match the input
- a text extraction shows searchable `MF-` or finding IDs

Suggested commands when available:

```bash
pdfinfo <pdf-path>
pdftotext <pdf-path> -
```

## Operator Handoff

In the final response, include:

- PDF path
- finding count
- page size and orientation
- page count
- note that IDs are traceable back to AuditLanes artifacts
