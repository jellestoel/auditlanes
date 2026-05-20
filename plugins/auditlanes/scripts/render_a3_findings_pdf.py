import argparse
import datetime as dt
import json
import re
import subprocess
from pathlib import Path


PDF_NAME = "security-findings-volledig-a3-landscape.pdf"
TEX_NAME = "security-findings-volledig-a3-landscape.tex"


SEVERITY_TO_SORT_PRIO = {
    "critical": "P0",
    "high": "P1",
    "medium": "P2",
    "low": "P3",
}

PRIO_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
SEVERITY_LABELS = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def collapse(value):
    if value is None:
        return ""
    value = str(value)
    value = value.replace("\u2014", "-").replace("\u2013", "-").replace("\u2212", "-")
    value = value.replace("\u2018", "'").replace("\u2019", "'")
    value = value.replace("\u201c", '"').replace("\u201d", '"')
    value = value.replace("\u00a0", " ")
    value = value.replace("\n", " ")
    value = re.sub(r"`+", "", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def shorten(value, limit):
    value = collapse(value)
    if len(value) <= limit:
        return value
    cut = value[: limit - 1].rsplit(" ", 1)[0]
    return cut.rstrip(".,;:") + "..."


def entry_target(finding):
    entrypoint = collapse(finding.get("entrypoint"))
    if entrypoint:
        entrypoint = re.sub(r"\s*\([^)]*\)", "", entrypoint)
        entrypoint = entrypoint.replace("ProtoRPC POST ", "ProtoRPC ")
        entrypoint = entrypoint.replace("POST/GET ", "")
        entrypoint = entrypoint.replace(" and ", " en ")
        entrypoint = entrypoint.replace(" with ", " met ")
        return shorten(entrypoint, 82)

    files = finding.get("files") or []
    if files:
        return shorten(files[0], 82)
    return finding.get("owner_family") or "onbekende plek"


def asset_label(text):
    checks = [
        ("gcs", "GCS-bestanden"),
        ("crm", "CRM-bestanden"),
        ("invoice", "facturen"),
        ("payment", "betalingen"),
        ("session", "sessies"),
        ("auth_key", "sessietokens"),
        ("token", "tokens"),
        ("customer", "klantdata"),
        ("sale_item", "verkoopregels"),
        ("sale", "verkoopdata"),
        ("order", "orders"),
        ("repair", "reparaties"),
        ("productlist", "productlijsten"),
        ("product list", "productlijsten"),
        ("product", "producten"),
        ("report", "rapporten"),
        ("task", "taken"),
        ("pdf", "PDF-bestanden"),
        ("contract", "contracten"),
        ("endpoint", "endpointinstellingen"),
        ("admin", "adminfuncties"),
        ("webhook", "webhooks"),
        ("callback", "callbacks"),
        ("xlsx", "exports"),
        ("export", "exports"),
        ("search", "zoekfunctie"),
        ("query", "zoekquery"),
        ("cache", "cache-endpoint"),
        ("cookie", "cookies"),
        ("csrf", "CSRF"),
        ("cors", "CORS"),
        ("tls", "TLS"),
        ("signrequest", "SignRequest"),
        ("telecombinatie", "Telecombinatie-data"),
        ("tc energy", "TC Energy-data"),
        ("tcenergy", "TC Energy-data"),
    ]
    for needle, label in checks:
        if needle in text:
            return label
    return "data"


def category(text):
    if "pickle" in text and ("rce" in text or "loads" in text):
        return "Pickle-RCE"
    if "csrf" in text:
        return "CSRF-bescherming ontbreekt"
    if "take_over_connection" in text or "tenant pivot" in text or "pivot their session" in text:
        return "Tenantpivot mogelijk"
    if "xss" in text or "|safe" in text:
        return "Stored XSS-risico"
    if "formula" in text or "xlsx" in text:
        return "Spreadsheet-formule-injectie"
    if "tls" in text or "verify=false" in text or "certificate verification" in text:
        return "TLS-verificatie uitgeschakeld"
    if "hardcoded" in text or "committed token" in text or "api token" in text:
        return "Hardcoded geheim"
    if ("webhook" in text or "callback" in text) and ("unauth" in text or "no auth" in text):
        return "Webhook zonder auth"
    if "allowed_hosts" in text or "cors" in text or "security header" in text:
        return "Platform-hardening ontbreekt"
    if "permission_required" in text or "fail-open" in text:
        return "Permission-check faalt open"
    if "admin" in text and ("role" in text or "developer" in text or "admin" in text):
        return "Admin-rolcheck ontbreekt"
    if "session" in text and ("token" in text or "auth_key" in text or "cookie" in text):
        return "Sessierisico"
    if "delete" in text or "destroy" in text:
        return "Ongeautoriseerd lezen/verwijderen"
    if "mutate" in text or "write primitive" in text or "tampering" in text or ".put()" in text:
        return "Ongeautoriseerde wijziging"
    if "unauth" in text or "without authentication" in text or "no authentication" in text:
        return "Authenticatie ontbreekt"
    if "cross-tenant" in text or "namespace" in text or "idor" in text or "urlsafe" in text:
        if "disclosure" in text or "leak" in text or "read-only" in text or "read " in text:
            return "Tenantdata kan lekken"
        return "Tenantcheck ontbreekt"
    if "query" in text or "search" in text:
        return "Query-invoer onvoldoende afgeschermd"
    return "Beveiligingsguard ontbreekt"


def risk_sentence(prefix, label, text):
    label = label or "data"
    if prefix == "Pickle-RCE":
        return "Code-uitvoering op de server kan mogelijk worden bereikt als het endpoint of de sleutel misbruikt wordt."
    if prefix == "CSRF-bescherming ontbreekt":
        return "Een ingelogde browser kan zonder bedoelde gebruikersactie een wijziging uitvoeren."
    if prefix == "Tenantpivot mogelijk":
        return "Een gebruiker kan de sessie naar een andere tenant laten wijzen en daarna daar acties uitvoeren."
    if prefix == "Stored XSS-risico":
        return "Ingevoerde klant- of backoffice-data kan later als script in een browser worden uitgevoerd."
    if prefix == "Spreadsheet-formule-injectie":
        return "Een export kan spreadsheet-formules bevatten die bij openen acties uitvoeren of data lekken."
    if prefix == "TLS-verificatie uitgeschakeld":
        return "Verkeer naar externe partijen kan worden onderschept of aangepast zonder certificaatfout."
    if prefix == "Hardcoded geheim":
        return "Een token of geheim staat in broncode/configuratie en kan buiten de runtime worden misbruikt."
    if prefix == "Webhook zonder auth":
        return "Een externe caller kan een provider-callback nadoen en interne status wijzigen."
    if prefix == "Platform-hardening ontbreekt":
        return "Basisbescherming rond headers, hosts, cookies, builds of containers is te ruim ingesteld."
    if prefix == "Permission-check faalt open":
        return "Een ontbrekende permissie kan alsnog als toegestaan eindigen."
    if prefix == "Admin-rolcheck ontbreekt":
        return "Een gebruiker zonder echte admin- of developerrol kan beheerfunctionaliteit raken."
    if prefix == "Sessierisico":
        return "Sessies of sessietokens kunnen worden gelekt, hergebruikt of te lang geldig blijven."
    if prefix == "Ongeautoriseerd lezen/verwijderen":
        return "Gegevens van andere tenants kunnen worden gelezen of verwijderd."
    if prefix == "Ongeautoriseerde wijziging":
        return "Gegevens of status kunnen zonder juiste tenant- of eigenaarscheck worden aangepast."
    if prefix == "Authenticatie ontbreekt":
        return "Een endpoint accepteert requests zonder betrouwbare authenticatie."
    if prefix == "Tenantdata kan lekken":
        return "Gegevens van een andere tenant kunnen worden ingezien."
    if prefix == "Tenantcheck ontbreekt":
        return "Een aangeleverde key wordt gebruikt zonder tenantbinding."
    if prefix == "Query-invoer onvoldoende afgeschermd":
        return "Zoek- of filterinvoer kan querygedrag beinvloeden buiten de bedoelde zoekterm."
    if "delete" in text or "destroy" in text:
        return "De betrokken data kan ongeautoriseerd worden verwijderd."
    if "disclosure" in text or "leak" in text or "read" in text:
        return "De betrokken data kan ongeautoriseerd worden ingezien."
    if "mutate" in text or "write" in text or "put()" in text:
        return "De betrokken data kan ongeautoriseerd worden gewijzigd."
    return "Een ontbrekende guard maakt misbruik of datalekken mogelijk."


def guard_hint(prefix, text):
    if prefix == "Pickle-RCE":
        return "verwijder het endpoint of vervang pickle door een veilig, gevalideerd formaat."
    if prefix == "CSRF-bescherming ontbreekt":
        return "zet CSRF aan en verwijder onnodige csrf_exempt/bypass-paden."
    if prefix == "Tenantpivot mogelijk":
        return "check takeover-rechten voordat session.current_connection wordt aangepast."
    if prefix == "Stored XSS-risico":
        return "escape output en verwijder onnodige safe-rendering."
    if prefix == "Spreadsheet-formule-injectie":
        return "prefix spreadsheet-formules en escape exportvelden."
    if prefix == "TLS-verificatie uitgeschakeld":
        return "zet certificaatverificatie aan en pin geen onveilige fallback."
    if prefix == "Hardcoded geheim":
        return "roteer het geheim en laad het alleen uit Secret Manager of runtimeconfiguratie."
    if prefix == "Webhook zonder auth" or prefix == "Authenticatie ontbreekt":
        return "vereis providerhandtekening, token of expliciete auth voordat state wijzigt."
    if prefix == "Admin-rolcheck ontbreekt":
        return "controleer de actuele NDB user.admin/user.developer, niet alleen sessieflags."
    if prefix == "Permission-check faalt open":
        return "laat ontbrekende permissies hard falen en test de denial-case."
    if prefix == "Platform-hardening ontbreekt":
        return "maak hosts, CORS, cookies, headers, images en buildrechten expliciet."
    if "namespace" in text or "current_connection" in text or "urlsafe" in text or "cross-tenant" in text:
        return "vergelijk key namespace/eigenaar met de actieve connection voor lezen en schrijven."
    if "admin" in text or "developer" in text:
        return "controleer echte admin/developerrechten server-side."
    if "session" in text or "auth_key" in text or "cookie" in text:
        return "maak sessiecookies HttpOnly/Secure/SameSite en voorkom tokenlekken."
    return "voeg een expliciete server-side guard toe en dek die af met een regressietest."


def title_for(prefix, label):
    if prefix == "Ongeautoriseerd lezen/verwijderen":
        return f"Ongeautoriseerde toegang tot {label}"
    if prefix == "Ongeautoriseerde wijziging":
        return f"Ongeautoriseerde wijziging van {label}"
    if prefix == "Tenantdata kan lekken":
        return f"Tenantdata kan lekken uit {label}"
    if prefix == "Tenantcheck ontbreekt":
        return f"Tenantcheck ontbreekt bij {label}"
    if prefix == "Admin-rolcheck ontbreekt":
        return f"Admin-rolcheck ontbreekt bij {label}"
    if prefix == "Sessierisico":
        return f"Sessierisico rond {label}"
    if prefix == "Authenticatie ontbreekt":
        return f"Authenticatie ontbreekt bij {label}"
    if prefix == "Beveiligingsguard ontbreekt":
        return f"Beveiligingsguard ontbreekt bij {label}"
    return f"{prefix} bij {label}"


def dutch_description_parts(finding):
    text = " ".join(
        collapse(finding.get(field)).lower()
        for field in ("summary", "impact_boundary", "missing_guard", "entrypoint", "security_invariant")
    )
    label = asset_label(text)
    target = entry_target(finding)
    prefix = category(text)
    status = collapse(finding.get("status")).lower()
    return {
        "title": shorten(title_for(prefix, label), 82),
        "route": shorten(target, 105),
        "risk": shorten(risk_sentence(prefix, label, text), 135),
        "guard": shorten(guard_hint(prefix, text), 135),
        "status": "kandidaat; verifieer exploitbaarheid" if status == "candidate" else "",
    }


def tex_escape(value):
    value = collapse(value)
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(ch, ch) for ch in value)


def canonical_id(finding):
    return (
        finding.get("merged_finding_id")
        or finding.get("finding_id")
        or finding.get("id")
        or finding.get("primary_source_finding_id")
        or "zonder-id"
    )


def secondary_id(finding):
    if finding.get("merged_finding_id"):
        return finding.get("primary_source_finding_id") or ""
    return finding.get("owner_family") or finding.get("family") or finding.get("primary_source_run") or ""


def load_findings(input_path):
    findings = []
    with input_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            severity = collapse(item.get("severity")).lower()
            prio = SEVERITY_TO_SORT_PRIO.get(severity, "P3")
            item["_prio"] = prio
            item["_severity_label"] = SEVERITY_LABELS.get(severity, severity or "unknown")
            item["_description_nl"] = dutch_description_parts(item)
            findings.append(item)
    findings.sort(
        key=lambda item: (
            PRIO_ORDER.get(item["_prio"], 99),
            0 if item.get("status") == "confirmed-static" else 1,
            canonical_id(item),
        )
    )
    return findings


def severity_command(severity):
    return {
        "critical": r"\Critical",
        "high": r"\High",
        "medium": r"\Medium",
        "low": r"\Low",
    }.get(severity, r"\Low")


def render_description(parts):
    lines = [
        r"\textbf{" + tex_escape(parts["title"]) + "}",
        r"\textit{Route:} " + tex_escape(parts["route"]),
        r"\textit{Risico:} " + tex_escape(parts["risk"]),
        r"\textit{Ontbreekt:} " + tex_escape(parts["guard"]),
    ]
    if parts.get("status"):
        lines.append(r"\textit{Status:} " + tex_escape(parts["status"]))
    return r"\newline ".join(lines)


def render_tex(findings, project_name, report_date, source_label):
    counts = {prio: 0 for prio in ("P0", "P1", "P2", "P3")}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding["_prio"]] += 1
        if finding["_severity_label"] in severity_counts:
            severity_counts[finding["_severity_label"]] += 1

    rows = []
    for finding in findings:
        fid = tex_escape(canonical_id(finding))
        source_id = secondary_id(finding)
        if source_id:
            fid = fid + r"\newline {\scriptsize " + tex_escape(source_id) + "}"
        desc = render_description(finding["_description_nl"])
        rows.append(f"{fid} & {desc} & {severity_command(finding['_severity_label'])} \\\\ \\hline")

    return r"""\documentclass[10pt]{article}
\usepackage[a3paper,landscape,margin=10mm]{geometry}
\usepackage[table]{xcolor}
\usepackage{longtable}
\usepackage{array}
\usepackage[T1]{fontenc}
\usepackage{lmodern}
\pagestyle{empty}

\definecolor{headerbg}{HTML}{1F2937}
\definecolor{rowalt}{HTML}{F6F8FB}
\definecolor{prioP0}{HTML}{B42318}
\definecolor{prioP1}{HTML}{C2410C}
\definecolor{prioP2}{HTML}{1D4ED8}
\definecolor{prioP3}{HTML}{4B5563}
\definecolor{rowline}{HTML}{D1D5DB}
\definecolor{textgray}{HTML}{374151}

\newcommand{\Critical}{\cellcolor{prioP0}\textcolor{white}{\textbf{critical}}}
\newcommand{\High}{\cellcolor{prioP1}\textcolor{white}{\textbf{high}}}
\newcommand{\Medium}{\cellcolor{prioP2}\textcolor{white}{\textbf{medium}}}
\newcommand{\Low}{\cellcolor{prioP3}\textcolor{white}{\textbf{low}}}

\setlength{\parindent}{0pt}
\setlength{\tabcolsep}{6pt}
\setlength{\arrayrulewidth}{0.25pt}
\arrayrulecolor{rowline}
\renewcommand{\arraystretch}{1.18}

\begin{document}

{\LARGE\textbf{""" + tex_escape(project_name) + r""" - security findings - volledige lijst - """ + tex_escape(report_date) + r"""}}\\[2mm]
{\small\textcolor{textgray}{AuditLanes-lijst: """ + str(len(findings)) + r""" findings uit """ + tex_escape(source_label) + r""". ID: canonical finding-id met bron/family eronder. Severity: critical=""" + str(severity_counts["critical"]) + r""", high=""" + str(severity_counts["high"]) + r""", medium=""" + str(severity_counts["medium"]) + r""", low=""" + str(severity_counts["low"]) + r""".}}

\vspace{5mm}

\small
\rowcolors{2}{rowalt}{white}
\begin{longtable}{
  >{\raggedright\arraybackslash}p{56mm}
  >{\raggedright\arraybackslash}p{302mm}
  >{\centering\arraybackslash}p{22mm}
}
\rowcolor{headerbg}
\textcolor{white}{\textbf{id}} &
\textcolor{white}{\textbf{omschrijving}} &
\textcolor{white}{\textbf{severity}} \\ \hline
\endfirsthead
\rowcolor{headerbg}
\textcolor{white}{\textbf{id}} &
\textcolor{white}{\textbf{omschrijving}} &
\textcolor{white}{\textbf{severity}} \\ \hline
\endhead
""" + "\n".join(rows) + r"""
\end{longtable}

\end{document}
"""


def default_output_path(input_path):
    if input_path.name == "merged-findings.jsonl":
        return input_path.parent / PDF_NAME
    if input_path.name == "finding-inventory.jsonl" and input_path.parent.name == "state":
        run_dir = input_path.parent.parent
        return run_dir / "final" / PDF_NAME
    return input_path.with_name(PDF_NAME)


def default_project_name(input_path):
    try:
        parts = input_path.resolve().parts
        if "repos" in parts:
            repo = parts[parts.index("repos") + 1]
            return repo.replace("-", " ").title().replace(" ", " ")
    except (ValueError, IndexError):
        pass
    return input_path.cwd().name.replace("-", " ").title()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Render an AuditLanes findings JSONL file as the standard A3 landscape PDF handoff."
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to merged-findings.jsonl or state/finding-inventory.jsonl.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output PDF path. Defaults next to the merged input or under run final/ for state input.",
    )
    parser.add_argument(
        "--project-name",
        help="Project name for the title. Defaults to the nearest repo-looking path segment.",
    )
    parser.add_argument(
        "--date",
        default=dt.date.today().isoformat(),
        help="Report date for the title, default: today in ISO format.",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=Path("/private/tmp/auditlanes_a3_pdf_build"),
        help="Temporary build directory for LaTeX artifacts.",
    )
    parser.add_argument(
        "--keep-tex",
        action="store_true",
        help="Also copy the generated .tex file next to the PDF.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    input_path = args.input.expanduser().resolve()
    output_path = (args.output.expanduser().resolve() if args.output else default_output_path(input_path))
    project_name = args.project_name or default_project_name(input_path)
    source_label = input_path.name

    args.build_dir.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tex_path = args.build_dir / TEX_NAME
    findings = load_findings(input_path)
    tex_path.write_text(render_tex(findings, project_name, args.date, source_label), encoding="utf-8")
    subprocess.run(
        [
            "xelatex",
            "-interaction=nonstopmode",
            "-halt-on-error",
            f"-output-directory={args.build_dir}",
            str(tex_path),
        ],
        check=True,
    )
    generated = args.build_dir / PDF_NAME
    output_path.write_bytes(generated.read_bytes())
    if args.keep_tex:
        output_path.with_suffix(".tex").write_text(tex_path.read_text(encoding="utf-8"), encoding="utf-8")
    print(output_path)


if __name__ == "__main__":
    main()
