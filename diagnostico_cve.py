#!/usr/bin/env python3
"""Diagnostico de descartes reales de CVE, sin enviar Telegram ni escribir state.json.

Reutiliza funciones y constantes de cve_notifier.py para que las reglas coincidan.
"""

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import time

import cve_notifier as notifier


CATEGORIES = (
    "rechazado",
    "antiguedad",
    "palabra_excluida",
    "sin_palabra_incluida",
    "duplicado_misma_severidad",
    "severidad",
    "elegible_para_notificar",
)


def load_state(path):
    """Read only; fail explicitly instead of silently changing the query window."""
    state_path = Path(path)
    with state_path.open("r", encoding="utf-8") as handle:
        state = json.load(handle)
    if not isinstance(state, dict) or not isinstance(state.get("sent_cves"), dict):
        raise ValueError("state.json invalido: falta el diccionario sent_cves")
    if not isinstance(state.get("last_run_timestamp"), str):
        raise ValueError("state.json invalido: falta last_run_timestamp")
    return state


def classify(item, cache, now, include, exclude, min_severity, report_unscored, max_age_days):
    """Copy of the decision order in the production loop, with shared filtering functions."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "(sin ID)")
    published = cve.get("published")

    if cve.get("vulnStatus", "").upper() == "REJECTED":
        return cve_id, "rechazado", "estado REJECTED"

    try:
        published_dt = datetime.strptime(
            published.split(".")[0], "%Y-%m-%dT%H:%M:%S"
        ).replace(tzinfo=timezone.utc)
        age = (now - published_dt).days
        if age > max_age_days:
            return cve_id, "antiguedad", f"{age} dias; maximo {max_age_days}"
    except (AttributeError, TypeError, ValueError):
        # The production script continues when it cannot parse a publication date.
        pass

    _, severity, _ = notifier.extract_cvss_info(cve)
    severity = severity.upper()

    if not notifier.match_keywords(item, include, exclude):
        # Check exclusions first, just like match_keywords().
        if exclude and not notifier.match_keywords(item, None, exclude):
            return cve_id, "palabra_excluida", "coincide con lista exclude de keywords.json"
        return cve_id, "sin_palabra_incluida", "no coincide con lista include de keywords.json"

    old = cache.get(cve_id)
    if old is not None:
        old_severity = (
            str(old.get("severity", "UNKNOWN")) if isinstance(old, dict) else str(old)
        ).upper()
        if old_severity == severity:
            return cve_id, "duplicado_misma_severidad", f"ya registrado como {severity}"

    if severity in ("AWAITING_ANALYSIS", "UNKNOWN"):
        eligible = report_unscored
    else:
        eligible = (
            notifier.SEVERITY_LEVELS.get(severity, 0)
            >= notifier.SEVERITY_LEVELS.get(min_severity, 2)
        )

    if not eligible:
        return cve_id, "severidad", f"{severity}; minimo {min_severity}"

    return cve_id, "elegible_para_notificar", f"severidad {severity}"


def fetch_range(start, end, api_key):
    params = {
        "lastModStartDate": start,
        "lastModEndDate": end,
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    headers = {"apiKey": api_key} if api_key else {}
    results = []
    while True:
        data = notifier.make_nvd_request(notifier.NVD_API_URL, params, headers)
        vulns = data.get("vulnerabilities", [])
        results.extend(vulns)
        total = data.get("totalResults", 0)
        index = data.get("startIndex", 0)
        per_page = data.get("resultsPerPage", 0)
        if per_page == 0 or index + per_page >= total:
            break
        params["startIndex"] = index + per_page
        time.sleep(1 if api_key else 6)
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description="Diagnostica descartes sin Telegram y sin escritura de estado")
    parser.add_argument("--state-file", default="state.json")
    parser.add_argument("--hours", type=int, default=0,
                        help="0: desde last_run_timestamp; >0: ultimas N horas (manteniendo la cache)")
    parser.add_argument("--max-detalle", type=int, default=100,
                        help="Cantidad maxima de CVE a detallar (0 = todos)")
    args = parser.parse_args(argv)

    if args.hours < 0 or args.hours > 24 * 120:
        parser.error("--hours debe estar entre 0 y 2880")
    if args.max_detalle < 0:
        parser.error("--max-detalle no puede ser negativo")

    try:
        state = load_state(args.state_file)
        include, exclude = notifier.load_keywords()
        now = datetime.now(timezone.utc)
        end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
        if args.hours:
            start = (now - timedelta(hours=args.hours)).strftime("%Y-%m-%dT%H:%M:%S.000")
        else:
            start = state["last_run_timestamp"]

        min_severity = os.environ.get("MIN_SEVERITY", "MEDIUM").upper()
        report_unscored = os.environ.get("REPORT_UNSCORED", "true").lower() in ("true", "1", "yes")
        max_age_str = os.environ.get("MAX_PUBLISHED_AGE_DAYS", "14")
        try:
            max_age_days = int(max_age_str)
        except ValueError:
            max_age_days = 14

        print("=== DIAGNOSTICO CVE (SOLO LECTURA) ===")
        print(f"Ventana de consulta (UTC): {start} -> {end}")
        print(f"CVEs en cache: {len(state['sent_cves'])}")
        print(f"Filtro: min_severity={min_severity}, report_unscored={report_unscored}, max_published_age_days={max_age_days}")
        print(f"Palabras incluidas: {include}; excluidas: {exclude}")
        print(f"NVD API key: {'configurada' if os.environ.get('NVD_API_KEY') else 'NO configurada'}")

        vulnerabilities = fetch_range(start, end, os.environ.get("NVD_API_KEY"))
        vulnerabilities.sort(key=lambda x: x.get("cve", {}).get("lastModified", ""))

        # Keep the cache simulation in RAM. No state.json changes are saved.
        cache = dict(state["sent_cves"])
        reasons = Counter()
        details = []
        for item in vulnerabilities:
            cve_id, reason, description = classify(
                item, cache, now, include, exclude, min_severity,
                report_unscored, max_age_days
            )
            reasons[reason] += 1
            details.append((cve_id, reason, description))

            # Mirror the production cache updates (in memory only).
            if reason in ("palabra_excluida", "sin_palabra_incluida", "severidad", "elegible_para_notificar"):
                cve = item.get("cve", {})
                _, sev, _ = notifier.extract_cvss_info(cve)
                cache[cve_id] = {"severity": sev.upper(), "published": cve.get("published")}

        print("\n=== RESUMEN ===")
        print(f"CVEs recuperados: {len(vulnerabilities)}")
        for category in CATEGORIES:
            print(f"{category}: {reasons[category]}")

        print("\n=== DETALLE ===")
        for cve_id, reason, description in details[:args.max_detalle or None]:
            print(f"{cve_id}: {reason} ({description})")
        if args.max_detalle and len(details) > args.max_detalle:
            print(f"... {len(details) - args.max_detalle} CVE adicionales omitidos del detalle")

        print("\n=== CONCLUSION ===")
        if not vulnerabilities:
            print("No hubo CVE modificados en la ventana consultada.")
        elif reasons["elegible_para_notificar"] == 0:
            print("Sin CVE elegibles: todos los recuperados fueron descartados por reglas del bot.")
        else:
            print(f"ATENCION: {reasons['elegible_para_notificar']} CVE cumplen reglas y podrian generar un intento de envio.")
        print("No se enviaron mensajes a Telegram ni se modifico state.json.")
        return 0
    except Exception as exc:
        print(f"ERROR DE DIAGNOSTICO: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
