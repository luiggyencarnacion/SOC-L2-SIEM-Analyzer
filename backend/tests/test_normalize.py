# tests/test_normalize.py - Normalizacion (fase A): texto, result, timestamps, IPs, aliases.
from datetime import datetime

from app.ingestion.aliases import build_alias_report
from app.ingestion.normalize import (
    first_token,
    map_result,
    normalize_key,
    parse_timestamp,
    validate_ip,
)


# --- Identidades ---

def test_keys_merge_case_and_separators():
    assert normalize_key("DC-01") == normalize_key("DC01") == "dc01"


def test_keys_differ_when_not_fusable():
    assert normalize_key("backupsvc") != normalize_key("svc_backup")


def test_alias_probable_and_candidate():
    # probable: misma clave, crudos distintos -> inferencia etiquetada
    hosts = build_alias_report(["DC-01", "DC01", "WS-018"], [])
    host_relations = hosts["hosts"]
    probable = [r for r in host_relations if r["status"] == "probable"]
    assert any({*r["members"]} == {"DC-01", "DC01"} and r["merged"] is False for r in probable)
    assert "inferencia" in probable[0]["rationale"]

    # candidate: 'backupsvc' vs 'svc_backup' claves distintas, NO se fusionan
    users = build_alias_report([], ["backupsvc", "svc_backup"])
    cand = [r for r in users["users"] if r["status"] == "candidate"]
    assert cand, "debe generar una relacion candidate por similaridad"
    assert cand[0]["merged"] is False
    assert "no se fusionan" in cand[0]["rationale"]


def test_alias_exact_unique():
    rep = build_alias_report(["WS-018"], ["CORP\\helpdesk"])
    assert rep["hosts"][0]["status"] == "exact"
    assert rep["users"][0]["status"] == "exact"


# --- Timestamps ---

def test_timestamp_missing_and_invalid():
    assert parse_timestamp(None) == (None, "missing")
    iso, status = parse_timestamp("no-es-una-fecha")
    assert status == "invalid"


def test_timestamp_naive_is_wall():
    iso, status = parse_timestamp("2026-10-23 07:46:07")
    assert status == "valid_wall"
    assert iso.startswith("2026-10-23T07:46:07")


def test_timestamp_with_offset_respected():
    iso, status = parse_timestamp("2026-10-23T09:46:07+02:00")
    assert status == "valid_offset"


def test_timestamp_datetime_object_naive():
    dt = datetime(2026, 10, 23, 7, 46, 7)
    _, status = parse_timestamp(dt)
    assert status == "valid_wall"


# --- Result / HTTP ---

def test_result_word_mapping():
    assert map_result("Success") == ("success", None)
    assert map_result("Failure") == ("failure", None)
    assert map_result("Allowed") == ("success", None)
    assert map_result("Denied") == ("denied", None)


def test_result_http_codes():
    assert map_result("200") == ("success", 200)
    assert map_result("404") == ("failure", 404)
    assert map_result("500") == ("error", 500)


def test_result_other():
    assert map_result("") == ("other", None)
    assert map_result("weird-value") == ("other", None)


# --- IPs ---

def test_ip_scopes():
    assert validate_ip("10.10.3.18") == ("10.10.3.18", "private")
    assert validate_ip("8.8.8.8")[1] == "public"
    assert validate_ip("127.0.0.1")[1] == "loopback"
    assert validate_ip("999.1.1.1") == (None, "invalid")
    assert validate_ip(None) == (None, None)


# --- Proceso ---

def test_first_token_from_commandline():
    assert first_token('"C:\\tools\\psscript.exe" -Version 1') == "psscript"
    assert first_token("C:\\Windows\\System32\\cmd.exe /c dir") == "cmd"
    assert first_token(None) is None
