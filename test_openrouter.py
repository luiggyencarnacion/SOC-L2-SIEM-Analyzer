# Prueba de conexion OpenRouter usando los ajustes guardados en RAM del backend.
import json

import httpx

BASE = "http://127.0.0.1:8000"

with httpx.Client(timeout=60) as c:
    s = c.get(f"{BASE}/api/ai/settings").json()
    print("proveedor:", s["provider"], "| efectivo:", s["effective_provider"], "| modo:", s["mode"])
    print("modelo:", s["model"] or "(vacio)")
    print("base_url:", s["base_url"] or "(vacia)")
    print("clave configurada:", s["key_configured"], "| fuente:", s["settings_source"])

    t = c.post(f"{BASE}/api/ai/test")
    body = t.json()
    print("prueba de conexion:", t.status_code, "->", body.get("detail", body))

    # Verificacion del id de modelo contra el catalogo publico de OpenRouter
    # (GET /models es publico; no gasta creditos ni expone la clave).
    if s["base_url"] and "openrouter" in s["base_url"] and s["model"]:
        try:
            r = httpx.get(s["base_url"].rstrip("/") + "/models", timeout=30)
            ids = {m["id"] for m in r.json().get("data", [])}
            print("catalogo OpenRouter alcanzable:", r.status_code, "| modelos:", len(ids))
            print("tu modelo esta en el catalogo:", s["model"] in ids)
            if s["model"] not in ids:
                cerca = [i for i in ids if s["model"].split("/")[-1] in i][:8]
                print("posibles coincidencias:", cerca)
        except Exception as exc:
            print("no se pudo consultar el catalogo:", exc)
