"""Diagnóstico de la app ADIPACK Avisos en cada tablet: por qué está o no conectada al MQTT.

Junta lo que el MDM ya sabe de la tablet (último check-in del agente, apps instaladas, errores de la
política) con lo que vio el broker MQTT (intentos de conexión aceptados o rechazados) y lo que el agente
v1.5+ informa de la app (si su servicio arrancó y qué dice su pantalla de estado).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

AGENT_PKG = "com.adipack.mdm.agent"
AVISOS_PKG = "com.adipack.avisos"
FEATURE_AVISOS = "avisos_config"      # el agente configura, arranca y vigila la app de avisos
FEATURE_UPDATE = "auto_update"        # el agente se actualiza solo desde el MDM
STALE_CHECKIN = timedelta(minutes=10)
APP_SILENCE_S = 5 * 60                # sin noticias de la app en 5 min = no está corriendo

CODES = {1: "versión de MQTT no soportada", 2: "identificador inválido", 3: "servidor no disponible",
         4: "usuario o clave incorrectos", 5: "no autorizada"}


def _aware(d: datetime | None) -> datetime | None:
    return d.replace(tzinfo=timezone.utc) if d is not None and d.tzinfo is None else d


def installed_apps(status: dict | None) -> dict[str, dict]:
    out = {}
    for a in (status or {}).get("apps") or []:
        if isinstance(a, dict) and a.get("package"):
            out[str(a["package"])] = a
    return out


def agent_features(status: dict | None) -> list[str]:
    f = (status or {}).get("agent_features")
    return [str(x) for x in f] if isinstance(f, list) else []


def agent_label(status: dict | None, fallback: str = "") -> str:
    a = installed_apps(status).get(AGENT_PKG)
    if a:
        return f"v{a.get('version_name') or '?'} (código {a.get('version_code', '?')})"
    return f"v{fallback}" if fallback else "desconocida"


def agent_is_old(status: dict | None) -> bool:
    """El agente no informa que sabe configurar la app de avisos (anterior a la v1.5)."""
    return FEATURE_AVISOS not in agent_features(status)


def _hint_sin_conexion(fw_ok: bool | None, host: str, port: int) -> str:
    if fw_ok is False:
        return (f"El Firewall de Windows de la PC del MDM no tiene abierto el puerto {port}: ejecuta "
                "ABRIR_FIREWALL.bat como administrador.")
    return (f"La tablet no llega a {host}:{port}. Revisa que esté en la misma red que la PC del MDM, que el "
            f"Firewall permita el puerto {port} (ABRIR_FIREWALL.bat) y que ningún antivirus lo bloquee.")


def diagnose(dev, presence: dict | None, attempt: dict | None, attempt_ip: dict | None, *,
             now: datetime, fw_ok: bool | None, host: str, port: int) -> dict:
    """{"nivel": ok|info|warn|err, "titulo", "detalle", "agente", "app"} para una tablet."""
    status = dev.status or {}
    apps = installed_apps(status)
    app = apps.get(AVISOS_PKG)
    out = {"agente": agent_label(status, dev.agent_version or ""),
           "app": f"v{app.get('version_name') or '?'}" if app else "no instalada" if apps else "—"}

    def res(nivel: str, titulo: str, detalle: str = "") -> dict:
        upd = str(status.get("agent_update_error") or "")
        if upd and nivel != "ok":
            detalle = f"{detalle} Además, el agente no pudo actualizarse solo: {upd[:250]}".strip()
        out.update(nivel=nivel, titulo=titulo, detalle=detalle)
        return out

    if (presence or {}).get("online"):
        return res("ok", "Conectada", "Recibe los avisos al instante.")

    last_seen = _aware(dev.last_seen)
    if last_seen is None or now - last_seen > STALE_CHECKIN:
        return res("err", "La tablet no se reporta al MDM",
                   "Está apagada, sin Wi-Fi o fuera de la red. Cuando vuelva, la app de avisos se conecta sola.")

    # El broker la vio intentar y la rechazó: la tablet tiene una clave/usuario que ya no vale.
    tries = [a for a in (attempt, attempt_ip) if a and a.get("since")]
    if tries:
        a = max(tries, key=lambda x: _aware(x["since"]))
        if not a.get("ok") and now - _aware(a["since"]) < timedelta(minutes=15):
            motivo = CODES.get(a.get("code"), f"código {a.get('code')}")
            quien = f"usuario «{a.get('user') or '(vacío)'}»"
            fix = ("Con el agente v1.5+ la configuración nueva le llega sola en la siguiente sincronización."
                   if not agent_is_old(status) else
                   "Su agente es anterior a la v1.5 y no le puede enviar la configuración correcta: actualízalo.")
            return res("err", f"El servidor MQTT la rechazó ({motivo})",
                       f"Intentó conectarse desde {a.get('ip') or '?'} con {quien}. {fix}")

    if apps and not app:
        err = str(status.get("last_error") or "")
        detalle = (f"El agente informó: {err[:300]}" if AVISOS_PKG in err else
                   "Todavía no está instalada. El agente la instala en la próxima sincronización (menos de 1 minuto); "
                   "si no aparece, revisa la página de la tablet.")
        return res("warn", "La app de avisos no está instalada", detalle)

    if agent_is_old(status):
        return res("err", "Agente MDM anterior a la v1.5",
                   f"El agente de esta tablet, {out['agente']}, instala la app de avisos pero no le entrega la "
                   "configuración (servidor, usuario y clave) ni la arranca, así que la app nunca se conecta. "
                   "Hay que poner el agente v1.5 en la tablet (ver «Cómo actualizar el agente» arriba).")

    svc = status.get("avisos_servicio") if isinstance(status.get("avisos_servicio"), dict) else {}
    info = svc.get(AVISOS_PKG) if isinstance(svc.get(AVISOS_PKG), dict) else {}
    estado_app = str(info.get("estado") or "")
    hace = info.get("hace_s")
    reciente = isinstance(hace, (int, float)) and hace <= APP_SILENCE_S
    if estado_app and reciente:
        if info.get("conectado"):
            return res("info", "La app dice que está conectada",
                       "El servidor aún no recibe su estado; debería verse «Conectada» en unos segundos.")
        texto = f"La app informa: «{estado_app[:200]}». "
        bajo = estado_app.lower()
        if "sin configurar" in bajo:
            return res("err", "La app no recibió su configuración",
                       texto + "El agente reintenta entregarla en cada sincronización. Si sigue así, revisa los "
                               "errores de la política en la página de la tablet.")
        if "rechazada" in bajo:
            return res("err", "El servidor MQTT rechazó a la tablet",
                       texto + "La configuración nueva le llega sola en la siguiente sincronización.")
        if "sin conexión" in bajo or "conectando" in bajo or "reconectando" in bajo:
            return res("err", "La app no llega al servidor MQTT", texto + _hint_sin_conexion(fw_ok, host, port))
        return res("warn", "La app todavía no se conecta", texto)

    arranque = str(info.get("arranque") or "")
    if arranque and arranque != "ok":
        return res("err", "Android no deja arrancar la app de avisos",
                   f"{arranque[:300]}. El agente vuelve a intentarlo y, si hace falta, abre la app un instante "
                   "para que arranque sola.")
    if estado_app and not reciente:
        return res("warn", "La app dejó de dar señales",
                   "Su servicio se detuvo (ahorro de batería de HyperOS o la app se cerró). El agente la vuelve a "
                   "arrancar en la próxima sincronización.")
    return res("info", "Esperando que la app arranque y se conecte",
               "El agente acaba de entregarle la configuración y de arrancarla. Recarga en 1 minuto.")
