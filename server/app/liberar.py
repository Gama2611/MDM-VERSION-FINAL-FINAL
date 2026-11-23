"""Liberar una tablet del MDM y borrado de fábrica limpio, sin perder nunca la tablet de la consola.

Antes (hasta v1.5.0) el borrado de fábrica marcaba la tablet como «retirada» apenas el agente decía
«Borrando equipo…». Si el borrado no llegaba a ejecutarse (HyperOS lo bloquea mientras rige la restricción
«no permitir restablecer»), la tablet desaparecía de la consola y quedaba bloqueada con el MDM.

Ahora:
1. **Liberar**: la tablet recibe una política especial que quita el kiosco y todas las restricciones
   (restablecer de fábrica, cámara, depuración, barra de estado...). Funciona con cualquier agente, también los
   antiguos, porque es una política normal. Después se puede restablecer a mano desde Ajustes.
2. **Borrado de fábrica limpio** = liberar + (cuando la tablet confirma que se liberó) orden de borrado.
   La tablet nunca se retira sola: queda en la lista como «Borrada, falta escanear el QR». Si después del
   borrado sigue reportándose, se marca «El borrado no se ejecutó» y se indica cómo hacerlo a mano.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

# Número de versión reservado para la política de liberación (el agente lo informa al aplicarla).
RELEASE_VERSION = 2_000_000_000
WIPE_FALLBACK_AFTER = timedelta(minutes=5)   # si no confirma la liberación, se intenta el borrado igual
WIPE_GRACE = timedelta(seconds=90)           # si sigue reportándose pasado esto, el borrado falló

STATES = {
    "liberar": ("warn", "Liberando del MDM"),
    "borrar": ("warn", "Borrado de fábrica en curso"),
    "borrada": ("info", "Borrada: falta escanear el QR"),
    "borrado_fallido": ("err", "El borrado no se ejecutó"),
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(d):
    return d.replace(tzinfo=timezone.utc) if d is not None and d.tzinfo is None else d


def release_policy() -> dict:
    """Política Android «sin MDM»: sin kiosco, sin restricciones, sin apps obligatorias."""
    from .schemas import AndroidPolicy
    from .services import policy_rev

    p = AndroidPolicy(kiosk_enabled=False).model_dump()
    for k in list(p):
        if k.startswith("disable_"):
            p[k] = False
    p.update(kiosk_enabled=False, kiosk_package="", kiosk_extra_packages=[], kiosk_exit_pin="",
             stay_on_while_plugged=False, auto_grant_permissions=False, system_updates="automatic",
             wifi_ssid="", wifi_password="", app_config={})
    p.pop("required_app_ids", None)
    p.pop("kiosk_exit_pin", None)
    p.update(version=RELEASE_VERSION, release=True, required_apps=[], kiosk_exit_pin_hash="", kiosk_exit_pin_salt="")
    p["rev"] = policy_rev(p)
    return p


def released(dev) -> bool:
    """La tablet confirmó que aplicó la política de liberación."""
    return dev.applied_policy_version == RELEASE_VERSION


def on_checkin(db, dev, applied_version: int) -> dict | None:
    """Lógica de liberación en cada check-in. Devuelve la política a enviar (o None)."""
    from .models import Command
    from .services import audit

    state = dev.release_state or ""
    if not state:
        return None
    now = _now()
    if state == "borrada":
        wipe = db.scalar(select(Command).where(Command.device_id == dev.id, Command.type == "wipe",
                                               Command.state == "done").order_by(Command.id.desc()))
        finished = _aware(wipe.finished_at) if wipe else None
        if finished is None or now - finished > WIPE_GRACE:
            # Sigue viva: el borrado no ocurrió. Queda liberada para restablecerla a mano.
            dev.release_state = "borrado_fallido"
            if wipe is not None:
                wipe.state = "failed"
                err = str((dev.status or {}).get("last_error") or "")
                wipe.result = ("La tablet siguió reportándose después de la orden: el borrado no se ejecutó."
                               + (f" Error del agente: {err[:300]}" if err else ""))
            audit(db, f"device:{dev.id}", "wipe_fallido", dev.name)
        state = dev.release_state
    if applied_version != RELEASE_VERSION:
        out = release_policy()
    else:
        out = None
    if state == "borrar":
        pending = db.scalar(select(Command).where(Command.device_id == dev.id, Command.type == "wipe",
                                                  Command.state.in_(["pending", "sent"])))
        ready = applied_version == RELEASE_VERSION or (dev.release_at and now - _aware(dev.release_at) > WIPE_FALLBACK_AFTER)
        if pending is None and ready:
            db.add(Command(device_id=dev.id, type="wipe", params={"clean": True}, created_by="liberacion"))
            db.flush()
    return out


def on_wipe_result(dev, success: bool) -> None:
    """El agente informó la orden de borrado. Nunca se retira la tablet: queda esperando el QR."""
    if success:
        dev.release_state = "borrada"
    elif dev.release_state == "borrar":
        dev.release_state = "borrado_fallido"
