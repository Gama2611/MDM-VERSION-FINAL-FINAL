"""v1.5: por qué una tablet no recibe avisos (diagnóstico), reenvío de la configuración cuando cambia,
versión más nueva de las apps y actualización automática del agente."""
import io
import queue
import time
from datetime import timedelta

import paho.mqtt.client as mqtt
from sqlalchemy import select

from test_avisos import Tablet, add_avisos_app, enroll_and_policy, mclient, wait  # noqa: F401
from test_control import db
from test_mdm import setup_android

AV = "com.adipack.avisos"


def checkin(client, h, version, rev=None, status=None):
    body = {"applied_policy_version": version, "status": status or {}}
    if rev is not None:
        body["applied_policy_rev"] = rev
    r = client.post("/api/v1/checkin", json=body, headers=h)
    assert r.status_code == 200, r.text
    return r.json()


def enroll_h(client, token, hw):
    from test_mdm import enroll
    r = enroll(client, token, hw)
    return r.json()["device_id"], {"Authorization": f"Bearer {r.json()['device_token']}"}


def test_policy_resent_when_per_device_config_changes(mclient):
    csrf, pid, token = setup_android(mclient)
    add_avisos_app(pid)
    dev_id, h = enroll_h(mclient, token, "hw-rev")
    pol = checkin(mclient, h, 0)["policy"]
    v, rev = pol["version"], pol["rev"]
    # Agente v1.5 con la política al día: no viaja nada
    assert checkin(mclient, h, v, rev)["policy"] is None
    # Agente antiguo (no manda rev): sólo por versión, como siempre
    assert checkin(mclient, h, v)["policy"] is None
    # Cambia algo que se calcula por tablet (el nombre): mismo número de versión, pero se reenvía
    from app.models import Device
    with db() as s:
        s.get(Device, dev_id).name = "TAB-RENOMBRADA"
        s.commit()
    pol2 = checkin(mclient, h, v, rev)["policy"]
    assert pol2 is not None and pol2["version"] == v and pol2["rev"] != rev
    assert pol2["app_configs"][AV]["dispositivo_nombre"] == "TAB-RENOMBRADA"
    assert checkin(mclient, h, v, pol2["rev"])["policy"] is None
    # Cambia la clave MQTT (otra SECRET_KEY): la tablet recibe la clave nueva
    from app.config import get_settings
    old = get_settings().secret_key
    try:
        get_settings().secret_key = old + "-nueva"
        pol3 = checkin(mclient, h, v, pol2["rev"])["policy"]
        assert pol3 is not None and pol3["app_configs"][AV]["clave"] != pol2["app_configs"][AV]["clave"]
    finally:
        get_settings().secret_key = old


def test_newest_uploaded_version_is_delivered_and_upload_bumps_policy(mclient):
    csrf, pid, token = setup_android(mclient)
    add_avisos_app(pid)  # versión 7
    from app.models import App, Policy
    with db() as s:
        v_before = s.get(Policy, pid).version
        s.add(App(package_name=AV, label="ADIPACK Avisos", filename="a8.apk", sha256="8" * 64,
                  version_name="1.0.8", version_code=8))
        s.commit()
    dev_id, h = enroll_h(mclient, token, "hw-new")
    pol = checkin(mclient, h, 0)["policy"]
    av = [a for a in pol["required_apps"] if a["package"] == AV]
    assert len(av) == 1 and av[0]["version_code"] == 8  # la más nueva, aunque la política marque la 7
    # Subir un APK nuevo por la consola sube la versión de las políticas que ya usan esa app
    import test_avisos as ta  # noqa: F401
    from app import services
    orig = services.read_apk_info
    services.read_apk_info = lambda path: {"package": AV, "version_code": 9, "version_name": "1.0.9", "label": "ADIPACK Avisos"}
    try:
        from test_mdm import csrf_of
        r = mclient.post("/apps/upload", data={"csrf": csrf_of(mclient, "/apps")},
                         files={"file": ("avisos.apk", io.BytesIO(b"PK-fake-apk-9"), "application/octet-stream")},
                         follow_redirects=False)
        assert r.status_code == 303, r.text
    finally:
        services.read_apk_info = orig
    with db() as s:
        assert s.get(Policy, pid).version == v_before + 1
    pol = checkin(mclient, h, pol["version"], pol["rev"])["policy"]
    assert [a["version_code"] for a in pol["required_apps"] if a["package"] == AV] == [9]


def test_agent_update_offered_only_for_signed_agent(mclient, monkeypatch):
    csrf, pid, token = setup_android(mclient)
    from app import services
    from app.models import App
    from app.config import get_settings
    get_settings().apk_dir.mkdir(parents=True, exist_ok=True)
    (get_settings().apk_dir / "agente-50.apk").write_bytes(b"x")
    with db() as s:
        s.add(App(package_name="com.adipack.mdm.agent", label="Agente", filename="agente-50.apk", sha256="a" * 64,
                  version_name="1.5.0", version_code=50, is_agent=True))
        s.commit()
    dev_id, h = enroll_h(mclient, token, "hw-upd")
    monkeypatch.setattr(services, "is_debug_signed_cached", lambda p: True)
    assert "agent_update" not in checkin(mclient, h, 0)["policy"]
    monkeypatch.setattr(services, "is_debug_signed_cached", lambda p: False)
    upd = checkin(mclient, h, 0)["policy"]["agent_update"]
    assert upd["version_code"] == 50 and upd["sha256"] == "a" * 64 and upd["url"].endswith("/download")


def _dev(**kw):
    from types import SimpleNamespace
    from app.mqtt_bus import utcnow
    base = dict(id=3, status={}, last_seen=utcnow(), agent_version="1.0.0")
    base.update(kw)
    return SimpleNamespace(**base)


def _diag(dev, presence=None, attempt=None, attempt_ip=None, fw_ok=None):
    from app.avisos_diag import diagnose
    from app.mqtt_bus import utcnow
    return diagnose(dev, presence, attempt, attempt_ip, now=utcnow(), fw_ok=fw_ok, host="192.168.1.10", port=1883)


AGENT_OLD = {"package": "com.adipack.mdm.agent", "version_name": "1.0.12", "version_code": 12}
APP = {"package": AV, "version_name": "1.0.1", "version_code": 2}


def test_diagnosis_cases():
    from app.mqtt_bus import utcnow
    assert _diag(_dev(), presence={"online": True})["nivel"] == "ok"
    d = _diag(_dev(last_seen=utcnow() - timedelta(hours=2)))
    assert d["titulo"] == "La tablet no se reporta al MDM"
    # Caso de la planta: agente antiguo, app instalada pero sin configurar ni arrancar
    d = _diag(_dev(status={"apps": [AGENT_OLD, APP]}))
    assert d["nivel"] == "err" and "anterior a la v1.5" in d["titulo"] and d["agente"].startswith("v1.0.12")
    assert d["app"] == "v1.0.1"
    # App no instalada (con el error que dio el agente)
    d = _diag(_dev(status={"apps": [AGENT_OLD], "last_error": "Política: com.adipack.avisos: Estado 1: INSTALL_FAILED"}))
    assert "no está instalada" in d["titulo"] and "INSTALL_FAILED" in d["detalle"]
    feats = ["avisos_config", "app_status", "policy_rev", "auto_update"]
    # Agente v1.5: la app dice que no llega y el firewall está cerrado
    st = {"apps": [AGENT_OLD, APP], "agent_features": feats,
          "avisos_servicio": {AV: {"estado": "Sin conexión con 192.168.1.10:1883 (timeout). Reintentando…", "conectado": False,
                                   "hace_s": 20, "arranque": "ok"}}}
    d = _diag(_dev(status=st), fw_ok=False)
    assert d["titulo"] == "La app no llega al servidor MQTT" and "ABRIR_FIREWALL" in d["detalle"]
    st["avisos_servicio"][AV]["estado"] = "Sin configurar: instala la app desde el MDM o configúrala a mano"
    assert _diag(_dev(status=st))["titulo"] == "La app no recibió su configuración"
    # Sin señales de la app y Android no dejó arrancarla
    st["avisos_servicio"] = {AV: {"arranque": "SecurityException: not allowed"}}
    assert _diag(_dev(status=st))["titulo"] == "Android no deja arrancar la app de avisos"
    # El broker la rechazó hace poco
    d = _diag(_dev(status=st), attempt={"ok": False, "since": utcnow(), "ip": "192.168.1.50", "code": 4, "user": "tablet-3"})
    assert "rechazó" in d["titulo"] and "usuario o clave" in d["titulo"] and "192.168.1.50" in d["detalle"]


def test_broker_records_attempts_and_page_shows_diagnosis(mclient):
    csrf, pid, token = setup_android(mclient)
    add_avisos_app(pid)
    from app.mqtt_bus import bus
    assert bus.wait_ready()
    dev_id, pol = enroll_and_policy(mclient, token, "hw-diag")
    cfg = pol["app_configs"][AV]
    # La página explica por qué no está conectada (agente sin «features» = anterior a la v1.5)
    page = mclient.get("/avisos").text
    assert "Nunca se ha conectado" in page and "Agente MDM anterior a la v1.5" in page and "Cómo actualizar el agente" in page
    # Clave equivocada: el broker lo anota para esa tablet
    bad = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=cfg["usuario"])
    rcq = queue.Queue()
    bad.on_connect = lambda c, u, f, rc, p: rcq.put(rc.value)
    bad.username_pw_set(cfg["usuario"], "vieja")
    bad.connect("127.0.0.1", bus.port)
    bad.loop_start()
    assert rcq.get(timeout=5) == 134
    bad.loop_stop()
    assert wait(lambda: bus.attempts.get(dev_id, {}).get("ok") is False)
    assert bus.attempts[dev_id]["ip"] == "127.0.0.1" and bus.attempts[dev_id]["code"] == 4
    assert "El servidor MQTT la rechazó (usuario o clave incorrectos)" in mclient.get("/avisos").text
    # Con la clave buena se conecta y la página lo muestra
    t = Tablet(cfg, bus.port)
    assert wait(lambda: bus.is_online(dev_id)) and bus.attempts[dev_id]["ok"] is True
    page = mclient.get("/avisos").text
    assert "● Conectada" in page and "Agente MDM anterior" not in page.split("Tablets</h2>")[1].split("</table>")[0]
    t.stop()


def test_reenroll_after_wipe_keeps_device_by_serial(client):
    csrf, pid, token = setup_android(client)
    body = {"enrollment_token": token, "platform": "android", "hardware_id": "android-abc123", "manufacturer": "Xiaomi",
            "model": "Redmi Pad 2", "serial": "RP2SERIAL01", "agent_version": "1.0"}
    first = client.post("/api/v1/enroll", json=body).json()
    # Borrado de fábrica: ANDROID_ID cambia; el agente nuevo manda el serial como identificador
    body2 = {**body, "hardware_id": "android-sn-RP2SERIAL01"}
    second = client.post("/api/v1/enroll", json=body2).json()
    assert second["device_id"] == first["device_id"] and second["name"] == first["name"]
    from app.models import Device
    with db() as s:
        assert s.get(Device, first["device_id"]).hardware_id == "android-sn-RP2SERIAL01"
        assert len(s.scalars(select(Device)).all()) == 1
