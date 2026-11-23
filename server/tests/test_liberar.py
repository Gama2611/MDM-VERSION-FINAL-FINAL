"""Recuperar una tablet retirada, liberarla del MDM y borrado de fábrica limpio (v1.5)."""
from datetime import timedelta

from sqlalchemy import select

from test_control import db
from test_mdm import enroll, setup_android


def _enroll(client, token, hw="hw-lib"):
    r = enroll(client, token, hw).json()
    return r["device_id"], {"Authorization": f"Bearer {r['device_token']}"}


def checkin(client, h, applied, status=None, code=200):
    r = client.post("/api/v1/checkin", json={"applied_policy_version": applied, "status": status or {}}, headers=h)
    assert r.status_code == code, r.text
    return r.json()


def cmd(client, csrf, dev_id, ctype, confirm):
    r = client.post(f"/devices/{dev_id}/command", data={"csrf": csrf, "type": ctype, "confirm": confirm}, follow_redirects=False)
    assert r.status_code == 303
    return r


def get_dev(dev_id):
    from app.models import Device
    with db() as s:
        d = s.get(Device, dev_id)
        s.expunge(d)
        return d


def test_tablet_hidden_by_old_wipe_bug_can_be_reactivated(client):
    """El caso de la planta: el borrado se reportó, la tablet quedó «retirada» pero sigue con el MDM."""
    csrf, pid, token = setup_android(client)
    dev_id, h = _enroll(client, token)
    pol = checkin(client, h, 0)["policy"]
    from app.models import Device
    with db() as s:
        s.get(Device, dev_id).retired = True  # lo que hacía la v1.4 al recibir «Borrando equipo…»
        s.commit()
    checkin(client, h, pol["version"], code=401)
    home = client.get("/").text
    assert "Equipos retirados (1)" in home and "Reactivar" in home
    r = client.post(f"/devices/{dev_id}/reactivate", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    checkin(client, h, pol["version"])  # el mismo token vuelve a funcionar
    assert "Equipos retirados" not in client.get("/").text and "TAB-01" in client.get("/").text


def test_manual_retire_then_reactivate_restores_access(client):
    csrf, pid, token = setup_android(client)
    dev_id, h = _enroll(client, token)
    client.post(f"/devices/{dev_id}/retire", data={"csrf": csrf, "confirm": "TAB-01"})
    checkin(client, h, 0, code=401)
    client.post(f"/devices/{dev_id}/reactivate", data={"csrf": csrf})
    checkin(client, h, 0)


def test_release_removes_kiosk_and_restrictions(client):
    csrf, pid, token = setup_android(client)
    dev_id, h = _enroll(client, token)
    v = checkin(client, h, 0)["policy"]["version"]
    cmd(client, csrf, dev_id, "release", "mal")  # confirmación equivocada: no hace nada
    assert get_dev(dev_id).release_state == ""
    cmd(client, csrf, dev_id, "release", "TAB-01")
    p = checkin(client, h, v)["policy"]
    from app.liberar import RELEASE_VERSION
    assert p["version"] == RELEASE_VERSION and p["release"] is True
    assert p["kiosk_enabled"] is False and p["required_apps"] == [] and p["kiosk_extra_packages"] == []
    assert all(p[k] is False for k in p if k.startswith("disable_"))
    assert p["disable_factory_reset"] is False and p["disable_camera"] is False and p["wifi_ssid"] == ""
    assert "kiosk_exit_pin" not in p and "app_configs" not in p
    out = checkin(client, h, RELEASE_VERSION)
    assert out["policy"] is None and out["commands"] == []  # sólo liberar: no se borra
    assert "ya está <b>liberada</b>" in client.get(f"/devices/{dev_id}").text
    # Cancelar: vuelve su política normal
    client.post(f"/devices/{dev_id}/release/cancel", data={"csrf": csrf})
    assert checkin(client, h, RELEASE_VERSION)["policy"]["version"] == v


def test_clean_wipe_flow_never_loses_the_tablet(client):
    csrf, pid, token = setup_android(client)
    dev_id, h = _enroll(client, token)
    v = checkin(client, h, 0)["policy"]["version"]
    cmd(client, csrf, dev_id, "wipe", "TAB-01")
    from app.liberar import RELEASE_VERSION
    out = checkin(client, h, v)
    assert out["policy"]["version"] == RELEASE_VERSION and out["commands"] == []  # paso 1: liberar
    out = checkin(client, h, RELEASE_VERSION)  # la tablet confirmó: paso 2 en la misma respuesta
    assert out["policy"] is None and [c["type"] for c in out["commands"]] == ["wipe"]
    wid = out["commands"][0]["id"]
    assert checkin(client, h, RELEASE_VERSION)["commands"] == []  # no se duplica
    client.post(f"/api/v1/commands/{wid}/result", json={"success": True, "output": "Borrando equipo…"}, headers=h)
    d = get_dev(dev_id)
    assert d.retired is False and d.release_state == "borrada"
    assert "Borrada: falta escanear el QR" in client.get("/").text
    # Sigue reportándose pasado el margen: el borrado no se ejecutó
    from app.models import Command
    with db() as s:
        c = s.get(Command, wid)
        c.finished_at = c.finished_at - timedelta(minutes=3)
        s.commit()
    checkin(client, h, RELEASE_VERSION, status={"last_error": "wipe falló: SecurityException: Factory reset is not allowed"})
    checkin(client, h, RELEASE_VERSION)
    assert get_dev(dev_id).release_state == "borrado_fallido"
    with db() as s:
        c = s.get(Command, wid)
        assert c.state == "failed" and "no se ejecutó" in c.result
    page = client.get(f"/devices/{dev_id}").text
    assert "El borrado no se ejecutó" in page and "Restablecer datos de fábrica" in page and "Wipe Data" in page


def test_wipe_result_right_away_and_reenroll_after_reset(client):
    csrf, pid, token = setup_android(client)
    body = {"enrollment_token": token, "platform": "android", "hardware_id": "android-sn-SER1", "manufacturer": "Xiaomi",
            "model": "Redmi Pad 2", "serial": "SER1", "agent_version": "1.0"}
    first = client.post("/api/v1/enroll", json=body).json()
    h = {"Authorization": f"Bearer {first['device_token']}"}
    checkin(client, h, 0)
    cmd(client, csrf, first["device_id"], "wipe", first["name"])
    from app.liberar import RELEASE_VERSION
    checkin(client, h, 0)
    wid = checkin(client, h, RELEASE_VERSION)["commands"][0]["id"]
    client.post(f"/api/v1/commands/{wid}/result", json={"success": True, "output": "Borrando equipo…"}, headers=h)
    # La tablet se borró y se vuelve a activar con el QR: mismo registro, estado limpio, política normal
    again = client.post("/api/v1/enroll", json=body).json()
    assert again["device_id"] == first["device_id"] and again["name"] == first["name"]
    d = get_dev(first["device_id"])
    assert d.release_state == "" and d.retired is False
    h2 = {"Authorization": f"Bearer {again['device_token']}"}
    assert checkin(client, h2, 0)["policy"]["version"] != RELEASE_VERSION


def test_wipe_sent_anyway_if_release_never_confirmed(client):
    csrf, pid, token = setup_android(client)
    dev_id, h = _enroll(client, token)
    v = checkin(client, h, 0)["policy"]["version"]
    cmd(client, csrf, dev_id, "wipe", "TAB-01")
    assert checkin(client, h, v)["commands"] == []
    from app.models import Device
    with db() as s:
        d = s.get(Device, dev_id)
        d.release_at = d.release_at - timedelta(minutes=6)
        s.commit()
    assert [c["type"] for c in checkin(client, h, v)["commands"]] == ["wipe"]
