package com.adipack.mdm.agent

import android.app.admin.DevicePolicyManager
import android.app.admin.SystemUpdatePolicy
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.wifi.WifiConfiguration
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.os.UserManager
import android.provider.Settings
import org.json.JSONArray
import org.json.JSONObject

/** Traduce la política JSON del servidor a llamadas de DevicePolicyManager. Idempotente. */
object PolicyApplier {

    fun apply(ctx: Context, p: JSONObject, api: Api): List<String> {
        val errors = mutableListOf<String>()
        if (!Dpm.isOwner(ctx)) return listOf("El agente no es Device Owner")
        val dpm = Dpm.dpm(ctx)
        val admin = Dpm.admin(ctx)

        fun step(name: String, block: () -> Unit) =
            try { block() } catch (e: Exception) { errors += "$name: ${e.message}"; logE("Política/$name", e) }

        // --- Restricciones de usuario ---
        val restrictions = buildMap {
            put(UserManager.DISALLOW_FACTORY_RESET, p.optBoolean("disable_factory_reset"))
            put(UserManager.DISALLOW_SAFE_BOOT, p.optBoolean("disable_safe_boot"))
            put(UserManager.DISALLOW_USB_FILE_TRANSFER, p.optBoolean("disable_usb_file_transfer"))
            put(UserManager.DISALLOW_DEBUGGING_FEATURES, p.optBoolean("disable_debugging"))
            put(UserManager.DISALLOW_ADD_USER, p.optBoolean("disable_add_user"))
            put(UserManager.DISALLOW_CONFIG_WIFI, p.optBoolean("disable_config_wifi"))
            put(UserManager.DISALLOW_BLUETOOTH, p.optBoolean("disable_bluetooth"))
            put(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES, p.optBoolean("disable_install_unknown_sources"))
            if (Build.VERSION.SDK_INT >= 29)
                put(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES_GLOBALLY, p.optBoolean("disable_install_unknown_sources"))
        }
        for ((key, on) in restrictions) step(key) {
            if (on) dpm.addUserRestriction(admin, key) else dpm.clearUserRestriction(admin, key)
        }

        step("camera") { dpm.setCameraDisabled(admin, p.optBoolean("disable_camera")) }
        step("screenshots") { dpm.setScreenCaptureDisabled(admin, p.optBoolean("disable_screenshots")) }
        step("statusbar") { dpm.setStatusBarDisabled(admin, p.optBoolean("disable_status_bar")) }
        step("keyguard") { dpm.setKeyguardDisabled(admin, p.optBoolean("disable_keyguard")) }
        step("stay_on") {
            val v = if (p.optBoolean("stay_on_while_plugged")) "7" else "0" // AC|USB|inalámbrico
            dpm.setGlobalSetting(admin, Settings.Global.STAY_ON_WHILE_PLUGGED_IN, v)
        }
        step("permissions") {
            dpm.setPermissionPolicy(admin,
                if (p.optBoolean("auto_grant_permissions")) DevicePolicyManager.PERMISSION_POLICY_AUTO_GRANT
                else DevicePolicyManager.PERMISSION_POLICY_PROMPT)
        }
        step("updates") {
            val pol = when (p.optString("system_updates")) {
                "automatic" -> SystemUpdatePolicy.createAutomaticInstallPolicy()
                "postpone" -> SystemUpdatePolicy.createPostponeInstallPolicy()
                else -> SystemUpdatePolicy.createWindowedInstallPolicy(
                    p.optInt("update_window_start_min", 120), p.optInt("update_window_end_min", 300))
            }
            dpm.setSystemUpdatePolicy(admin, pol)
        }
        step("wifi") { configureWifi(ctx, p) }

        // --- Configuración gestionada de la app del kiosco (RestrictionsManager) ---
        val kioskPkg = p.optString("kiosk_package")
        step("app_config") {
            if (kioskPkg.isNotEmpty()) dpm.setApplicationRestrictions(admin, kioskPkg, jsonToBundle(p.optJSONObject("app_config")))
        }

        // --- Configuración gestionada de otras apps (p. ej. ADIPACK Avisos: servidor MQTT, usuario, clave) ---
        step("app_configs") { applyAppConfigs(ctx, p) }

        // --- Apps obligatorias antes del kiosco (la app del kiosco debe existir) ---
        errors += ensureRequiredApps(ctx, p, api)
        errors += afterApps(ctx, p)

        // --- Kiosco ---
        step("kiosk") { applyKiosk(ctx, p) }
        // Política de liberación (MDM › «Liberar del MDM»): además se devuelve el inicio de Xiaomi.
        if (p.optBoolean("release")) step("release") {
            dpm.clearPackagePersistentPreferredActivities(admin, ctx.packageName)
            prefs(ctx).kioskSuspendedUntil = 0
        }
        return errors
    }

    private fun prefs(ctx: Context) = Prefs(ctx)

    fun ensureRequiredApps(ctx: Context, p: JSONObject, api: Api): List<String> {
        val errors = mutableListOf<String>()
        val apps = p.optJSONArray("required_apps") ?: JSONArray()
        for (i in 0 until apps.length()) {
            val a = apps.getJSONObject(i)
            val pkg = a.getString("package")
            val want = a.optLong("version_code")
            val have = installedVersion(ctx, pkg)
            if (have != null && have >= want) continue
            val r = AppInstaller.installFromServer(ctx, api, a.getString("url"), a.getString("sha256"), pkg)
            if (!r.success) errors += "$pkg: ${r.output}"
        }
        return errors
    }

    fun applyKiosk(ctx: Context, p: JSONObject) {
        val dpm = Dpm.dpm(ctx)
        val admin = Dpm.admin(ctx)
        val prefs = Prefs(ctx)
        val enabled = p.optBoolean("kiosk_enabled") && !prefs.kioskSuspended()
        val home = IntentFilter(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_HOME); addCategory(Intent.CATEGORY_DEFAULT)
        }
        if (enabled) {
            val pkgs = mutableListOf(ctx.packageName, p.optString("kiosk_package"))
            p.optJSONArray("kiosk_extra_packages")?.let { arr -> for (i in 0 until arr.length()) pkgs += arr.getString(i) }
            dpm.setLockTaskPackages(admin, pkgs.filter { it.isNotEmpty() }.distinct().toTypedArray())
            if (Build.VERSION.SDK_INT >= 28) {
                var f = DevicePolicyManager.LOCK_TASK_FEATURE_NONE
                if (p.optBoolean("kiosk_show_system_info")) f = f or DevicePolicyManager.LOCK_TASK_FEATURE_SYSTEM_INFO
                if (p.optBoolean("kiosk_allow_power_menu")) f = f or DevicePolicyManager.LOCK_TASK_FEATURE_GLOBAL_ACTIONS
                if (p.optBoolean("kiosk_show_home_button")) f = f or DevicePolicyManager.LOCK_TASK_FEATURE_HOME
                if (p.optBoolean("kiosk_show_notifications"))  // NOTIFICATIONS exige HOME
                    f = f or DevicePolicyManager.LOCK_TASK_FEATURE_NOTIFICATIONS or DevicePolicyManager.LOCK_TASK_FEATURE_HOME
                dpm.setLockTaskFeatures(admin, f)
            }
            dpm.addPersistentPreferredActivity(admin, home, ComponentName(ctx, KioskActivity::class.java))
            KioskActivity.launch(ctx)
        } else {
            // Quitar paquetes de la lista termina el lock task en curso.
            dpm.setLockTaskPackages(admin, emptyArray())
            if (!p.optBoolean("kiosk_enabled")) dpm.clearPackagePersistentPreferredActivities(admin, ctx.packageName)
            KioskActivity.launch(ctx, unlock = true)
        }
    }

    /**
     * Configuración gestionada (RestrictionsManager) para cada app de "app_configs", salvo la del kiosco.
     * Sólo escribe si cambió (cada escritura despierta a la app). Se repite después de instalar y en cada
     * sincronización: así la app la tiene aunque se haya instalado después, reinstalado o borrado sus datos.
     */
    fun applyAppConfigs(ctx: Context, p: JSONObject) {
        val configs = p.optJSONObject("app_configs") ?: return
        val kioskPkg = p.optString("kiosk_package")
        val dpm = Dpm.dpm(ctx)
        val admin = Dpm.admin(ctx)
        for (pkg in configs.keys()) {
            if (pkg == kioskPkg) continue  // la del kiosco usa "app_config"
            val want = jsonToBundle(configs.optJSONObject(pkg))
            val have = try { dpm.getApplicationRestrictions(admin, pkg) } catch (e: Exception) { null }
            if (have == null || !sameBundle(have, want)) dpm.setApplicationRestrictions(admin, pkg, want)
        }
    }

    private fun sameBundle(a: Bundle, b: Bundle): Boolean {
        if (a.keySet() != b.keySet()) return false
        @Suppress("DEPRECATION")
        return a.keySet().all { k -> a.get(k)?.toString() == b.get(k)?.toString() }
    }

    /**
     * Después de instalar apps: concede los permisos indicados ("grant_permissions") y enciende los
     * servicios que deben estar siempre activos ("keep_alive_services"). Se repite en cada sincronización:
     * si Android o el ahorro de batería detuvo el servicio, el agente (Device Owner) lo vuelve a iniciar.
     */
    fun afterApps(ctx: Context, p: JSONObject): List<String> {
        val errors = mutableListOf<String>()
        if (!Dpm.isOwner(ctx)) return errors
        val dpm = Dpm.dpm(ctx)
        val admin = Dpm.admin(ctx)
        val grants = p.optJSONArray("grant_permissions") ?: JSONArray()
        for (i in 0 until grants.length()) {
            val g = grants.optJSONObject(i) ?: continue
            val pkg = g.optString("package")
            if (pkg.isEmpty() || installedVersion(ctx, pkg) == null) continue
            val perms = g.optJSONArray("permissions") ?: continue
            for (j in 0 until perms.length()) {
                val perm = perms.optString(j)
                // POST_NOTIFICATIONS sólo es un permiso «peligroso» desde Android 13.
                if (perm == "android.permission.POST_NOTIFICATIONS" && Build.VERSION.SDK_INT < 33) continue
                try {
                    if (dpm.getPermissionGrantState(admin, pkg, perm) != DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED &&
                        !dpm.setPermissionGrantState(admin, pkg, perm, DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED))
                        errors += "$pkg: no se pudo conceder $perm"
                } catch (e: Exception) { errors += "$pkg/$perm: ${e.message}" }
            }
        }
        try { applyAppConfigs(ctx, p) } catch (e: Exception) { errors += "app_configs: ${e.message}" }
        val services = p.optJSONArray("keep_alive_services") ?: JSONArray()
        for (i in 0 until services.length()) {
            val sv = services.optJSONObject(i) ?: continue
            val pkg = sv.optString("package")
            val cls = sv.optString("service")
            if (pkg.isEmpty() || cls.isEmpty() || installedVersion(ctx, pkg) == null) continue
            val result = try {
                val cn = ctx.startForegroundService(Intent().setComponent(ComponentName(pkg, cls)))
                if (cn == null) "Android no encontró el servicio $cls" else "ok"
            } catch (e: Exception) {
                logE("No se pudo iniciar $pkg/$cls", e)
                "${e.javaClass.simpleName}: ${e.message}"
            }
            watchdog(ctx, pkg, sv.optString("start_activity"), result)
        }
        return errors
    }

    private const val SILENCE_MS = 3 * 60_000L      // sin noticias de la app en 3 min tras arrancarla
    private const val KICK_EVERY_MS = 15 * 60_000L  // como mucho, abrir la app una vez cada 15 min

    /**
     * Vigilancia de una app que debe estar siempre activa (ADIPACK Avisos). La app informa su estado al agente
     * (AppStatusReceiver) cada minuto. Si después de arrancar su servicio pasan 3 min sin noticias, es que
     * Android/HyperOS no la dejó arrancar desde otra app: el agente abre un instante su pantalla invisible de
     * arranque ("start_activity"), que enciende el servicio desde la propia app.
     */
    private fun watchdog(ctx: Context, pkg: String, startActivity: String, startResult: String) {
        val prefs = Prefs(ctx)
        val now = System.currentTimeMillis()
        val w = prefs.watch(pkg)
        w.put("arranque", startResult).put("arranque_ms", now)
        val lastStatus = prefs.appStatus(pkg)?.optLong("ms") ?: 0L
        var since = w.optLong("silencio_desde", 0L)
        if (lastStatus > since && since > 0L || now - lastStatus < SILENCE_MS) {
            since = 0L  // la app está viva
        } else if (since == 0L) {
            since = now  // empieza a contar desde este intento de arranque
        } else if (now - since >= SILENCE_MS && now - w.optLong("abierta_ms", 0L) >= KICK_EVERY_MS) {
            val cn = if (startActivity.isNotEmpty()) ComponentName.unflattenFromString(startActivity) else null
            if (cn != null && cn.packageName == pkg && activityExists(ctx, cn)) {
                w.put("abierta_ms", now)
                try {
                    ctx.startActivity(Intent().setComponent(cn).putExtra("origen", "mdm").addFlags(
                        Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION or
                            Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS))
                    logI("$pkg no daba señales: se abrió ${cn.className} para arrancarla")
                    w.put("abierta_resultado", "ok")
                } catch (e: Exception) {
                    logE("No se pudo abrir $startActivity", e)
                    w.put("abierta_resultado", "${e.javaClass.simpleName}: ${e.message}")
                }
            }
        }
        w.put("silencio_desde", since)
        prefs.setWatch(pkg, w)
    }

    private fun activityExists(ctx: Context, cn: ComponentName): Boolean = try {
        ctx.packageManager.getActivityInfo(cn, 0); true
    } catch (e: PackageManager.NameNotFoundException) { false }

    /** Resumen para el check-in: {paquete: {arranque, estado, conectado, version, hace_s, abierta_ms}}. */
    fun watchedStatus(ctx: Context, p: JSONObject): JSONObject {
        val out = JSONObject()
        val prefs = Prefs(ctx)
        val now = System.currentTimeMillis()
        val services = p.optJSONArray("keep_alive_services") ?: return out
        for (i in 0 until services.length()) {
            val pkg = services.optJSONObject(i)?.optString("package").orEmpty()
            if (pkg.isEmpty()) continue
            val w = prefs.watch(pkg)
            val o = JSONObject()
                .put("instalada", installedVersion(ctx, pkg) != null)
                .put("arranque", w.optString("arranque"))
                .put("configurada", try {
                    !Dpm.dpm(ctx).getApplicationRestrictions(Dpm.admin(ctx), pkg).isEmpty
                } catch (e: Exception) { false })
            if (w.has("abierta_ms")) o.put("abierta_hace_s", (now - w.optLong("abierta_ms")) / 1000)
            w.optString("abierta_resultado").takeIf { it.isNotEmpty() }?.let { o.put("abierta_resultado", it) }
            prefs.appStatus(pkg)?.let { st ->
                o.put("estado", st.optString("estado")).put("conectado", st.optBoolean("conectado"))
                    .put("version", st.optString("version")).put("hace_s", (now - st.optLong("ms")) / 1000)
            }
            out.put(pkg, o)
        }
        return out
    }

    /**
     * Actualización automática del agente: si el MDM tiene un agente firmado más nuevo, lo instala sobre sí
     * mismo (Device Owner, sin preguntar). Android reinicia el agente al terminar (MY_PACKAGE_REPLACED).
     * Si la firma no coincide u otro error, no se reintenta ese mismo archivo.
     */
    fun maybeSelfUpdate(ctx: Context, p: JSONObject, api: Api) {
        val u = p.optJSONObject("agent_update") ?: return
        val want = u.optLong("version_code")
        val sha = u.optString("sha256")
        val have = installedVersion(ctx, ctx.packageName) ?: return
        if (want <= have || sha.isEmpty()) return
        val prefs = Prefs(ctx)
        if (prefs.agentUpdateFailedSha == sha) return
        logI("Actualizando el agente: $have -> $want")
        val r = AppInstaller.installFromServer(ctx, api, u.optString("url"), sha, ctx.packageName)
        if (!r.success) {
            prefs.agentUpdateFailedSha = sha
            prefs.agentUpdateError = "No se pudo actualizar a ${u.optString("version_name")}: ${r.output}"
            logE(prefs.agentUpdateError)
        }
    }

    /** Tras instalar la app del kiosco, relanzar el kiosco para que la abra. */
    fun applyKioskIfTarget(ctx: Context, pkg: String) {
        val p = Prefs(ctx).policy()
        try { afterApps(ctx, p) } catch (e: Exception) { logE("afterApps", e) }
        if (p.optBoolean("kiosk_enabled") && p.optString("kiosk_package") == pkg) KioskActivity.launch(ctx)
    }

    fun installedVersion(ctx: Context, pkg: String): Long? = try {
        val info = ctx.packageManager.getPackageInfo(pkg, 0)
        if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else @Suppress("DEPRECATION") info.versionCode.toLong()
    } catch (e: PackageManager.NameNotFoundException) { null }

    private fun jsonToBundle(o: JSONObject?): Bundle {
        val b = Bundle()
        if (o == null) return b
        for (k in o.keys()) when (val v = o.get(k)) {
            is Boolean -> b.putBoolean(k, v)
            is Int -> b.putInt(k, v)
            is Long -> b.putLong(k, v)
            is Double -> b.putString(k, v.toString())
            is JSONObject -> b.putBundle(k, jsonToBundle(v))
            is JSONArray -> b.putStringArray(k, Array(v.length()) { v.get(it).toString() })
            JSONObject.NULL -> {}
            else -> b.putString(k, v.toString())
        }
        return b
    }

    @Suppress("DEPRECATION")
    private fun configureWifi(ctx: Context, p: JSONObject) {
        val ssid = p.optString("wifi_ssid")
        if (ssid.isEmpty()) return
        val wm = ctx.applicationContext.getSystemService(WifiManager::class.java) ?: return
        if (!wm.isWifiEnabled) wm.isWifiEnabled = true  // permitido a Device Owner
        val quoted = "\"$ssid\""
        // Device Owner está exento de la deprecación de addNetwork en Android 10+.
        val existing = try { wm.configuredNetworks?.firstOrNull { it.SSID == quoted } } catch (e: SecurityException) { null }
        val conf = WifiConfiguration().apply {
            SSID = quoted
            when (p.optString("wifi_security", "WPA")) {
                "WPA" -> preSharedKey = "\"${p.optString("wifi_password")}\""
                "WEP" -> { wepKeys[0] = "\"${p.optString("wifi_password")}\""; allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE) }
                else -> allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE)
            }
        }
        val id = if (existing != null) { conf.networkId = existing.networkId; wm.updateNetwork(conf) } else wm.addNetwork(conf)
        if (id == -1) throw IllegalStateException("addNetwork devolvió -1 para $ssid")
        wm.enableNetwork(id, false)
    }
}
