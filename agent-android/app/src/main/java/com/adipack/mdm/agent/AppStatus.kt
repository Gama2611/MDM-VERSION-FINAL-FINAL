package com.adipack.mdm.agent

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import org.json.JSONObject

/**
 * La app ADIPACK Avisos informa aquí su estado («Conectada · TAB-01», «Sin conexión con…», «Sin configurar»…)
 * cada vez que cambia y cada minuto. El agente lo guarda, lo usa para vigilarla (PolicyApplier.watchdog)
 * y lo envía al MDM en cada check-in: así la consola muestra por qué una tablet no recibe avisos.
 *
 * Sólo se aceptan paquetes que la política marca como servicios permanentes ("keep_alive_services").
 */
class AppStatusReceiver : BroadcastReceiver() {
    companion object {
        const val ACTION = "com.adipack.mdm.agent.action.APP_STATUS"
    }

    override fun onReceive(ctx: Context, intent: Intent) {
        if (intent.action != ACTION) return
        val pkg = intent.getStringExtra("package") ?: return
        val allowed = Prefs(ctx).policy().optJSONArray("keep_alive_services") ?: return
        if ((0 until allowed.length()).none { allowed.optJSONObject(it)?.optString("package") == pkg }) return
        val st = JSONObject()
            .put("estado", (intent.getStringExtra("estado") ?: "").take(300))
            .put("conectado", intent.getBooleanExtra("conectado", false))
            .put("version", (intent.getStringExtra("version") ?: "").take(32))
            .put("ms", System.currentTimeMillis())  // hora del agente: evita relojes distintos
        Prefs(ctx).setAppStatus(pkg, st)
    }
}
