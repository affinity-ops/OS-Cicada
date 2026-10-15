package com.cicada.aegis.aegis_ciba_companion

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Stops the native alarm when the notification is swiped away.
 * Registered as the deleteIntent on the HITL notification.
 */
class AlarmStopReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
        HitlFirebaseMessagingService.stopAlarm()
    }
}
