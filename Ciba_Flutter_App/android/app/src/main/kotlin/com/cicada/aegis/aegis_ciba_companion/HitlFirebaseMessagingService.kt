package com.cicada.aegis.aegis_ciba_companion

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.MediaPlayer
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

/**
 * Native Android FCM handler — runs even when app is killed.
 *
 * This is the MOST RELIABLE way to wake the device on Samsung/Android 14+.
 * It bypasses Flutter's background isolate entirely, which Samsung's battery
 * optimisation frequently kills.
 *
 * The handler:
 *   1. Acquires a 10-second wake lock to turn the screen on
 *   2. Starts a LOOPING MediaPlayer alarm at max volume
 *   3. Creates a high-priority notification with fullScreenIntent
 *   4. Launches MainActivity directly (which loads Flutter)
 *
 * The MediaPlayer alarm is stopped when:
 *   - The user opens the app (Flutter takes over with SoLoud)
 *   - The notification is dismissed
 *   - 60 seconds pass (safety timeout)
 */
class HitlFirebaseMessagingService : FirebaseMessagingService() {

    companion object {
        private const val TAG = "CicadaFCM"
        private const val CHANNEL_ID = "hitl_alerts_v3"
        private const val CHANNEL_NAME = "HITL Security Alerts"

        // Static MediaPlayer so it can be stopped from MainActivity
        var mediaPlayer: MediaPlayer? = null

        fun stopAlarm() {
            try {
                mediaPlayer?.stop()
                mediaPlayer?.release()
                mediaPlayer = null
                Log.d(TAG, "Native alarm stopped")
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping alarm: ${e.message}")
            }
        }
    }

    override fun onMessageReceived(message: RemoteMessage) {
        super.onMessageReceived(message)

        val type = message.data["type"]
        if (type != "hitl_alert") return

        val holdRef = message.data["hold_ref"] ?: "unknown"
        Log.d(TAG, "HITL alert received: hold_ref=$holdRef")

        // 1. Acquire wake lock to turn screen on
        wakeScreen()

        // 2. Start looping alarm sound at max volume
        startAlarm()

        // 3. Show high-priority notification with full-screen intent
        showAlarmNotification(holdRef)
    }

    private fun wakeScreen() {
        try {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            @Suppress("DEPRECATION")
            val wakeLock = pm.newWakeLock(
                PowerManager.FULL_WAKE_LOCK or
                PowerManager.ACQUIRE_CAUSES_WAKEUP or
                PowerManager.ON_AFTER_RELEASE,
                "cicada:hitl_wake"
            )
            wakeLock.acquire(60_000L) // 60 seconds — enough for the operator to respond
            Log.d(TAG, "Wake lock acquired — screen should turn on")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to acquire wake lock: ${e.message}")
        }
    }

    private fun startAlarm() {
        try {
            // Stop any existing alarm first
            stopAlarm()

            val sirenUri = Uri.parse("android.resource://$packageName/raw/siren")
            mediaPlayer = MediaPlayer().apply {
                setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_ALARM)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                        .build()
                )
                setDataSource(applicationContext, sirenUri)
                isLooping = true
                prepare()

                // Force max volume on the alarm stream
                val audioManager = getSystemService(Context.AUDIO_SERVICE) as AudioManager
                val maxVol = audioManager.getStreamMaxVolume(AudioManager.STREAM_ALARM)
                audioManager.setStreamVolume(AudioManager.STREAM_ALARM, maxVol, 0)

                start()
            }
            Log.d(TAG, "Native alarm started — looping at max volume")

            // Safety timeout: stop alarm after 60 seconds if not dismissed
            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                stopAlarm()
            }, 60_000L)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start alarm: ${e.message}")
        }
    }

    private fun showAlarmNotification(holdRef: String) {
        val notificationManager =
            getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // Create/update the notification channel (required for Android 8+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // Don't set sound on channel — we use MediaPlayer instead
            val channel = NotificationChannel(
                CHANNEL_ID, CHANNEL_NAME, NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Critical AI agent decision requests"
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 500, 200, 500, 200, 500)
                // No sound — MediaPlayer handles the alarm audio
                setSound(null, null)
                lockscreenVisibility = NotificationCompat.VISIBILITY_PUBLIC
                setBypassDnd(true)
            }
            notificationManager.createNotificationChannel(channel)
        }

        // Intent to launch the app when notification is tapped
        val launchIntent = Intent(applicationContext, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("hold_ref", holdRef)
            putExtra("from_notification", true)
        }

        val pendingIntent = PendingIntent.getActivity(
            applicationContext, holdRef.hashCode(), launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // Full-screen intent — opens app directly on lock screen
        val fullScreenPendingIntent = PendingIntent.getActivity(
            applicationContext, holdRef.hashCode() + 1, launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(applicationContext, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("\uD83D\uDEA8 HITL Decision Required")
            .setContentText("An AI agent action requires your immediate approval.")
            .setStyle(NotificationCompat.BigTextStyle()
                .bigText("An AI agent action requires your immediate approval. " +
                         "Tap to review and respond within the 120-second window."))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setVibrate(longArrayOf(0, 500, 200, 500, 200, 500))
            .setFullScreenIntent(fullScreenPendingIntent, true)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setOngoing(true)
            .setColorized(true)
            .setColor(0xFFFF0000.toInt())
            // Delete intent — stop alarm when notification is swiped away
            .setDeleteIntent(createStopAlarmIntent())
            .build()

        notificationManager.notify(holdRef.hashCode(), notification)
        Log.d(TAG, "Alarm notification posted for hold_ref=$holdRef")
    }

    private fun createStopAlarmIntent(): PendingIntent {
        val intent = Intent(applicationContext, AlarmStopReceiver::class.java)
        return PendingIntent.getBroadcast(
            applicationContext, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    override fun onNewToken(token: String) {
        super.onNewToken(token)
        Log.d(TAG, "FCM token refreshed: ${token.take(8)}...${token.takeLast(8)}")
    }
}
