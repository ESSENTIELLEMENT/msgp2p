package org.msgp2p.flutter

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/**
 * Android 12+/13+/14+ Foreground Service with type `connectedDevice` (architecture.md §5.2).
 * Keeps BLE Extended Advertising, Coded PHY scanning, and L2CAP CoC sockets active
 * while hikers or field teams carry devices in pockets off-grid.
 */
class Msgp2pForegroundService : Service() {

    companion object {
        const val CHANNEL_ID = "msgp2p_ble_relay_channel"
        const val NOTIFICATION_ID = 4201
        const val EXTRA_TITLE = "title"
        const val EXTRA_CONTENT = "content"
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val title = intent?.getStringExtra(EXTRA_TITLE) ?: "msgp2p Off-Grid Sync Active"
        val content = intent?.getStringExtra(EXTRA_CONTENT) ?: "Relaying group messages over Bluetooth LE"

        createNotificationChannel()
        val notification = buildNotification(title, content)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val channel = NotificationChannel(
                CHANNEL_ID,
                "msgp2p Mesh Relay",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Background Bluetooth LE store-carry-forward relay"
            }
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(title: String, content: String): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle(title)
            .setContentText(content)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(true)
            .build()
    }
}
