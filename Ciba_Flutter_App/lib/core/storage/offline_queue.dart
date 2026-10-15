// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import 'package:sqflite/sqflite.dart';
import 'package:path_provider/path_provider.dart';

/// SQLite-backed offline decision queue.
///
/// Phase 3 spec: When the device is offline, signed decisions are queued
/// locally and batch-synced when connectivity returns.
class OfflineQueue {
  Database? _db;

  Future<void> init() async {
    final dir = await getApplicationDocumentsDirectory();
    final dbPath = '${dir.path}/aegis_offline.db';
    _db = await openDatabase(
      dbPath,
      version: 1,
      onCreate: (db, version) async {
        await db.execute('''
          CREATE TABLE offline_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hold_ref TEXT NOT NULL,
            decision TEXT NOT NULL,
            decision_nonce TEXT NOT NULL,
            gateway_timestamp TEXT NOT NULL,
            hold_payload_hash TEXT NOT NULL,
            signature_ed25519 TEXT NOT NULL,
            signature_ml_dsa65 TEXT,
            ed25519_pub TEXT NOT NULL,
            attestation_token TEXT,
            queued_at TEXT NOT NULL
          )
        ''');
      },
    );
  }

  /// Queue a signed decision for later batch sync.
  Future<void> enqueue(Map<String, dynamic> decision) async {
    if (_db == null) await init();
    await _db!.insert('offline_decisions', {
      ...decision,
      'queued_at': DateTime.now().toUtc().toIso8601String(),
    });
  }

  /// Retrieve all queued decisions for batch sync.
  Future<List<Map<String, dynamic>>> getAll() async {
    if (_db == null) await init();
    return _db!.query('offline_decisions', orderBy: 'queued_at ASC');
  }

  /// Clear all queued decisions after successful sync.
  Future<void> clearAll() async {
    if (_db == null) await init();
    await _db!.delete('offline_decisions');
  }

  /// Remove specific decisions by IDs after partial sync.
  Future<void> removeByIds(List<int> ids) async {
    if (_db == null) await init();
    final placeholders = ids.map((_) => '?').join(',');
    await _db!.delete(
      'offline_decisions',
      where: 'id IN ($placeholders)',
      whereArgs: ids,
    );
  }

  Future<int> get count async {
    if (_db == null) await init();
    final result = await _db!.rawQuery('SELECT COUNT(*) as c FROM offline_decisions');
    return Sqflite.firstIntValue(result) ?? 0;
  }
}
