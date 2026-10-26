import 'dart:async';
import 'package:collection/collection.dart';
import 'package:msgp2p_core/msgp2p_core.dart';

/// A scheduled simulation event.
class SimEvent {
  final int id;
  final int timeMs;
  final int priority;
  final Future<void> Function() action;
  final String description;

  SimEvent({
    required this.id,
    required this.timeMs,
    required this.priority,
    required this.action,
    required this.description,
  });
}

/// Virtual clock maintaining simulation time, implementing msgp2p_core [Clock].
class SimClock implements Clock {
  int _currentTimeMs = 0;

  SimClock([int initialTimeMs = 0]) : _currentTimeMs = initialTimeMs;

  int get currentTimeMs => _currentTimeMs;

  @override
  DateTime now() => DateTime.fromMillisecondsSinceEpoch(_currentTimeMs);

  void setTime(int timeMs) {
    _currentTimeMs = timeMs;
  }

  void advance(int deltaMs) {
    _currentTimeMs += deltaMs;
  }
}

/// Deterministic event queue for discrete-event simulation (FR-TEST-02).
class EventQueue {
  final SimClock clock;
  int _eventIdCounter = 0;

  final PriorityQueue<SimEvent> _queue = PriorityQueue<SimEvent>((a, b) {
    final cmpTime = a.timeMs.compareTo(b.timeMs);
    if (cmpTime != 0) return cmpTime;
    final cmpPrio = a.priority.compareTo(b.priority);
    if (cmpPrio != 0) return cmpPrio;
    return a.id.compareTo(b.id);
  });

  EventQueue({SimClock? clock}) : clock = clock ?? SimClock();

  bool get isEmpty => _queue.isEmpty;
  bool get isNotEmpty => _queue.isNotEmpty;
  int get length => _queue.length;

  /// Schedules an action at virtual time [timeMs].
  void schedule(
    int timeMs,
    Future<void> Function() action, {
    int priority = 0,
    String description = '',
  }) {
    if (timeMs < clock.currentTimeMs) {
      throw ArgumentError(
          'Cannot schedule event in the past (now=${clock.currentTimeMs}, scheduled=$timeMs)');
    }
    _eventIdCounter++;
    final event = SimEvent(
      id: _eventIdCounter,
      timeMs: timeMs,
      priority: priority,
      action: action,
      description: description,
    );
    _queue.add(event);
  }

  /// Runs simulation until the event queue is empty or virtual time reaches [maxTimeMs].
  Future<int> runUntil(int maxTimeMs) async {
    var executedCount = 0;
    while (_queue.isNotEmpty) {
      final next = _queue.first;
      if (next.timeMs > maxTimeMs) {
        break;
      }

      _queue.removeFirst();
      clock.setTime(next.timeMs);
      await next.action();
      executedCount++;
    }

    if (clock.currentTimeMs < maxTimeMs) {
      clock.setTime(maxTimeMs);
    }

    return executedCount;
  }

  /// Clears all pending events.
  void clear() {
    _queue.clear();
  }
}
