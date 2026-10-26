import 'dart:io';
import '../packages/msgp2p_core/lib/msgp2p_core.dart';

/// Host orchestrator CLI that runs a unified Scenario YAML across attached Android
/// emulators (`netsimd` / Root-Canal) or in headless in-process verification mode,
/// collects structured JSONL traces, and validates scenario assertions (`FR-TEST-05`, `FR-TEST-08`).
Future<void> main(List<String> args) async {
  var scenarioPath = 'packages/msgp2p_sim/scenarios/trail_sync.yaml';
  var traceOutputPath = '';

  for (var i = 0; i < args.length; i++) {
    if (args[i] == '--scenario' && i + 1 < args.length) {
      scenarioPath = args[++i];
    } else if (args[i] == '--trace-out' && i + 1 < args.length) {
      traceOutputPath = args[++i];
    }
  }

  final file = File(scenarioPath);
  if (!file.existsSync()) {
    stderr.writeln('Error: Scenario file not found at $scenarioPath');
    exit(2);
  }

  final scenario = Scenario.fromYaml(file.readAsStringSync());
  stdout.writeln('=== msgp2p Host Scenario Orchestrator ===');
  stdout.writeln('Scenario : ${scenario.name}');
  stdout.writeln('Nodes    : ${scenario.nodes.map((n) => n.id).join(", ")}');
  stdout.writeln('Duration : ${scenario.durationMs ~/ 1000}s (seed: ${scenario.seed})');

  final harness = await MeshHarness.create(
    seed: scenario.seed,
    groupId: scenario.groupId,
  );

  try {
    final failures = await harness.runScenario(scenario);
    final traceJsonl = harness.exportTraceJsonl();
    final traceEvents = MeshHarness.parseTraceJsonl(traceJsonl);

    if (traceOutputPath.isNotEmpty) {
      File(traceOutputPath).writeAsStringSync('$traceJsonl\n');
      stdout.writeln('Wrote ${traceEvents.length} trace events to $traceOutputPath');
    } else {
      stdout.writeln('Collected ${traceEvents.length} structured JSONL trace events.');
    }

    if (failures.isNotEmpty) {
      stderr.writeln('Scenario FAILED with ${failures.length} assertion failure(s):');
      for (final f in failures) {
        stderr.writeln('  - $f');
      }
      exit(1);
    }

    stdout.writeln('ALL SCENARIO ASSERTIONS PASSED!');
  } finally {
    await harness.dispose();
  }
}
