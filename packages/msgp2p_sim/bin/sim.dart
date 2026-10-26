import 'dart:io';
import 'package:args/args.dart';
import 'package:msgp2p_sim/msgp2p_sim.dart';

void main(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('scenario',
        abbr: 's', help: 'Path to scenario YAML file', mandatory: true)
    ..addOption('seed', help: 'Override random seed')
    ..addOption('trace', abbr: 't', help: 'Output path for JSONL trace events')
    ..addFlag('verbose',
        abbr: 'v', defaultsTo: false, help: 'Print verbose metrics output')
    ..addFlag('help',
        abbr: 'h', negatable: false, help: 'Show usage instructions');

  ArgResults results;
  try {
    results = parser.parse(arguments);
  } catch (e) {
    stderr.writeln('Error: $e\n');
    stderr.writeln(parser.usage);
    exit(1);
  }

  if (results['help'] == true) {
    print(
        'msgp2p_sim: Deterministic DTN Discrete-Event Simulator (FR-TEST-02)\n');
    print(parser.usage);
    exit(0);
  }

  final scenarioPath = results['scenario'] as String;
  final scenarioFile = File(scenarioPath);
  if (!scenarioFile.existsSync()) {
    stderr.writeln('Scenario file not found: $scenarioPath');
    exit(1);
  }

  final yamlContent = scenarioFile.readAsStringSync();
  var scenario = Scenario.fromYaml(yamlContent);

  if (results['seed'] != null) {
    final overrideSeed = int.tryParse(results['seed'] as String);
    if (overrideSeed != null) {
      scenario = Scenario(
        name: scenario.name,
        durationMs: scenario.durationMs,
        seed: overrideSeed,
        groupId: scenario.groupId,
        nodes: scenario.nodes,
        contacts: scenario.contacts,
        workload: scenario.workload,
        gateways: scenario.gateways,
        assertions: scenario.assertions,
      );
    }
  }

  print('=== msgp2p_sim: Running scenario "${scenario.name}" ===');
  print(
      'Nodes: ${scenario.nodes.length} | Contacts: ${scenario.contacts.length} | Workload: ${scenario.workload.length} messages');
  print('Duration: ${scenario.durationMs ~/ 1000}s | Seed: ${scenario.seed}');

  final simulator = Simulator(scenario: scenario);
  try {
    await simulator.initialize();
    final metrics = await simulator.run();

    print('\n=== Simulation Results ===');
    print(
        'Delivery ratio: ${(metrics.deliveryRatio * 100).toStringAsFixed(1)}%');
    print('Total bytes on air: ${metrics.totalBytesOnAir} B');
    print('Duplicates: ${metrics.duplicateEnvelopesReceived}');

    if (results['trace'] != null) {
      final tracePath = results['trace'] as String;
      final traceFile = File(tracePath);
      traceFile.writeAsStringSync(simulator.exportTraceJsonl());
      print('Trace written to: $tracePath');
    }

    if (results['verbose'] == true) {
      print('\nMetrics Detail:');
      print(metrics.toJsonString());
    }

    if (metrics.assertionFailures.isNotEmpty) {
      stderr.writeln(
          '\nFAILED: ${metrics.assertionFailures.length} scenario assertion(s) failed:');
      for (final f in metrics.assertionFailures) {
        stderr.writeln(' - $f');
      }
      exit(2);
    }

    print('\nAll scenario assertions PASSED.');
  } finally {
    await simulator.dispose();
  }
}
