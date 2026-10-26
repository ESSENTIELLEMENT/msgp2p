import 'dart:io';
import 'package:msgp2p_sim/msgp2p_sim.dart';
import 'package:test/test.dart';

void main() {
  group('Phase 5 Field Trial Simulation (8-Phone Mixed Android/iOS Mesh, v1.0)',
      () {
    test(
        'Runs field_trial_8_nodes.yaml with calibrated forest/open link profiles to 100% convergence',
        () async {
      final profilesYaml = File('link_profiles.yaml').readAsStringSync();
      final profiles = LinkProfile.parseYaml(profilesYaml);
      expect(
        profiles.keys,
        containsAll([
          'ble_1m',
          'ble_1m_forest',
          'ble_coded_s8',
          'ble_coded_s8_forest',
          'ios_ble',
          'wifi_aware',
        ]),
      );

      final scenarioYaml =
          File('scenarios/field_trial_8_nodes.yaml').readAsStringSync();
      final scenario = Scenario.fromYaml(scenarioYaml);
      expect(scenario.nodes.length, equals(8));

      final sim = Simulator(scenario: scenario, customProfiles: profiles);
      await sim.initialize();
      final metrics = await sim.run();

      expect(metrics.assertionFailures, isEmpty);
      expect(metrics.deliveryRatio, equals(1.0));
      expect(metrics.duplicateEnvelopesReceived, equals(0));
      expect(metrics.wifiAwareUpgrades, greaterThanOrEqualTo(4));
      expect(metrics.attachmentsTransferred, greaterThanOrEqualTo(4));
      expect(sim.server.issuedReceipts, isNotEmpty);

      await sim.dispose();
    });
  });
}
