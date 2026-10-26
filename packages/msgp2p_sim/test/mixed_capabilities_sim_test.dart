import 'dart:io';
import 'package:msgp2p_sim/msgp2p_sim.dart';
import 'package:test/test.dart';

void main() {
  group('Mixed Android/iOS Capabilities & Wi-Fi Aware Upgrade Simulator (v0.2)',
      () {
    test(
        'Runs mixed_android_ios_upgrade.yaml: Coded PHY relay + BLE -> Wi-Fi Aware attachment upgrade',
        () async {
      final yamlStr =
          File('scenarios/mixed_android_ios_upgrade.yaml').readAsStringSync();
      final scenario = Scenario.fromYaml(yamlStr);

      expect(scenario.nodes.length, equals(3));
      final iosNode = scenario.nodes.firstWhere((n) => n.id == 'ios_basecamp');
      expect(iosNode.platform, equals('ios'));
      expect(iosNode.supportsCodedPhy, isFalse);
      expect(iosNode.supportsWifiAware, isTrue);

      final sim = Simulator(scenario: scenario);
      await sim.initialize();
      final metrics = await sim.run();
      await sim.dispose();

      expect(metrics.assertionFailures, isEmpty);
      expect(metrics.deliveryRatio, equals(1.0));
      // Two BLE contacts (android_scout <-> android_mule and android_mule <-> ios_basecamp)
      // automatically upgraded to Wi-Fi Aware to transfer the 8 KB photo attachment
      expect(metrics.wifiAwareUpgrades, greaterThanOrEqualTo(2));
      expect(metrics.attachmentsTransferred, greaterThanOrEqualTo(2));
    });
  });
}
