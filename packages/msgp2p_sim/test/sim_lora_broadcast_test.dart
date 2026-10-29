import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:msgp2p_sim/msgp2p_sim.dart';
import 'package:test/test.dart';

void main() {
  group('LoRa 0-RTT Broadcast Mesh Simulation', () {
    late Uint8List serverSeed;
    late cg.SimpleKeyPair serverKeyPair;
    late Uint8List serverPublicKey;
    late Uint8List groupId;
    late Uint8List groupKey;

    late cg.SimpleKeyPair hikerKeyPair;
    late Uint8List hikerPk;
    late MembershipCert hikerCert;

    setUpAll(() async {
      serverSeed = Uint8List.fromList(List.filled(32, 9));
      serverKeyPair = await MsgP2PCrypto.newKeyPairFromSeed(serverSeed);
      serverPublicKey = await MsgP2PCrypto.getPublicKeyBytes(serverKeyPair);

      groupId =
          Uint8List.fromList(hex.decode('b0b1c2d3e4f50123456789abcdef0999'));
      groupKey = Uint8List.fromList(List.filled(32, 0x77));

      hikerKeyPair = await MsgP2PCrypto.newKeyPairFromSeed(
          Uint8List.fromList(List.filled(32, 2)));
      hikerPk = await MsgP2PCrypto.getPublicKeyBytes(hikerKeyPair);

      final now = DateTime.now().millisecondsSinceEpoch;
      final certCoreMap = {
        'v': 1,
        'group_id': groupId,
        'user_id': 'lost_hiker_node',
        'member_pubkey': hikerPk,
        'noise_pubkey': Uint8List(32),
        'role': 0,
        'issued_at': now,
        'expires_at': now + 86400000,
      };
      final coreCbor = CanonicalCbor.encode(certCoreMap);
      final sig = await MsgP2PCrypto.sign(coreCbor, serverKeyPair);
      hikerCert = MembershipCert(
        version: 1,
        groupId: groupId,
        userId: 'lost_hiker_node',
        memberPubkey: hikerPk,
        noisePubkey: Uint8List(32),
        role: 0,
        issuedAt: now,
        expiresAt: now + 86400000,
        serverSig: sig,
      );
    });

    test(
        '5-Node Mountain SAR: 0-RTT SOS broadcast propagates from ravine via ridge relay to base camp & search teams',
        () async {
      final medium = SimMedium();
      final clock = VirtualClock(DateTime(2026, 10, 27, 10, 0, 0));

      // 5 Nodes:
      // A = Hiker in ravine
      // B = Ridge Relay Drone
      // C = Base Camp Command
      // D = Field Search Team 1
      // E = Medical SAR Team 2
      final nodeAddresses = ['node_A', 'node_B', 'node_C', 'node_D', 'node_E'];
      final transports = <String, SimLoRaTransport>{};
      final stores = <String, MemoryMessageStore>{};
      final engines = <String, BroadcastEngine>{};

      for (final addr in nodeAddresses) {
        final transport = SimLoRaTransport(
          nodeAddress: addr,
          medium: medium,
          profile: LinkProfile.loraSf7,
        );
        transports[addr] = transport;
        medium.register(transport);

        final store = MemoryMessageStore();
        stores[addr] = store;

        final engine = BroadcastEngine(
          transport: transport,
          store: store,
          pinnedServerKey: serverPublicKey,
          expectedGroupId: groupId,
          groupKeysByEpoch: {1: groupKey},
          clock: clock,
          relayEnabled: addr == 'node_B', // Node B acts as the ridge repeater
        );
        engines[addr] = engine;
        engine.start();
      }

      // Topology:
      // A can only reach B (ridge drone)
      // B can reach A, C, D, E
      // C, D, E can reach B
      medium.setFullMesh(false);
      medium.setContact('node_A', 'node_B', true);
      medium.setContact('node_B', 'node_C', true);
      medium.setContact('node_B', 'node_D', true);
      medium.setContact('node_B', 'node_E', true);

      // Create an urgent SOS envelope authored by Hiker (Node A)
      final now = clock.now().millisecondsSinceEpoch;
      final sosEnvelope = await Envelope.create(
        groupId: groupId,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: hikerKeyPair,
        certRef: hikerCert.certRef,
        seq: 1,
        payload: {
          'type': 'sos',
          'priority': 'critical',
          'victim': 'Hiker Alpha',
          'coordinates': {'lat': 44.5218, 'lng': -121.7821},
          'elevation_m': 2140,
          'condition': 'Broken ankle, exposed to wind chill',
        },
        priority: 0,
        customCreatedAt: now,
      );

      // Node A broadcasts 0-RTT SOS with certificate attached
      await engines['node_A']!.broadcastEnvelope(
        sosEnvelope,
        cert: hikerCert,
        hopLimit: 2,
      );

      // Allow asynchronous relay propagation (Node A -> Node B -> Nodes C, D, E)
      await Future.delayed(const Duration(milliseconds: 300));

      // Verify 100% convergence across all recipient nodes (B, C, D, E)
      for (final recipient in ['node_B', 'node_C', 'node_D', 'node_E']) {
        final stored =
            await stores[recipient]!.getEnvelope(sosEnvelope.messageId);
        expect(stored, isNotNull,
            reason:
                'Node $recipient failed to receive and ingest SOS envelope');

        // Verify payload decryption
        final decrypted = await stored!.decryptPayload(groupKey);
        expect(decrypted['type'], equals('sos'));
        expect(decrypted['victim'], equals('Hiker Alpha'));
        expect(decrypted['coordinates']['lat'], equals(44.5218));
      }

      // Cleanup
      for (final engine in engines.values) {
        await engine.dispose();
      }
      for (final transport in transports.values) {
        await transport.dispose();
      }
    });
  });
}
