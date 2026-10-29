import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:flutter/material.dart';
import 'package:msgp2p_flutter/msgp2p_flutter.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final controller = await BbsDemoEnvironment.createDefault();
  runApp(BbsChatApp(environment: controller));
}

/// Self-contained mesh environment holding the local user's [MsgP2PNode],
/// a simulated nearby trail relay peer, and a simulated server signing key
/// so the reference app works interactively out-of-the-box and in widget tests.
class BbsDemoEnvironment {
  final MsgP2PNode localNode;
  final MsgP2PNode relayPeerNode;
  final cg.SimpleKeyPair serverKeyPair;
  final Uint8List serverPubkey;
  final Uint8List groupId;
  final LoopbackBleMedium bleMedium;

  BbsDemoEnvironment({
    required this.localNode,
    required this.relayPeerNode,
    required this.serverKeyPair,
    required this.serverPubkey,
    required this.groupId,
    required this.bleMedium,
  });

  static Future<BbsDemoEnvironment> createDefault() async {
    final groupId = Uint8List.fromList(List.generate(16, (i) => i + 1));
    final groupKey = Uint8List.fromList(List.generate(32, (i) => i + 0x20));
    final beaconKey = Uint8List.fromList(List.filled(32, 0x77));

    final serverKeyPair = await MsgP2PCrypto.newKeyPairFromSeed(
      Uint8List.fromList(List.filled(32, 0x09)),
    );
    final serverPubkey = await MsgP2PCrypto.getPublicKeyBytes(serverKeyPair);
    final bleMedium = LoopbackBleMedium();
    final awareMedium = LoopbackWifiAwareMedium();

    Future<MsgP2PNode> buildNode(String address, int seedByte) async {
      final signSeed = Uint8List.fromList(List.filled(32, seedByte));
      final noiseSeed = Uint8List.fromList(List.filled(32, seedByte + 40));

      final signKp = await MsgP2PCrypto.newKeyPairFromSeed(signSeed);
      final memberPk = await MsgP2PCrypto.getPublicKeyBytes(signKp);
      final noiseKp = await cg.X25519().newKeyPairFromSeed(noiseSeed);
      final noisePk = await NoiseHandshake.getPublicKeyBytes(noiseKp);

      final now = DateTime.now().millisecondsSinceEpoch;
      final certCore = MembershipCert(
        groupId: groupId,
        userId: address,
        memberPubkey: memberPk,
        noisePubkey: noisePk,
        role: 0,
        issuedAt: now - 60000,
        expiresAt: now + 7 * 86400000,
        serverSig: Uint8List(0),
      );
      final sig = await MsgP2PCrypto.sign(certCore.toCoreCbor(), serverKeyPair);
      final cert = MembershipCert(
        groupId: groupId,
        userId: address,
        memberPubkey: memberPk,
        noisePubkey: noisePk,
        role: 0,
        issuedAt: certCore.issuedAt,
        expiresAt: certCore.expiresAt,
        serverSig: sig,
      );

      final bridge = bleMedium.createBridge(address);
      final transport = AndroidBleTransport(bridge: bridge);
      final awareBridge = awareMedium.createBridge('NAN-$address');
      final awareTransport = WifiAwareTransport(bridge: awareBridge);

      return MsgP2PNode.initialize(
        config: MsgP2PConfig(
          serverEndpoint: Uri.parse('http://localhost:8000/api/v1'),
          serverPublicKey: serverPubkey,
          groupId: groupId,
        ),
        transport: transport,
        wifiAwareTransport: awareTransport,
        keyVault: MemoryKeyVault.fromSeeds(
            IdentitySeeds(signing: signSeed, noise: noiseSeed)),
        initialCert: cert,
        initialGroupKeys: {1: groupKey},
        initialBeaconKey: beaconKey,
      );
    }

    final localNode = await buildNode('AA:BB:CC:11:22:01', 10);
    final relayPeerNode = await buildNode('AA:BB:CC:11:22:02', 20);

    await relayPeerNode.startMeshRadio();
    await localNode.startMeshRadio();

    // Seed an initial bulletin post from the local node
    await localNode.publish(
      type: 'bbs_post',
      body: {
        'topic': 'Trail Status',
        'title': 'Bridge out at km 12',
        'text': 'Use the north ridge detour near Creek Camp.',
        'lat': 35.3606,
        'lng': 138.7274,
      },
      priority: Priority.normal,
    );

    return BbsDemoEnvironment(
      localNode: localNode,
      relayPeerNode: relayPeerNode,
      serverKeyPair: serverKeyPair,
      serverPubkey: serverPubkey,
      groupId: groupId,
      bleMedium: bleMedium,
    );
  }

  /// Triggers a BLE P2P sync between the local node and the nearby trail relay node.
  Future<void> syncWithNearbyPeer() async {
    await localNode.syncDirectlyWithNode(
      relayPeerNode,
      peerAddress: 'AA:BB:CC:11:22:02',
      runTransportSession: false,
    );
  }

  /// Simulates gateway server confirmation by issuing a signed [ServerReceipt] for all held messages.
  Future<void> confirmAllWithGatewayReceipt() async {
    final msgs = await localNode.getDecryptedMessages();
    if (msgs.isEmpty) return;

    final maxSeq = msgs.map((m) => m.seq).reduce((a, b) => a > b ? a : b);
    final now = DateTime.now().millisecondsSinceEpoch;
    final core = ServerReceipt(
      groupId: groupId,
      author: localNode.memberPubkey,
      ranges: [SeqRange(1, maxSeq)],
      issuedAt: now,
      serverSig: Uint8List(0),
    );
    final sig = await MsgP2PCrypto.sign(core.toCoreCbor(), serverKeyPair);
    final signed = ServerReceipt(
      groupId: groupId,
      author: localNode.memberPubkey,
      ranges: [SeqRange(1, maxSeq)],
      issuedAt: now,
      serverSig: sig,
    );
    await localNode.applyServerReceipt(signed);
  }

  Future<void> dispose() async {
    await localNode.dispose();
    await relayPeerNode.dispose();
  }
}

class BbsChatApp extends StatelessWidget {
  final BbsDemoEnvironment environment;

  const BbsChatApp({super.key, required this.environment});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'msgp2p Off-Grid BBS',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF1B5E20)),
        useMaterial3: true,
      ),
      home: BbsHomeScreen(environment: environment),
    );
  }
}

class BbsHomeScreen extends StatefulWidget {
  final BbsDemoEnvironment environment;

  const BbsHomeScreen({super.key, required this.environment});

  @override
  State<BbsHomeScreen> createState() => _BbsHomeScreenState();
}

class _BbsHomeScreenState extends State<BbsHomeScreen> {
  int _selectedIndex = 0;
  List<DecryptedMessage> _messages = [];
  List<DiscoveredPeerInfo> _peers = [];

  bool _blePermissionsGranted = true;
  bool _batteryExemptionEnabled = true;
  bool _foregroundServiceActive = true;

  @override
  void initState() {
    super.initState();
    _refreshState();
    widget.environment.localNode.messagesStream.listen((msgs) {
      if (mounted) {
        setState(() => _messages = msgs);
      }
    });
    widget.environment.localNode.peersStream.listen((peers) {
      if (mounted) {
        setState(() => _peers = peers);
      }
    });
  }

  Future<void> _refreshState() async {
    final msgs = await widget.environment.localNode.getDecryptedMessages();
    final peers = widget.environment.localNode.currentPeers;
    if (mounted) {
      setState(() {
        _messages = msgs;
        _peers = peers;
      });
    }
  }

  Future<void> _publishSosAlert() async {
    await widget.environment.localNode.publish(
      type: 'sos',
      body: {
        'topic': 'EMERGENCY SOS',
        'title': 'SOS: Hiker Needs Immediate Assistance',
        'text': 'Sprained ankle below North Summit ridge shelter.',
        'lat': 35.3629,
        'lng': 138.7311,
      },
      priority: Priority.sos,
    );
    await _refreshState();
  }

  Future<void> _showNewPostDialog() async {
    final titleCtrl = TextEditingController();
    final textCtrl = TextEditingController();
    final topicCtrl = TextEditingController(text: 'Trail Conditions');
    var attachLocation = true;
    var attachPhoto = false;

    final submitted = await showDialog<bool>(
      context: context,
      builder: (ctx) {
        return StatefulBuilder(
          builder: (ctx, setDialogState) {
            return AlertDialog(
              title: const Text('New BBS Post'),
              content: SingleChildScrollView(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    TextField(
                      key: const Key('post_topic_input'),
                      controller: topicCtrl,
                      decoration:
                          const InputDecoration(labelText: 'Topic / Thread'),
                    ),
                    const SizedBox(height: 8),
                    TextField(
                      key: const Key('post_title_input'),
                      controller: titleCtrl,
                      decoration: const InputDecoration(labelText: 'Title'),
                    ),
                    const SizedBox(height: 8),
                    TextField(
                      key: const Key('post_body_input'),
                      controller: textCtrl,
                      maxLines: 3,
                      decoration:
                          const InputDecoration(labelText: 'Message Body'),
                    ),
                    const SizedBox(height: 8),
                    CheckboxListTile(
                      contentPadding: EdgeInsets.zero,
                      title:
                          const Text('Attach GNSS Coordinates (35.36, 138.72)'),
                      value: attachLocation,
                      onChanged: (v) =>
                          setDialogState(() => attachLocation = v ?? true),
                    ),
                    CheckboxListTile(
                      key: const Key('attach_photo_checkbox'),
                      contentPadding: EdgeInsets.zero,
                      title:
                          const Text('Attach Trail Photo (Wi-Fi Aware Bulk)'),
                      value: attachPhoto,
                      onChanged: (v) =>
                          setDialogState(() => attachPhoto = v ?? false),
                    ),
                  ],
                ),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(ctx).pop(false),
                  child: const Text('Cancel'),
                ),
                FilledButton(
                  key: const Key('submit_post_button'),
                  onPressed: () => Navigator.of(ctx).pop(true),
                  child: const Text('Publish'),
                ),
              ],
            );
          },
        );
      },
    );

    if (submitted == true && titleCtrl.text.trim().isNotEmpty) {
      await widget.environment.localNode.publish(
        type: 'bbs_post',
        body: {
          'topic': topicCtrl.text.trim(),
          'title': titleCtrl.text.trim(),
          'text': textCtrl.text.trim(),
          if (attachLocation) 'lat': 35.3606,
          if (attachLocation) 'lng': 138.7274,
        },
        attachments: attachPhoto
            ? [
                (
                  bytes: Uint8List.fromList(
                      List.generate(4096, (i) => (i * 17) & 0xFF)),
                  mime: 'image/jpeg',
                ),
              ]
            : null,
        priority: Priority.normal,
      );
      await _refreshState();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(
            'msgp2p BBS • Node ${widget.environment.localNode.memberShortId}'),
        actions: [
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 4),
            child: FilledButton.tonalIcon(
              key: const Key('sync_peer_action'),
              onPressed: () async {
                await widget.environment.syncWithNearbyPeer();
                await _refreshState();
              },
              icon: const Icon(Icons.bluetooth_connected, size: 18),
              label: const Text('Sync Peer'),
            ),
          ),
          Padding(
            padding: const EdgeInsets.only(right: 8),
            child: FilledButton.tonalIcon(
              key: const Key('sync_gateway_action'),
              onPressed: () async {
                await widget.environment.confirmAllWithGatewayReceipt();
                await _refreshState();
              },
              icon: const Icon(Icons.cloud_done, size: 18),
              label: const Text('Gateway Sync'),
            ),
          ),
        ],
      ),
      body: IndexedStack(
        index: _selectedIndex,
        children: [
          _buildBoardTab(),
          _buildPeerRadarTab(),
          _buildOnboardingTab(),
        ],
      ),
      floatingActionButton: _selectedIndex == 0
          ? Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                FloatingActionButton.extended(
                  key: const Key('sos_button'),
                  heroTag: 'sos_fab',
                  backgroundColor: Colors.red.shade700,
                  foregroundColor: Colors.white,
                  onPressed: _publishSosAlert,
                  icon: const Icon(Icons.sos),
                  label: const Text('SOS Alert'),
                ),
                const SizedBox(width: 12),
                FloatingActionButton.extended(
                  key: const Key('new_post_button'),
                  heroTag: 'post_fab',
                  onPressed: _showNewPostDialog,
                  icon: const Icon(Icons.edit_note),
                  label: const Text('New Post'),
                ),
              ],
            )
          : null,
      bottomNavigationBar: NavigationBar(
        selectedIndex: _selectedIndex,
        onDestinationSelected: (idx) => setState(() => _selectedIndex = idx),
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.forum_outlined),
            selectedIcon: Icon(Icons.forum),
            label: 'BBS Board',
          ),
          NavigationDestination(
            icon: Icon(Icons.radar_outlined),
            selectedIcon: Icon(Icons.radar),
            label: 'Peer Radar',
          ),
          NavigationDestination(
            icon: Icon(Icons.shield_outlined),
            selectedIcon: Icon(Icons.shield),
            label: 'Onboarding',
          ),
        ],
      ),
    );
  }

  /// Tab 1: BBS Board with topic threads, location coordinates, SOS highlight, and status badges (`FR-APP-01..02`).
  Widget _buildBoardTab() {
    if (_messages.isEmpty) {
      return const Center(child: Text('No group messages yet.'));
    }

    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(12, 12, 12, 88),
      itemCount: _messages.length,
      itemBuilder: (context, index) {
        final msg = _messages[index];
        final title = msg.body['title']?.toString() ?? 'Untitled';
        final topic = msg.body['topic']?.toString() ?? 'General';
        final text = msg.body['text']?.toString() ?? '';
        final hasLocation =
            msg.body.containsKey('lat') && msg.body.containsKey('lng');

        return Card(
          key: Key('message_card_${msg.seq}'),
          color: msg.isSos ? Colors.red.shade50 : null,
          margin: const EdgeInsets.only(bottom: 10),
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    if (msg.isSos)
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 8, vertical: 2),
                        margin: const EdgeInsets.only(right: 8),
                        decoration: BoxDecoration(
                          color: Colors.red.shade700,
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: const Text(
                          'PRIORITY 0 • SOS',
                          style: TextStyle(
                              color: Colors.white,
                              fontWeight: FontWeight.bold,
                              fontSize: 11),
                        ),
                      ),
                    Chip(
                      label: Text(topic, style: const TextStyle(fontSize: 11)),
                      visualDensity: VisualDensity.compact,
                    ),
                    const Spacer(),
                    _buildStatusBadge(msg.status),
                  ],
                ),
                const SizedBox(height: 6),
                Text(
                  title,
                  style: Theme.of(context).textTheme.titleMedium?.copyWith(
                        fontWeight: FontWeight.bold,
                        color: msg.isSos ? Colors.red.shade900 : null,
                      ),
                ),
                if (text.isNotEmpty) ...[
                  const SizedBox(height: 4),
                  Text(text),
                ],
                const SizedBox(height: 8),
                Row(
                  children: [
                    Icon(Icons.person_outline,
                        size: 14, color: Colors.grey.shade700),
                    const SizedBox(width: 4),
                    Text(
                      'Author ${msg.authorShortId} • #${msg.seq}',
                      style:
                          TextStyle(fontSize: 12, color: Colors.grey.shade700),
                    ),
                    if (hasLocation) ...[
                      const SizedBox(width: 12),
                      Icon(Icons.location_on_outlined,
                          size: 14, color: Colors.green.shade800),
                      const SizedBox(width: 2),
                      Text(
                        '${msg.body['lat']}, ${msg.body['lng']}',
                        style: TextStyle(
                            fontSize: 12, color: Colors.green.shade800),
                      ),
                    ],
                    if (msg.attachments.isNotEmpty) ...[
                      const SizedBox(width: 12),
                      Icon(Icons.attachment,
                          size: 14, color: Colors.indigo.shade700),
                      const SizedBox(width: 2),
                      Text(
                        'Blob (${msg.attachments.first.size} B)',
                        style: TextStyle(
                            fontSize: 12, color: Colors.indigo.shade700),
                      ),
                    ],
                  ],
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildStatusBadge(MessageDeliveryStatus status) {
    final (Color bg, Color fg, IconData icon) = switch (status) {
      MessageDeliveryStatus.localOnly => (
          Colors.amber.shade100,
          Colors.amber.shade900,
          Icons.smartphone
        ),
      MessageDeliveryStatus.handedToPeer => (
          Colors.blue.shade100,
          Colors.blue.shade900,
          Icons.bluetooth_searching
        ),
      MessageDeliveryStatus.serverConfirmed => (
          Colors.green.shade100,
          Colors.green.shade900,
          Icons.verified
        ),
    };

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 14, color: fg),
          const SizedBox(width: 4),
          Text(
            status.label,
            style:
                TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: fg),
          ),
        ],
      ),
    );
  }

  /// Tab 2: Peer Diagnostic Radar (`FR-APP-03`).
  Widget _buildPeerRadarTab() {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: ListTile(
            leading: const Icon(Icons.sensors, color: Colors.green),
            title: const Text('BLE Rotating Beacon Radar Active'),
            subtitle:
                const Text('Scanning Coded PHY (S=8 Long Range) + 1M/2M PHY'),
            trailing: FilledButton(
              key: const Key('radar_sync_button'),
              onPressed: () async {
                await widget.environment.syncWithNearbyPeer();
                await _refreshState();
              },
              child: const Text('Sync Now'),
            ),
          ),
        ),
        const SizedBox(height: 12),
        Text(
          'Nearby Anonymized Mesh Peers (${_peers.length})',
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 8),
        if (_peers.isEmpty)
          const Card(
            child: Padding(
              padding: EdgeInsets.all(16),
              child: Text('No peers discovered yet.'),
            ),
          )
        else
          ..._peers.map((peer) {
            return Card(
              key: Key('peer_tile_${peer.address}'),
              child: ListTile(
                leading: const CircleAvatar(child: Icon(Icons.bluetooth)),
                title: Text('Token: ${peer.rotatingTokenHex}...'),
                subtitle: Text(
                  'PHY: ${peer.activePhy} • RSSI: ${peer.rssi} dBm\n'
                  'Last Sync: ${peer.lastSyncedAt != null ? "Synced" : "Pending encounter"}',
                ),
                isThreeLine: true,
              ),
            );
          }),
      ],
    );
  }

  /// Tab 3: Android Permissions & OEM Battery Exemption Onboarding (`FR-APP-04`).
  Widget _buildOnboardingTab() {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Text(
          'Off-Grid Mesh Readiness Checklist',
          style: Theme.of(context).textTheme.titleLarge,
        ),
        const SizedBox(height: 8),
        const Text(
          'Continuous store-carry-forward relay in mountain and disaster zones requires '
          'Android Nearby Devices permissions and unrestricted background battery execution.',
        ),
        const SizedBox(height: 16),
        Card(
          child: SwitchListTile(
            key: const Key('onboarding_ble_permissions'),
            title: const Text('Android 12+ Nearby Devices Permissions'),
            subtitle: const Text(
                'BLUETOOTH_SCAN, BLUETOOTH_ADVERTISE, BLUETOOTH_CONNECT'),
            value: _blePermissionsGranted,
            onChanged: (v) => setState(() => _blePermissionsGranted = v),
          ),
        ),
        const SizedBox(height: 8),
        Card(
          child: SwitchListTile(
            key: const Key('onboarding_foreground_service'),
            title: const Text('Foreground Service (connectedDevice)'),
            subtitle: const Text(
                'Keeps BLE Coded PHY scanner active while screen is locked'),
            value: _foregroundServiceActive,
            onChanged: (v) => setState(() => _foregroundServiceActive = v),
          ),
        ),
        const SizedBox(height: 8),
        Card(
          child: SwitchListTile(
            key: const Key('onboarding_battery_exemption'),
            title: const Text('OEM Battery Optimization Exemption'),
            subtitle: const Text(
                'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS enabled for 8h trail windows'),
            value: _batteryExemptionEnabled,
            onChanged: (v) => setState(() => _batteryExemptionEnabled = v),
          ),
        ),
      ],
    );
  }
}
