import 'package:bbs_chat_app/main.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('Reference BBS Chat App UI & Mesh Status Flow (FR-APP-01..04)', () {
    testWidgets(
        'Renders initial BBS post, creates new post, triggers SOS, and transitions Local -> Peer -> Server badges',
        (tester) async {
      final env = await BbsDemoEnvironment.createDefault();
      addTearDown(env.dispose);

      await tester.pumpWidget(BbsChatApp(environment: env));
      await tester.pumpAndSettle();

      // 1. Initial seeded BBS post is displayed with 'Local only' status badge
      expect(find.text('Bridge out at km 12'), findsOneWidget);
      expect(find.text('Local only'), findsOneWidget);

      // 2. Create a new BBS post via the dialog (FR-APP-01)
      await tester.tap(find.byKey(const Key('new_post_button')));
      await tester.pumpAndSettle();

      await tester.enterText(
          find.byKey(const Key('post_title_input')), 'Water cache at Camp 2');
      await tester.enterText(find.byKey(const Key('post_body_input')),
          '12 liters stored under tarp.');
      await tester.tap(find.byKey(const Key('attach_photo_checkbox')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('submit_post_button')));
      await tester.pumpAndSettle();

      expect(find.text('Water cache at Camp 2'), findsOneWidget);
      expect(find.text('Blob (4096 B)'), findsOneWidget);
      expect(find.text('Local only'), findsNWidgets(2));

      // 3. Trigger 1-tap Emergency SOS alert (FR-APP-01)
      await tester.tap(find.byKey(const Key('sos_button')));
      await tester.pumpAndSettle();

      expect(find.text('PRIORITY 0 • SOS'), findsOneWidget);
      expect(
          find.text('SOS: Hiker Needs Immediate Assistance'), findsOneWidget);

      // 4. Sync with nearby BLE peer -> badges transition to 'Handed to peer' (FR-APP-02)
      await tester.tap(find.byKey(const Key('sync_peer_action')));
      await tester.pumpAndSettle();

      expect(find.text('Handed to peer'), findsNWidgets(3));
      expect(find.text('Local only'), findsNothing);

      // 5. Sync with gateway server -> badges transition to 'Server confirmed' (FR-APP-02)
      await tester.tap(find.byKey(const Key('sync_gateway_action')));
      await tester.pumpAndSettle();

      expect(find.text('Server confirmed'), findsNWidgets(3));
      expect(find.text('Handed to peer'), findsNothing);

      // 6. Navigate to Peer Radar tab and verify anonymized rotating token & PHY (FR-APP-03)
      await tester.tap(find.text('Peer Radar'));
      await tester.pumpAndSettle();

      expect(
          find.textContaining('Nearby Anonymized Mesh Peers'), findsOneWidget);
      expect(find.textContaining('Token:'), findsWidgets);

      // 7. Navigate to Onboarding tab and verify permission/battery checklist (FR-APP-04)
      await tester.tap(find.text('Onboarding'));
      await tester.pumpAndSettle();

      expect(find.text('Off-Grid Mesh Readiness Checklist'), findsOneWidget);
      expect(
          find.byKey(const Key('onboarding_ble_permissions')), findsOneWidget);
      expect(find.byKey(const Key('onboarding_battery_exemption')),
          findsOneWidget);
    });
  });
}
