/// Pure Dart core engine for the msgp2p delay-tolerant opportunistic mesh sync protocol.
library msgp2p_core;

export 'src/crypto/beacon_token.dart';
export 'src/crypto/crypto.dart';
export 'src/crypto/noise.dart';
export 'src/crypto/noise_handshake.dart';
export 'src/encoding/canonical_cbor.dart';
export 'src/framing/chunking.dart';
export 'src/framing/crc16.dart';
export 'src/framing/frame.dart';
export 'src/identity/identity_guard.dart';
export 'src/identity/key_vault.dart';
export 'src/model/certificate.dart';
export 'src/model/envelope.dart';
export 'src/model/receipt.dart';
export 'src/model/revocation.dart';
export 'src/model/version_vector.dart';
export 'src/storage/memory_message_store.dart';
export 'src/storage/message_store.dart';
export 'src/storage/sqlite_message_store.dart';
export 'src/sync/clock_rules.dart';
export 'src/sync/peer_cooldown_tracker.dart';
export 'src/sync/scan_scheduler.dart';
export 'src/transport/fake_transport.dart';
export 'src/transport/transport.dart';
export 'src/crypto/random_source.dart';

export 'src/sync/session_messages.dart';
export 'src/sync/session_state_machine.dart';

export 'src/harness/mesh_harness.dart';
export 'src/harness/scenario.dart';
export 'src/gateway/gateway_api.dart';
export 'src/gateway/io_http_executor.dart';
export 'src/gateway/gateway_client.dart';

export 'src/framing/broadcast_framing.dart';
export 'src/transport/broadcast_transport.dart';
export 'src/sync/broadcast_engine.dart';

export 'src/group/group_membership.dart';
export 'src/group/group_store_pool.dart';
export 'src/group/multi_group_beacon_manager.dart';
export 'src/group/multi_group_sync_coordinator.dart';
