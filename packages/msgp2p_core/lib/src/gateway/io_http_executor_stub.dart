import 'dart:typed_data';
import 'gateway_api.dart';

/// Stub [IoHttpExecutor] used on platforms without `dart:io` (Web / Wasm).
///
/// Pass a custom [HttpExecutor] (for example backed by `package:http` or
/// browser `fetch`) to `GatewayClient` when targeting Web/Wasm.
class IoHttpExecutor implements HttpExecutor {
  IoHttpExecutor({
    Object? client,
    bool? closeClientOnDispose,
  });

  @override
  Future<HttpReply> send(
    String method,
    Uri url, {
    Map<String, String>? headers,
    Uint8List? body,
  }) {
    throw UnsupportedError(
      'IoHttpExecutor is only supported on platforms with dart:io. '
      'Pass a custom HttpExecutor to GatewayClient on Web/Wasm.',
    );
  }

  /// No-op on non-`dart:io` platforms.
  void close({bool force = false}) {}
}
