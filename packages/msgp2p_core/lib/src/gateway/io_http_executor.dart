import 'dart:io';
import 'dart:typed_data';
import 'gateway_api.dart';

/// Default [HttpExecutor] using `dart:io` [HttpClient].
class IoHttpExecutor implements HttpExecutor {
  HttpClient? _client;
  final bool _closeClientOnDispose;

  /// Creates an [IoHttpExecutor].
  ///
  /// If [client] is omitted, an internal [HttpClient] is lazily created on first
  /// request and closed on [close]. If an external [client] is supplied,
  /// [closeClientOnDispose] defaults to `false` so shared host clients are not
  /// prematurely closed unless explicitly requested.
  IoHttpExecutor({
    Object? client,
    bool? closeClientOnDispose,
  })  : assert(client == null || client is HttpClient,
            'IoHttpExecutor client must be a dart:io HttpClient'),
        _client = client as HttpClient?,
        _closeClientOnDispose = closeClientOnDispose ?? (client == null);

  HttpClient get _httpClient => _client ??= HttpClient();

  @override
  Future<HttpReply> send(
    String method,
    Uri url, {
    Map<String, String>? headers,
    Uint8List? body,
  }) async {
    final request = await _httpClient.openUrl(method, url);
    try {
      headers?.forEach((name, value) {
        request.headers.set(name, value);
      });
      if (body != null && body.isNotEmpty) {
        request.add(body);
      }
    } catch (_) {
      request.abort();
      rethrow;
    }

    final response = await request.close();
    final bytesBuilder = BytesBuilder(copy: false);
    await for (final chunk in response) {
      bytesBuilder.add(chunk);
    }
    final responseBody = bytesBuilder.takeBytes();
    final responseHeaders = <String, String>{};
    response.headers.forEach((name, values) {
      responseHeaders[name.toLowerCase()] = values.join(', ');
    });

    return HttpReply(
      statusCode: response.statusCode,
      headers: responseHeaders,
      body: responseBody,
    );
  }

  /// Closes the underlying [HttpClient] if owned by this executor (or if
  /// `closeClientOnDispose` was set to `true`).
  void close({bool force = false}) {
    if (_closeClientOnDispose) {
      _client?.close(force: force);
    }
  }
}
