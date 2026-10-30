import 'dart:io';
import 'dart:typed_data';
import 'gateway_api.dart';

/// Default [HttpExecutor] using `dart:io` [HttpClient].
class IoHttpExecutor implements HttpExecutor {
  final HttpClient _client;
  final bool _closeClientOnDispose;

  IoHttpExecutor({
    HttpClient? client,
    bool closeClientOnDispose = true,
  })  : _client = client ?? HttpClient(),
        _closeClientOnDispose = closeClientOnDispose;

  @override
  Future<HttpReply> send(
    String method,
    Uri url, {
    Map<String, String>? headers,
    Uint8List? body,
  }) async {
    final request = await _client.openUrl(method, url);
    headers?.forEach((name, value) {
      request.headers.set(name, value);
    });
    if (body != null && body.isNotEmpty) {
      request.add(body);
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

  /// Closes the underlying [HttpClient].
  void close({bool force = false}) {
    if (_closeClientOnDispose) {
      _client.close(force: force);
    }
  }
}
