import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:pem/pem.dart';

// --- Exception Classes ---

/// The base class for all exceptions thrown by the http_security_pinning package.
abstract class CertificatePinningException implements Exception {
  /// A descriptive message explaining the error.
  final String message;

  /// Creates a new certificate pinning exception.
  CertificatePinningException(this.message);

  @override
  String toString() => 'CertificatePinningException: $message';
}

/// Thrown when fetching the certificate chain from the native platform fails.
///
/// This can happen due to network errors, timeouts, or if the native
/// code encounters an unexpected issue. The [message] property contains
/// more details from the native layer.
class CertificateFetchException extends CertificatePinningException {
  /// Creates a new certificate fetch exception.
  CertificateFetchException(String message)
      : super('Failed to fetch certificate chain. Reason: $message');
}

/// Thrown when the server's certificate chain is successfully fetched,
/// but none of the certificates' SPKI hashes match the pins provided to the client.
///
/// This is the primary exception that indicates a pinning validation failure.
class NoValidPinsFoundException extends CertificatePinningException {
  /// The host for which the pinning validation failed.
  final String host;

  /// Creates a new "no valid pins found" exception.
  NoValidPinsFoundException(this.host)
      : super('No valid SPKI pins found for host: $host');
}

// --- Internal Service Class ---

/// A private service class that handles the core logic of certificate pinning.
///
/// This includes fetching certificates from the native layer, validating them
/// against the provided pins, and creating a [SecurityContext].
class _HttpSecurityPinningService {
  static const String _tag = "HttpSecurityPinningClient";
  static const MethodChannel _channel = MethodChannel('http_security_pinning');

  /// A cache of host certificates to avoid re-fetching on every request.
  static const int _maxCacheSize = 50;
  static final Map<String, List<Uint8List>> _hostCertificates =
      <String, List<Uint8List>>{};

  /// Pre-decoded SPKI pins cache to avoid repeated base64 decoding.
  /// Uses a stable string key (sorted pin list) to prevent duplicate cache entries.
  static final Map<String, List<List<int>>> _decodedPinsCache =
      <String, List<List<int>>>{};

  /// Maps (host + pin set) to their client creation completers to prevent duplicate creation
  /// and ensure thread-safe future resolution.
  /// 
  /// Key format: "host:pin1,pin2,..." to scope coordination per unique (host, pins) pair.
  /// This prevents race conditions when concurrent requests to the same host use different pin sets.
  static final Map<String, Completer<HttpClient>> _clientCreationCompleters =
      <String, Completer<HttpClient>>{};

  /// Creates a stable completion key from host and pins to scope client creation coordination.
  /// 
  /// Ensures that two HttpSecurityPinningClient instances for the same host but different
  /// pin sets don't interfere with each other's delegate creation.
  static String _makeCompletionKey(String host, Set<String> pins) {
    final sortedPins = pins.toList()..sort();
    return '$host:${sortedPins.join(',')}';
  }

  /// Fetches the certificate chain for a given [url] from the native platform.
  ///
  /// Implements a retry mechanism based on [retryCount]. Each attempt respects
  /// the given [timeout].
  ///
  /// Throws a [CertificateFetchException] if all retry attempts fail.
  static Future<List<Uint8List>> _getHostCertificates(
    Uri url,
    Duration timeout,
    int retryCount,
  ) async {
    if (_hostCertificates[url.host] == null) {
      int attempts = 0;
      while (attempts <= retryCount) {
        try {
          final arguments = <String, dynamic>{
            'url': url.toString(),
            'timeout': timeout.inMilliseconds,
          };
          final List<Object?>? fetchedHostCertificates = await _channel
              .invokeMethod('fetchHostCertificates', arguments)
              .timeout(timeout +
                  const Duration(
                      seconds: 1)); // Add a grace period to the Dart timeout

          if (fetchedHostCertificates == null ||
              fetchedHostCertificates.isEmpty) {
            throw CertificateFetchException(
                'Native method returned no certificates.');
          }

          final certList = fetchedHostCertificates
              .whereType<Uint8List>()
              .toList(growable: true);
          
          // Enforce cache size limit (FIFO eviction)
          if (_hostCertificates.length >= _maxCacheSize) {
            _hostCertificates.remove(_hostCertificates.keys.first);
          }
          
          _hostCertificates[url.host] = certList;
          break; // Success, exit loop
        } on PlatformException catch (e) {
          attempts++;
          debugPrint(
              "$_tag: Failed to fetch certificates (attempt $attempts/${retryCount + 1}): ${e.message}");
          if (attempts > retryCount) {
            throw CertificateFetchException(
                e.message ?? 'Unknown platform error');
          }
        } on TimeoutException {
          attempts++;
          debugPrint(
              "$_tag: Failed to fetch certificates (attempt $attempts/${retryCount + 1}): Timeout");
          if (attempts > retryCount) {
            throw CertificateFetchException('Certificate fetch timed out.');
          }
        } catch (e) {
          attempts++;
          debugPrint(
              "$_tag: Failed to fetch certificates (attempt $attempts/${retryCount + 1}): $e");
          if (attempts > retryCount) {
            throw CertificateFetchException(e.toString());
          }
        }
      }
    }
    return _hostCertificates[url.host]!;
  }

  /// Filters the fetched certificate chain for a [url] against a set of [validPins].
  ///
  /// Throws a [NoValidPinsFoundException] if no certificates in the chain
  /// match the provided pins.
  static Future<List<Uint8List>> _hostPinCertificates(
    Uri url,
    Set<String> validPins,
    Duration timeout,
    int retryCount,
  ) async {
    final hostCertificates =
        await _HttpSecurityPinningService._getHostCertificates(
            url, timeout, retryCount);

    // Pre-decode and cache pins to avoid repeated base64 decoding
    // Use a stable string key to prevent duplicate cache entries
    final sortedPins = (validPins.toList()..sort());
    final pinKey = sortedPins.join(',');
    
    if (!_decodedPinsCache.containsKey(pinKey)) {
      try {
        // Pins are already validated in constructor, but re-decode for cache
        final decodedList = <List<int>>[];
        for (final pin in validPins) {
          decodedList.add(base64.decode(pin));
        }
        _decodedPinsCache[pinKey] = decodedList;
      } on FormatException catch (e) {
        throw CertificateFetchException(
            'Failed to decode SPKI pins: $e. Pins must be valid base64.');
      }
    }
    final decodedPins = _decodedPinsCache[pinKey]!;

    final info = StringBuffer("Certificate chain for $url: ");
    bool isFirst = true;
    final List<Uint8List> hostPinCerts = [];
    
    for (final cert in hostCertificates) {
      try {
        final Uint8List serverSpkiSha256Digest =
            Uint8List.fromList(_spkiSha256Digest(cert).bytes);
        if (!isFirst) info.write(", ");
        isFirst = false;
        info.write(base64.encode(serverSpkiSha256Digest));
        
        // Check if certificate matches any pin
        for (final pin in decodedPins) {
          if (_listEquals(pin, serverSpkiSha256Digest)) {
            hostPinCerts.add(cert);
            info.write(" pinned");
            break; // Certificate matched, no need to check other pins
          }
        }
      } on CertificateFetchException catch (e) {
        debugPrint(
            "$_tag: Failed to extract SPKI from certificate in chain: ${e.message}");
        // Continue with next certificate instead of failing entire chain
        continue;
      }
    }
    debugPrint("$_tag: $info");

    if (hostPinCerts.isEmpty) {
      throw NoValidPinsFoundException(url.host);
    }

    return hostPinCerts;
  }

  /// Creates a [SecurityContext] containing the trusted certificates that match
  /// the pinned hashes for the given [url].
  static Future<SecurityContext> _pinnedSecurityContext(
    Uri url,
    Set<String> validPins,
    Duration timeout,
    int retryCount,
  ) async {
    final List<Uint8List> pinCerts =
        await _HttpSecurityPinningService._hostPinCertificates(
            url, validPins, timeout, retryCount);

    final securityContext = SecurityContext();
    for (final pinCert in pinCerts) {
      final pemCertificate = PemCodec(PemLabel.certificate).encode(pinCert);
      final Uint8List pemCertificatesBytes =
          const AsciiEncoder().convert(pemCertificate);
      securityContext.setTrustedCertificatesBytes(pemCertificatesBytes);
    }
    debugPrint(
        "$_tag: Pinned security context with ${pinCerts.length} trusted certs, from ${validPins.length} possible pins");
    return securityContext;
  }

  /// Removes a [host] from the certificate cache.
  static Future<void> _removeCertificates(String host) async {
    _hostCertificates.remove(host);
  }

  /// Computes the SHA-256 digest of the Subject Public Key Info (SPKI)
  /// from a DER-encoded [certificate].
  ///
  /// Properly extracts SubjectPublicKeyInfo from X.509 certificate by:
  /// 1. Parsing the Certificate SEQUENCE
  /// 2. Extracting TBSCertificate (first element)
  /// 3. Locating SubjectPublicKeyInfo by finding the BIT STRING at index 6
  ///    (accounting for optional version field if present)
  /// 4. Computing SHA-256 of the DER-encoded SPKI
  static Digest _spkiSha256Digest(Uint8List certificate) {
    try {
      final asn1Parser = ASN1Parser(certificate);
      final signedCert = asn1Parser.nextObject();
      
      // Verify Certificate is a SEQUENCE
      if (signedCert is! ASN1Sequence) {
        throw CertificateFetchException(
            'Invalid certificate: root element is not a SEQUENCE');
      }
      
      if (signedCert.elements.isEmpty) {
        throw CertificateFetchException(
            'Invalid certificate: Certificate SEQUENCE is empty');
      }
      
      // Extract TBSCertificate (first element of Certificate)
      final cert = signedCert.elements[0];
      if (cert is! ASN1Sequence) {
        throw CertificateFetchException(
            'Invalid certificate: TBSCertificate is not a SEQUENCE');
      }
      
      if (cert.elements.length < 7) {
        throw CertificateFetchException(
            'Invalid certificate: TBSCertificate has insufficient fields');
      }
      
      // Find SubjectPublicKeyInfo (SEQUENCE) at position 6
      // Note: Position may vary if optional version field [0] is present,
      // but in standard X.509 v3 certs, it's at index 6
      ASN1Object? spkiElement = cert.elements[6];
      
      // If element at index 6 is not a SEQUENCE, it might be BIT STRING
      // (edge case for X.509 v1 certs or non-standard encodings)
      if (spkiElement is! ASN1Sequence) {
        // Fallback: search for SubjectPublicKeyInfo
        for (int i = cert.elements.length - 1; i >= 0; i--) {
          if (cert.elements[i] is ASN1Sequence &&
              i < cert.elements.length - 1) {
            // Check if next element exists
            if (i + 1 < cert.elements.length) {
              spkiElement = cert.elements[i];
              break;
            }
          }
        }
      }
      
      if (spkiElement is! ASN1Sequence) {
        throw CertificateFetchException(
            'Invalid certificate: could not find SubjectPublicKeyInfo SEQUENCE');
      }
      
      // Compute SHA-256 of DER-encoded SPKI
      // encodedBytes includes the SEQUENCE tag and length
      final spkiBytes = spkiElement.encodedBytes;
      final spkiDigest = sha256.convert(spkiBytes);
      
      return spkiDigest;
    } on CertificateFetchException {
      rethrow;
    } catch (e) {
      throw CertificateFetchException(
          'Failed to parse certificate ASN.1 structure: $e');
    }
  }

  /// A utility function to compare two lists of bytes.
  static bool _listEquals<E>(List<E>? list1, List<E>? list2) {
    if (identical(list1, list2)) return true;
    if (list1 == null || list2 == null) return false;
    final length = list1.length;
    if (length != list2.length) return false;
    for (var i = 0; i < length; i++) {
      if (list1[i] != list2[i]) return false;
    }
    return true;
  }
}

class _Credential {
  final Uri url;
  final String realm;
  final HttpClientCredentials credentials;

  _Credential(this.url, this.realm, this.credentials);
}

class _ProxyCredential {
  final String host;
  final int port;
  final String realm;
  final HttpClientCredentials credentials;

  _ProxyCredential(this.host, this.port, this.realm, this.credentials);
}

/// An implementation of Dart's [HttpClient] that enforces certificate pinning.
///
/// This client ensures that connections are only made to servers presenting
/// certificates with a Subject Public Key Info (SPKI) that matches one of the
/// provided [spkiHashes].
///
/// It works as a wrapper around a standard [HttpClient], intercepting connection
/// creation to inject a custom [SecurityContext] with the pinned certificates.
///
/// If the server's certificate chain does not match any of the provided pins,
/// the connection will fail, throwing a [NoValidPinsFoundException] before the
/// request is sent.
///
/// Example usage with `package:http`:
/// ```dart
/// final secureClient = IOClient(HttpSecurityPinningClient(
///   ["YOUR_SPKI_HASH_HERE"],
/// ));
/// final response = await secureClient.get(Uri.parse('https://example.com'));
/// ```
class HttpSecurityPinningClient implements HttpClient {
  /// Clears the static cache of fetched certificates.
  ///
  /// This is useful for testing purposes, for example to test timeout and retry logic.
  static void clearCache() {
    _HttpSecurityPinningService._hostCertificates.clear();
    _HttpSecurityPinningService._decodedPinsCache.clear();
    _HttpSecurityPinningService._clientCreationCompleters.clear();
  }

  static const String _tag = "HttpSecurityPinningClient";

  /// A set of trusted SHA-256 hashes of Subject Public Key Info (SPKI).
  final Set<String> _validPins;

  /// The timeout for fetching the certificate chain from the native platform.
  final Duration timeout;

  /// The number of times to retry fetching the certificate chain upon failure.
  final int retryCount;

  HttpClient _delegatePinnedHttpClient = HttpClient();

  String? _connectedHost;

  bool _isClosed = false;

  Future<bool> Function(Uri url, String scheme, String? realm)? _authenticate;
  Future<ConnectionTask<Socket>> Function(
      Uri url, String? proxyHost, int? proxyPort)? _connectionFactory;
  void Function(String line)? _keyLog;
  final List<_Credential> _credentials = [];
  String Function(Uri url)? _findProxy;
  Future<bool> Function(String host, int port, String scheme, String? realm)?
      _authenticateProxy;
  final List<_ProxyCredential> _proxyCredentials = [];
  bool Function(X509Certificate cert, String host, int port)?
      _badCertificateCallback;

  bool _pinningFailureCallback(X509Certificate cert, String host, int port) {
    final badCertificateCallback = _badCertificateCallback;
    
    // If user provided a custom callback, use its decision
    if (badCertificateCallback != null) {
      final shouldTrust = badCertificateCallback(cert, host, port);
      if (shouldTrust) {
        return true; // User trusts this certificate
      }
    }

    debugPrint(
        "$_tag: Pinning failure callback for $host. Invalidating cache.");
    _HttpSecurityPinningService._removeCertificates(host);
    _connectedHost = null;
    return false;
  }

  void _copyHttpClientState(HttpClient from, HttpClient to) {
    to.idleTimeout = from.idleTimeout;
    to.userAgent = from.userAgent;
    to.connectionTimeout = from.connectionTimeout;
    to.maxConnectionsPerHost = from.maxConnectionsPerHost;
    to.autoUncompress = from.autoUncompress;

    to.authenticate = _authenticate;
    to.connectionFactory = _connectionFactory;
    to.keyLog = _keyLog;
    to.findProxy = _findProxy;
    to.authenticateProxy = _authenticateProxy;

    for (final credential in _credentials) {
      to.addCredentials(
          credential.url, credential.realm, credential.credentials);
    }
    for (final proxyCredential in _proxyCredentials) {
      to.addProxyCredentials(proxyCredential.host, proxyCredential.port,
          proxyCredential.realm, proxyCredential.credentials);
    }

    to.badCertificateCallback = _pinningFailureCallback;
  }

  Future<HttpClient> _createPinnedHttpClient(Uri url) async {
    final securityContext = _validPins.isEmpty
        ? SecurityContext.defaultContext
        : await _HttpSecurityPinningService._pinnedSecurityContext(
            url, _validPins, timeout, retryCount);

    final newHttpClient = HttpClient(context: securityContext);
    _copyHttpClientState(_delegatePinnedHttpClient, newHttpClient);

    _connectedHost = url.host;
    return newHttpClient;
  }

  Future<HttpClient> _getOrCreatePinnedHttpClient(Uri url) async {
    if (_isClosed) {
      throw StateError(
          'HttpSecurityPinningClient has been closed and cannot be used');
    }

    // Atomically check/create completer for this (host, pins) pair
    final completionKey = _HttpSecurityPinningService._makeCompletionKey(url.host, _validPins);
    Completer<HttpClient>? completer = 
        _HttpSecurityPinningService._clientCreationCompleters[completionKey];
    
    final shouldCreateClient = completer == null && _connectedHost != url.host;
    
    if (shouldCreateClient) {
      // Create and store completer atomically
      completer = Completer<HttpClient>();
      _HttpSecurityPinningService._clientCreationCompleters[completionKey] = completer;
      
      try {
        final newHttpClient = await _createPinnedHttpClient(url);
        final oldClient = _delegatePinnedHttpClient;
        _delegatePinnedHttpClient = newHttpClient;
        oldClient.close();
        completer.complete(newHttpClient);
      } catch (e, stackTrace) {
        completer.completeError(e, stackTrace);
        rethrow;
      } finally {
        // Clean up the completer after creation
        _HttpSecurityPinningService._clientCreationCompleters.remove(completionKey);
      }
    } else if (completer != null) {
      // Wait for ongoing creation to complete
      try {
        final client = await completer.future;
        _delegatePinnedHttpClient = client;
      } catch (_) {
        // If creation failed, clear the completer so next request retries
        _HttpSecurityPinningService._clientCreationCompleters.remove(completionKey);
        rethrow;
      }
    }
    
    return _delegatePinnedHttpClient;
  }

  /// Creates a new [HttpClient] that enforces certificate pinning.
  ///
  /// [spkiHashes] is a list of trusted SHA-256 hashes of a certificate's
  /// Subject Public Key Info (SPKI) in Base64 encoding (standard RFC 4648).
  ///
  /// [timeout] specifies the duration to wait for the native platform to fetch
  /// the certificate chain for a host. Defaults to 10 seconds.
  ///
  /// [retryCount] specifies the number of times to retry fetching the certificate
  /// chain upon failure. Defaults to 3 times.
  ///
  /// Throws [ArgumentError] if any SPKI hash is invalid (invalid base64 or wrong length).
  HttpSecurityPinningClient(
    List<String> spkiHashes, {
    this.timeout = const Duration(seconds: 10),
    this.retryCount = 3,
  })  : _validPins = _validatePins(spkiHashes),
        super() {
    debugPrint(
        "$_tag: HttpSecurityPinningClient initialized with ${_validPins.length} pins");
  }

  /// Validates and normalizes SPKI pins at construction time.
  ///
  /// Ensures:
  /// - Each pin is valid base64 (standard RFC 4648)
  /// - Each pin decodes to exactly 32 bytes (SHA-256)
  /// - Duplicate pins are removed
  static Set<String> _validatePins(List<String> spkiHashes) {
    final validatedPins = <String>{};

    for (final pin in spkiHashes) {
      try {
        // Decode and validate length
        final decodedPin = base64.decode(pin);
        
        // SHA-256 must be exactly 32 bytes
        if (decodedPin.length != 32) {
          throw ArgumentError(
              'SPKI hash "$pin" is ${decodedPin.length} bytes, expected 32 (SHA-256)');
        }
        
        validatedPins.add(pin);
      } on FormatException catch (e) {
        throw ArgumentError('Invalid base64 in SPKI hash "$pin": $e');
      }
    }

    if (validatedPins.isEmpty) {
      throw ArgumentError('At least one valid SPKI hash is required');
    }

    return validatedPins;
  }

  @override
  Future<HttpClientRequest> open(
      String method, String host, int port, String path) async {
    final url = Uri(scheme: "https", host: host, port: port, path: path);
    final client = await _getOrCreatePinnedHttpClient(url);
    return client.open(method, host, port, path);
  }

  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) async {
    final client = await _getOrCreatePinnedHttpClient(url);
    return client.openUrl(method, url);
  }

  @override
  Future<HttpClientRequest> get(String host, int port, String path) =>
      open('GET', host, port, path);

  @override
  Future<HttpClientRequest> getUrl(Uri url) => openUrl('GET', url);

  @override
  Future<HttpClientRequest> post(String host, int port, String path) =>
      open('POST', host, port, path);

  @override
  Future<HttpClientRequest> postUrl(Uri url) => openUrl('POST', url);

  @override
  Future<HttpClientRequest> put(String host, int port, String path) =>
      open('PUT', host, port, path);

  @override
  Future<HttpClientRequest> putUrl(Uri url) => openUrl('PUT', url);

  @override
  Future<HttpClientRequest> delete(String host, int port, String path) =>
      open('DELETE', host, port, path);

  @override
  Future<HttpClientRequest> deleteUrl(Uri url) => openUrl('DELETE', url);

  @override
  Future<HttpClientRequest> head(String host, int port, String path) =>
      open('HEAD', host, port, path);

  @override
  Future<HttpClientRequest> headUrl(Uri url) => openUrl('HEAD', url);

  @override
  Future<HttpClientRequest> patch(String host, int port, String path) =>
      open('PATCH', host, port, path);

  @override
  Future<HttpClientRequest> patchUrl(Uri url) => openUrl('PATCH', url);

  @override
  set idleTimeout(Duration timeout) =>
      _delegatePinnedHttpClient.idleTimeout = timeout;

  @override
  Duration get idleTimeout => _delegatePinnedHttpClient.idleTimeout;

  @override
  set connectionTimeout(Duration? timeout) =>
      _delegatePinnedHttpClient.connectionTimeout = timeout;

  @override
  Duration? get connectionTimeout =>
      _delegatePinnedHttpClient.connectionTimeout;

  @override
  set maxConnectionsPerHost(int? maxConnections) =>
      _delegatePinnedHttpClient.maxConnectionsPerHost = maxConnections;

  @override
  int? get maxConnectionsPerHost =>
      _delegatePinnedHttpClient.maxConnectionsPerHost;

  @override
  set autoUncompress(bool autoUncompress) =>
      _delegatePinnedHttpClient.autoUncompress = autoUncompress;

  @override
  bool get autoUncompress => _delegatePinnedHttpClient.autoUncompress;

  @override
  set userAgent(String? userAgent) =>
      _delegatePinnedHttpClient.userAgent = userAgent;

  @override
  String? get userAgent => _delegatePinnedHttpClient.userAgent;

  @override
  set authenticate(
      Future<bool> Function(Uri url, String scheme, String? realm)? f) {
    _authenticate = f;
    _delegatePinnedHttpClient.authenticate = f;
  }

  @override
  set connectionFactory(
      Future<ConnectionTask<Socket>> Function(
              Uri url, String? proxyHost, int? proxyPort)?
          f) {
    _connectionFactory = f;
    _delegatePinnedHttpClient.connectionFactory = f;
  }

  @override
  set keyLog(void Function(String line)? f) {
    _keyLog = f;
    _delegatePinnedHttpClient.keyLog = f;
  }

  @override
  void addCredentials(
      Uri url, String realm, HttpClientCredentials credentials) {
    _credentials.add(_Credential(url, realm, credentials));
    _delegatePinnedHttpClient.addCredentials(url, realm, credentials);
  }

  @override
  set findProxy(String Function(Uri url)? f) {
    _findProxy = f;
    _delegatePinnedHttpClient.findProxy = f;
  }

  @override
  set authenticateProxy(
      Future<bool> Function(
              String host, int port, String scheme, String? realm)?
          f) {
    _authenticateProxy = f;
    _delegatePinnedHttpClient.authenticateProxy = f;
  }

  @override
  void addProxyCredentials(
      String host, int port, String realm, HttpClientCredentials credentials) {
    _proxyCredentials.add(_ProxyCredential(host, port, realm, credentials));
    _delegatePinnedHttpClient.addProxyCredentials(
        host, port, realm, credentials);
  }

  @override
  set badCertificateCallback(
      bool Function(X509Certificate cert, String host, int port)? callback) {
    _badCertificateCallback = callback;
    _delegatePinnedHttpClient.badCertificateCallback = _pinningFailureCallback;
  }

  @override
  void close({bool force = false}) {
    _delegatePinnedHttpClient.close(force: force);
    _isClosed = true;
  }
}
