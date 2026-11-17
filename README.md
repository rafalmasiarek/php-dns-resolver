# dns-resolver
DNS resolver contract with two implementations:

- `SystemDnsResolver` — zero-config, backed by PHP's own `dns_get_record()`/`gethostbyaddr()`.
- `DnsClient`/`FailoverDnsClient` — from-scratch raw UDP/TCP client targeting an explicit
  resolver, with its own timeout, independent of the system resolver.

## Features

- Record types: A, AAAA, MX (preference-sorted), TXT, PTR.
- EDNS0 (RFC 6891): 4096-byte UDP payload advertisement + DNSSEC OK bit, with automatic TCP
  fallback when a response still arrives truncated.
- AD (Authenticated Data) bit reporting on every answer — a soft signal that the queried
  resolver validated DNSSEC, not a cryptographic guarantee.
- `FailoverDnsClient`: ordered multi-resolver failover, PSR-3 audit logging, and an optional
  total-timeout bounding every attempt across all configured resolvers combined.
- `resolveManyA()`: concurrent batch A-record resolution over non-blocking sockets, with
  duplicate hostnames collapsed before querying.
- `CachingDnsResolver`: TTL-respecting decorator for any `DnsResolverInterface`, backed by
  the included `InMemoryDnsCache` or a custom `DnsCacheInterface` implementation.



## License
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

```text
The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files, to deal in the Software
without restriction.

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

Source: https://opensource.org/licenses/MIT
```
See [LICENSE](LICENSE) for full details.
## Authors

- Rafał Masiarek | [website](https://masiarek.pl) | [github](https://github.com/rafalmasiarek)


## Index

### Classes

- [`CachingDnsResolver`](#cachingdnsresolver) — `rafalmasiarek\DnsResolver`
- [`DnsAnswer`](#dnsanswer) — `rafalmasiarek\DnsResolver`
- [`DnsClient`](#dnsclient) — `rafalmasiarek\DnsResolver`
- [`DnsMessageDecoder`](#dnsmessagedecoder) — `rafalmasiarek\DnsResolver`
- [`DnsMessageEncoder`](#dnsmessageencoder) — `rafalmasiarek\DnsResolver`
- [`DnsQueryException`](#dnsqueryexception) — `rafalmasiarek\DnsResolver`
- [`DnsTimeoutException`](#dnstimeoutexception) — `rafalmasiarek\DnsResolver`
- [`FailoverDnsClient`](#failoverdnsclient) — `rafalmasiarek\DnsResolver`
- [`InMemoryDnsCache`](#inmemorydnscache) — `rafalmasiarek\DnsResolver`
- [`SystemDnsResolver`](#systemdnsresolver) — `rafalmasiarek\DnsResolver`
- [`TcpTransport`](#tcptransport) — `rafalmasiarek\DnsResolver\Transport`
- [`UdpTransport`](#udptransport) — `rafalmasiarek\DnsResolver\Transport`

### Interfaces

- [`DnsCacheInterface`](#dnscacheinterface) — `rafalmasiarek\DnsResolver`
- [`DnsResolverInterface`](#dnsresolverinterface) — `rafalmasiarek\DnsResolver`
- [`DnsTransportInterface`](#dnstransportinterface) — `rafalmasiarek\DnsResolver\Transport`

## `CachingDnsResolver`

*final class* — `rafalmasiarek\DnsResolver\CachingDnsResolver` · [source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/CachingDnsResolver.php#L18)

Decorates any DnsResolverInterface with a TTL-respecting cache, keyed per query type + hostname. Entries with a TTL of 0 (unknown/do-not-cache, including every NXDOMAIN without an authority SOA) are never stored. resolveManyA() is intentionally not cached here — it already fans out per hostname in the wrapped resolver, and caching a batch result per-hostname would need to special-case partial hits; cache the individual resolveA() calls instead if that matters for your use case.

implements [`DnsResolverInterface`](#dnsresolverinterface)

**Depends on:** [`DnsCacheInterface`](#dnscacheinterface)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#cachingdnsresolver-__construct) | public | — | — |
| [`resolveA()`](#cachingdnsresolver-resolvea) | public | [`DnsAnswer`](#dnsanswer) | Resolves the A records for a hostname. |
| [`resolveAAAA()`](#cachingdnsresolver-resolveaaaa) | public | [`DnsAnswer`](#dnsanswer) | Resolves the AAAA records for a hostname. |
| [`resolveMx()`](#cachingdnsresolver-resolvemx) | public | [`DnsAnswer`](#dnsanswer) | Resolves the MX records for a domain. |
| [`resolveTxt()`](#cachingdnsresolver-resolvetxt) | public | [`DnsAnswer`](#dnsanswer) | Resolves the TXT records for a hostname. |
| [`resolvePtr()`](#cachingdnsresolver-resolveptr) | public | [`DnsAnswer`](#dnsanswer) | Resolves the PTR (reverse DNS) record for an IPv4 or IPv6 address. |
| [`resolve()`](#cachingdnsresolver-resolve) | public | [`DnsAnswer`](#dnsanswer) | Resolves the best available address for a hostname, trying IPv4 and IPv6 in whichever order the implementation is configured to prefer, falling back to the other family when the preferred one yields no records. |
| [`resolveManyA()`](#cachingdnsresolver-resolvemanya) | public | `array<string, DnsAnswer\|DnsQueryException>` | Resolves the A records for several hostnames concurrently instead of one at a time, so the total wait is bounded by the slowest single query rather than the sum of all of them. Duplicate hostnames are queried once. |
| [`cached()`](#cachingdnsresolver-cached) | private | [`DnsAnswer`](#dnsanswer) | — |

<details>
<summary><code>__construct()</code></summary>

#### `CachingDnsResolver __construct()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/CachingDnsResolver.php#L24)

```php
public function __construct(DnsResolverInterface $inner, DnsCacheInterface $cache)
```

| Param | Type | Description |
|---|---|---|
| `$inner` | [`DnsResolverInterface`](#dnsresolverinterface) | Resolver to cache the results of. |
| `$cache` | [`DnsCacheInterface`](#dnscacheinterface) | Storage backend; a fresh InMemoryDnsCache when omitted. |

</details>

<details>
<summary><code>resolveA()</code></summary>

#### `CachingDnsResolver resolveA()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/CachingDnsResolver.php#L33)

```php
public function resolveA(string $hostname): DnsAnswer
```

Resolves the A records for a hostname.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When the query cannot be completed. |

</details>

<details>
<summary><code>resolveAAAA()</code></summary>

#### `CachingDnsResolver resolveAAAA()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/CachingDnsResolver.php#L41)

```php
public function resolveAAAA(string $hostname): DnsAnswer
```

Resolves the AAAA records for a hostname.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When the query cannot be completed. |

</details>

<details>
<summary><code>resolveMx()</code></summary>

#### `CachingDnsResolver resolveMx()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/CachingDnsResolver.php#L49)

```php
public function resolveMx(string $hostname): DnsAnswer
```

Resolves the MX records for a domain.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified domain to query. |

**Returns:** [`DnsAnswer`](#dnsanswer) — Records are mail exchanger hostnames, ordered by ascending preference (lowest/most-preferred first).

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When the query cannot be completed. |

</details>

<details>
<summary><code>resolveTxt()</code></summary>

#### `CachingDnsResolver resolveTxt()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/CachingDnsResolver.php#L57)

```php
public function resolveTxt(string $hostname): DnsAnswer
```

Resolves the TXT records for a hostname.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer) — Each record is one TXT record's full text (its character-strings concatenated, per convention).

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When the query cannot be completed. |

</details>

<details>
<summary><code>resolvePtr()</code></summary>

#### `CachingDnsResolver resolvePtr()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/CachingDnsResolver.php#L65)

```php
public function resolvePtr(string $ip): DnsAnswer
```

Resolves the PTR (reverse DNS) record for an IPv4 or IPv6 address.

| Param | Type | Description |
|---|---|---|
| `$ip` | `string` | IPv4 or IPv6 address. |

**Returns:** [`DnsAnswer`](#dnsanswer) — Records are hostnames, not addresses. Empty on NXDOMAIN.

| Throws | When |
|---|---|
| `\InvalidArgumentException` | When $ip is not a valid IPv4 or IPv6 address. |
| [`DnsQueryException`](#dnsqueryexception) | When the query cannot be completed. |

</details>

<details>
<summary><code>resolve()</code></summary>

#### `CachingDnsResolver resolve()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/CachingDnsResolver.php#L73)

```php
public function resolve(string $hostname): DnsAnswer
```

Resolves the best available address for a hostname, trying IPv4 and IPv6 in whichever order the implementation is configured to prefer, falling back to the other family when the preferred one yields no records.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When neither address family can be resolved. |

</details>

<details>
<summary><code>resolveManyA()</code></summary>

#### `CachingDnsResolver resolveManyA()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/CachingDnsResolver.php#L81)

```php
public function resolveManyA(array $hostnames): array
```

Resolves the A records for several hostnames concurrently instead of one at a time, so the total wait is bounded by the slowest single query rather than the sum of all of them. Duplicate hostnames are queried once.

| Param | Type | Description |
|---|---|---|
| `$hostnames` | `list<string>` | Fully-qualified hostnames to query. |

**Returns:** `array<string, DnsAnswer\|DnsQueryException>` — Keyed by hostname. Each value is either a successful DnsAnswer or the DnsQueryException/DnsTimeoutException that occurred for that hostname — one host's failure never affects another's result.

</details>

<details>
<summary><code>cached()</code></summary>

#### `CachingDnsResolver cached()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/CachingDnsResolver.php#L93)

```php
private function cached(string $type, string $key, callable $resolve): DnsAnswer
```

| Param | Type | Description |
|---|---|---|
| `$type` | `string` | — |
| `$key` | `string` | — |
| `$resolve` | `callable` | — |

**Returns:** [`DnsAnswer`](#dnsanswer)

</details>

## `DnsAnswer`

*final readonly class* — `rafalmasiarek\DnsResolver\DnsAnswer` · [source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsAnswer.php#L12)

Result of a DNS query, including the TTL to honor for caching.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#dnsanswer-__construct) | public | — | — |

<details>
<summary><code>__construct()</code></summary>

#### `DnsAnswer __construct()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsAnswer.php#L25)

```php
public function __construct(array $records, int $ttl, bool $authenticatedData)
```

| Param | Type | Description |
|---|---|---|
| `$records` | `list<string>` | IPv4 or IPv6 addresses from the answer. Empty when the hostname has no record of the queried type. |
| `$ttl` | `int` | Seconds this answer may be cached for. 0 when unknown — callers should treat that as "do not cache". |
| `$authenticatedData` | `bool` | Whether the resolver's response carried the DNS header's AD (Authenticated Data) bit, i.e. the resolver itself validated DNSSEC for this answer. Always false for resolvers that cannot observe the raw header (e.g. SystemDnsResolver). |

</details>

## `DnsCacheInterface`

*interface* — `rafalmasiarek\DnsResolver\DnsCacheInterface` · [source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsCacheInterface.php#L15)

Storage backend for CachingDnsResolver. Deliberately not PSR-16 — this package has no dependencies, and this contract is narrow enough (a single value type, TTL-aware) that PSR-16's generic get/set/delete surface would add nothing. Implement to back CachingDnsResolver with Redis, APCu, etc.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`get()`](#dnscacheinterface-get) | public | `DnsAnswer\|null` | — |
| [`set()`](#dnscacheinterface-set) | public | `void` | — |

<details>
<summary><code>get()</code></summary>

#### `DnsCacheInterface get()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsCacheInterface.php#L22)

```php
public function get(string $key): ?DnsAnswer
```

| Param | Type | Description |
|---|---|---|
| `$key` | `string` | — |

**Returns:** `DnsAnswer\|null` — Null on a cache miss or an expired entry.

</details>

<details>
<summary><code>set()</code></summary>

#### `DnsCacheInterface set()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsCacheInterface.php#L32)

```php
public function set(string $key, DnsAnswer $answer, int $ttl): void
```

| Param | Type | Description |
|---|---|---|
| `$key` | `string` | — |
| `$answer` | [`DnsAnswer`](#dnsanswer) | — |
| `$ttl` | `int` | Seconds until the entry expires. Callers never pass 0 or negative values — CachingDnsResolver skips storing those. |

</details>

## `DnsClient`

*final class* — `rafalmasiarek\DnsResolver\DnsClient` · [source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsClient.php#L33)

From-scratch DNS client (RFC 1035) resolving over raw UDP/TCP against an explicit resolver, with its own connect/read timeout. Does not use the system resolver (dns_get_record()/checkdnsrr() always query whatever is configured in /etc/resolv.conf and have no per-call timeout) — this client always targets the resolver IP given at construction time. Sends EDNS0 (RFC 6891): an OPT pseudo-record advertising a 4096-byte UDP payload size and requesting the DNSSEC OK (DO) bit, so most answers that would otherwise truncate at the classic 512-byte UDP limit (large TXT/SPF records, domains with many MX records) fit in a single UDP response. When a response still arrives with the TC (truncated) bit set, the same query is retried once over TCP. Message encoding/decoding lives in DnsMessageEncoder/DnsMessageDecoder (pure, socket-free); the wire transport lives in Transport\UdpTransport/ TcpTransport. This class owns only the per-type public API, the UDP-then-TCP-on-truncation orchestration, and the concurrent batch path.

implements [`DnsResolverInterface`](#dnsresolverinterface)

**Depends on:** [`UdpTransport`](#udptransport), [`TcpTransport`](#tcptransport)

| Property | Type | Visibility | Description |
|---|---|---|---|
| `$udpTransport` | [`UdpTransport`](#udptransport) | private readonly | — |
| `$tcpTransport` | [`TcpTransport`](#tcptransport) | private readonly | — |

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#dnsclient-__construct) | public | — | — |
| [`withTimeout()`](#dnsclient-withtimeout) | public | `self` | Returns a clone of this client with a different timeout — used by FailoverDnsClient to shrink the per-attempt timeout to whatever budget remains under a total-timeout cap, without affecting this instance. |
| [`resolveA()`](#dnsclient-resolvea) | public | [`DnsAnswer`](#dnsanswer) | Resolves the A records for a hostname. |
| [`resolveAAAA()`](#dnsclient-resolveaaaa) | public | [`DnsAnswer`](#dnsanswer) | Resolves the AAAA records for a hostname. |
| [`resolveMx()`](#dnsclient-resolvemx) | public | [`DnsAnswer`](#dnsanswer) | Resolves the MX records for a domain. |
| [`resolveTxt()`](#dnsclient-resolvetxt) | public | [`DnsAnswer`](#dnsanswer) | Resolves the TXT records for a hostname. |
| [`resolvePtr()`](#dnsclient-resolveptr) | public | [`DnsAnswer`](#dnsanswer) | Resolves the PTR (reverse DNS) record for an IPv4 or IPv6 address. |
| [`reverseDnsName()`](#dnsclient-reversednsname) | private static | `string` | Builds the in-addr.arpa (IPv4) or ip6.arpa (IPv6) query name for an address. |
| [`resolve()`](#dnsclient-resolve) | public | [`DnsAnswer`](#dnsanswer) | Resolves the best available address for a hostname, always trying A first then AAAA — this single resolver has no notion of family preference; that policy lives in FailoverDnsClient, which queries this method's two siblings directly instead of calling this one. |
| [`resolveManyA()`](#dnsclient-resolvemanya) | public | `array<string, DnsAnswer\|DnsQueryException>` | Resolves the A records for several hostnames concurrently: one UDP socket per hostname (duplicates collapsed first), all queries sent immediately, then a single stream_select() loop collects whichever responses arrive first — so the total wait is bounded by the slowest single query (up to $this->timeout) rather than the sum of every query's own timeout. No TCP-truncation fallback here — A-record responses for the handful of addresses a single query returns do not truncate in practice, and adding a second, sequential TCP round-trip per truncated host would defeat the point of resolving concurrently. |
| [`query()`](#dnsclient-query) | private | [`DnsAnswer`](#dnsanswer) | Sends a single-question query of the given type over UDP, retrying once over TCP if the UDP response comes back truncated, and parses the result. |

<details>
<summary><code>__construct()</code></summary>

#### `DnsClient __construct()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsClient.php#L64)

```php
public function __construct(string $resolver, int $port, float $timeout)
```

| Param | Type | Description |
|---|---|---|
| `$resolver` | `string` | Resolver IP address to query. |
| `$port` | `int` | Resolver port. |
| `$timeout` | `float` | Socket connect + read timeout, in seconds. |

</details>

<details>
<summary><code>withTimeout()</code></summary>

#### `DnsClient withTimeout()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsClient.php#L82)

```php
public function withTimeout(float $timeout): self
```

Returns a clone of this client with a different timeout — used by FailoverDnsClient to shrink the per-attempt timeout to whatever budget remains under a total-timeout cap, without affecting this instance.

| Param | Type | Description |
|---|---|---|
| `$timeout` | `float` | — |

**Returns:** `self`

</details>

<details>
<summary><code>resolveA()</code></summary>

#### `DnsClient resolveA()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsClient.php#L97)

```php
public function resolveA(string $hostname): DnsAnswer
```

Resolves the A records for a hostname.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsTimeoutException`](#dnstimeoutexception) | When no response arrives within the timeout. |
| [`DnsQueryException`](#dnsqueryexception) | On socket failure or a malformed/non-NXDOMAIN error response. |

</details>

<details>
<summary><code>resolveAAAA()</code></summary>

#### `DnsClient resolveAAAA()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsClient.php#L112)

```php
public function resolveAAAA(string $hostname): DnsAnswer
```

Resolves the AAAA records for a hostname.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsTimeoutException`](#dnstimeoutexception) | When no response arrives within the timeout. |
| [`DnsQueryException`](#dnsqueryexception) | On socket failure or a malformed/non-NXDOMAIN error response. |

</details>

<details>
<summary><code>resolveMx()</code></summary>

#### `DnsClient resolveMx()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsClient.php#L127)

```php
public function resolveMx(string $hostname): DnsAnswer
```

Resolves the MX records for a domain.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified domain to query. |

**Returns:** [`DnsAnswer`](#dnsanswer) — Records are mail exchanger hostnames, ordered by ascending preference.

| Throws | When |
|---|---|
| [`DnsTimeoutException`](#dnstimeoutexception) | When no response arrives within the timeout. |
| [`DnsQueryException`](#dnsqueryexception) | On socket failure or a malformed/non-NXDOMAIN error response. |

</details>

<details>
<summary><code>resolveTxt()</code></summary>

#### `DnsClient resolveTxt()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsClient.php#L142)

```php
public function resolveTxt(string $hostname): DnsAnswer
```

Resolves the TXT records for a hostname.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer) — Each record is one TXT record's full text.

| Throws | When |
|---|---|
| [`DnsTimeoutException`](#dnstimeoutexception) | When no response arrives within the timeout. |
| [`DnsQueryException`](#dnsqueryexception) | On socket failure or a malformed/non-NXDOMAIN error response. |

</details>

<details>
<summary><code>resolvePtr()</code></summary>

#### `DnsClient resolvePtr()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsClient.php#L158)

```php
public function resolvePtr(string $ip): DnsAnswer
```

Resolves the PTR (reverse DNS) record for an IPv4 or IPv6 address.

| Param | Type | Description |
|---|---|---|
| `$ip` | `string` | IPv4 or IPv6 address. |

**Returns:** [`DnsAnswer`](#dnsanswer) — Records are hostnames, not addresses. Empty on NXDOMAIN.

| Throws | When |
|---|---|
| `\InvalidArgumentException` | When $ip is not a valid IPv4 or IPv6 address. |
| [`DnsTimeoutException`](#dnstimeoutexception) | When no response arrives within the timeout. |
| [`DnsQueryException`](#dnsqueryexception) | On socket failure or a malformed/non-NXDOMAIN error response. |

</details>

<details>
<summary><code>reverseDnsName()</code></summary>

#### `DnsClient reverseDnsName()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsClient.php#L172)

```php
private static function reverseDnsName(string $ip): string
```

Builds the in-addr.arpa (IPv4) or ip6.arpa (IPv6) query name for an address.

| Param | Type | Description |
|---|---|---|
| `$ip` | `string` | IPv4 or IPv6 address. |

**Returns:** `string`

| Throws | When |
|---|---|
| `\InvalidArgumentException` | When $ip is not a valid IPv4 or IPv6 address. |

</details>

<details>
<summary><code>resolve()</code></summary>

#### `DnsClient resolve()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsClient.php#L200)

```php
public function resolve(string $hostname): DnsAnswer
```

Resolves the best available address for a hostname, always trying A first then AAAA — this single resolver has no notion of family preference; that policy lives in FailoverDnsClient, which queries this method's two siblings directly instead of calling this one.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsTimeoutException`](#dnstimeoutexception) | When no response arrives within the timeout. |
| [`DnsQueryException`](#dnsqueryexception) | On socket failure or a malformed/non-NXDOMAIN error response. |

</details>

<details>
<summary><code>resolveManyA()</code></summary>

#### `DnsClient resolveManyA()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsClient.php#L222)

```php
public function resolveManyA(array $hostnames): array
```

Resolves the A records for several hostnames concurrently: one UDP socket per hostname (duplicates collapsed first), all queries sent immediately, then a single stream_select() loop collects whichever responses arrive first — so the total wait is bounded by the slowest single query (up to $this->timeout) rather than the sum of every query's own timeout. No TCP-truncation fallback here — A-record responses for the handful of addresses a single query returns do not truncate in practice, and adding a second, sequential TCP round-trip per truncated host would defeat the point of resolving concurrently.

| Param | Type | Description |
|---|---|---|
| `$hostnames` | `list<string>` | Fully-qualified hostnames to query. |

**Returns:** `array<string, DnsAnswer\|DnsQueryException>` — Keyed by hostname.

</details>

<details>
<summary><code>query()</code></summary>

#### `DnsClient query()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsClient.php#L332)

```php
private function query(string $hostname, int $type): DnsAnswer
```

Sends a single-question query of the given type over UDP, retrying once over TCP if the UDP response comes back truncated, and parses the result.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |
| `$type` | `int` | DNS record type. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsTimeoutException`](#dnstimeoutexception) | When no response arrives within the timeout. |
| [`DnsQueryException`](#dnsqueryexception) | On socket failure or a malformed/non-NXDOMAIN error response. |

</details>

## `DnsMessageDecoder`

*final class* — `rafalmasiarek\DnsResolver\DnsMessageDecoder` · [source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsMessageDecoder.php#L20)

Parses binary DNS response packets (RFC 1035 §4.1.1-4.1.4) into a DnsAnswer. Pure, side-effect-free — no sockets, so testable without a transport. Every field read from the packet is bounds-checked against the packet's actual remaining length before use. A malformed or truncated packet always throws DnsQueryException rather than being silently treated as partially valid — e.g. an answer record whose declared RDLENGTH would read past the end of the packet, or a TXT character-string whose declared length would do the same, is rejected outright instead of returning truncated data.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`isTruncated()`](#dnsmessagedecoder-istruncated) | public static | `bool` | Whether a raw response packet has the TC (truncated) flag set. |
| [`decode()`](#dnsmessagedecoder-decode) | public static | [`DnsAnswer`](#dnsanswer) | Parses a DNS response packet and extracts records of the queried type and a cache TTL. |
| [`decodeCharacterStrings()`](#dnsmessagedecoder-decodecharacterstrings) | private static | `string` | Decodes a TXT record's RDATA: one or more length-prefixed character-strings, concatenated into a single string per the common resolver convention. |
| [`findSoaTtl()`](#dnsmessagedecoder-findsoattl) | private static | `int` | Scans the authority section for an SOA record and returns its TTL. |
| [`decodeName()`](#dnsmessagedecoder-decodename) | public static | `string` | Decodes a (possibly compressed) domain name starting at $offset, advancing it past the name. |

<details>
<summary><code>isTruncated()</code></summary>

#### `DnsMessageDecoder isTruncated()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsMessageDecoder.php#L58)

```php
public static function isTruncated(string $data): bool
```

Whether a raw response packet has the TC (truncated) flag set.

| Param | Type | Description |
|---|---|---|
| `$data` | `string` | — |

**Returns:** `bool`

</details>

<details>
<summary><code>decode()</code></summary>

#### `DnsMessageDecoder decode()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsMessageDecoder.php#L79)

```php
public static function decode(string $data, int $expectedId, int $type): DnsAnswer
```

Parses a DNS response packet and extracts records of the queried type and a cache TTL.

| Param | Type | Description |
|---|---|---|
| `$data` | `string` | Raw response packet. |
| `$expectedId` | `int` | Query id the response must echo back. |
| `$type` | `int` | DNS record type queried; only answer records of this type are collected. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | On a truncated/malformed packet, id mismatch, or an error RCODE other than NXDOMAIN (3). |

</details>

<details>
<summary><code>decodeCharacterStrings()</code></summary>

#### `DnsMessageDecoder decodeCharacterStrings()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsMessageDecoder.php#L203)

```php
private static function decodeCharacterStrings(string $rdata): string
```

Decodes a TXT record's RDATA: one or more length-prefixed character-strings, concatenated into a single string per the common resolver convention.

| Param | Type | Description |
|---|---|---|
| `$rdata` | `string` | — |

**Returns:** `string`

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When a character-string's declared length extends past the end of $rdata — a malformed record is rejected outright rather than silently returning truncated text. |

</details>

<details>
<summary><code>findSoaTtl()</code></summary>

#### `DnsMessageDecoder findSoaTtl()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsMessageDecoder.php#L236)

```php
private static function findSoaTtl(string $data, int $offset, int $nscount): int
```

Scans the authority section for an SOA record and returns its TTL.

| Param | Type | Description |
|---|---|---|
| `$data` | `string` | Raw response packet. |
| `$offset` | `int` | Byte offset of the authority section (past the question section). |
| `$nscount` | `int` | Number of authority records to scan. |

**Returns:** `int` — The SOA record's TTL, or 0 when no SOA record is present.

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | On a malformed authority record header or RDATA extending past the end of the packet. |

</details>

<details>
<summary><code>decodeName()</code></summary>

#### `DnsMessageDecoder decodeName()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsMessageDecoder.php#L275)

```php
public static function decodeName(string $data, int $offset): string
```

Decodes a (possibly compressed) domain name starting at $offset, advancing it past the name.

| Param | Type | Description |
|---|---|---|
| `$data` | `string` | — |
| `$offset` | `int` | Byte offset to start reading at; advanced past the encoded name. |

**Returns:** `string` — Decoded, dot-separated domain name.

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | On a truncated name, a compression pointer loop, or a decoded name exceeding 255 bytes (RFC 1035 §3.1) — the pointer-loop guard alone bounds the number of jumps to the packet size, but not the total assembled name length. |

</details>

## `DnsMessageEncoder`

*final class* — `rafalmasiarek\DnsResolver\DnsMessageEncoder` · [source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsMessageEncoder.php#L13)

Builds binary DNS query packets (RFC 1035 §4.1.1-4.1.3, EDNS0 RFC 6891). Pure, side-effect-free — no sockets, so testable without a transport.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`buildQuery()`](#dnsmessageencoder-buildquery) | public static | `string` | Builds a single-question DNS query packet with an EDNS0 OPT pseudo-record advertising a 4096-byte UDP payload size and requesting the DNSSEC OK bit. |
| [`encodeName()`](#dnsmessageencoder-encodename) | public static | `string` | Encodes a hostname as a sequence of length-prefixed labels terminated by a zero byte. |
| [`buildOptRecord()`](#dnsmessageencoder-buildoptrecord) | private static | `string` | Builds the EDNS0 OPT pseudo-record (RFC 6891): root name, TYPE=OPT, CLASS=advertised UDP payload size, TTL carries ext-RCODE(0)+version(0)+ flags (DO bit set, requesting DNSSEC OK), empty RDATA. |

<details>
<summary><code>buildQuery()</code></summary>

#### `DnsMessageEncoder buildQuery()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsMessageEncoder.php#L39)

```php
public static function buildQuery(string $hostname, int $id, int $type): string
```

Builds a single-question DNS query packet with an EDNS0 OPT pseudo-record advertising a 4096-byte UDP payload size and requesting the DNSSEC OK bit.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | — |
| `$id` | `int` | 16-bit query identifier, echoed back in the response. |
| `$type` | `int` | DNS record type. |

**Returns:** `string` — Binary DNS query packet.

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When $hostname cannot be encoded (see encodeName()). |

</details>

<details>
<summary><code>encodeName()</code></summary>

#### `DnsMessageEncoder encodeName()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsMessageEncoder.php#L70)

```php
public static function encodeName(string $hostname): string
```

Encodes a hostname as a sequence of length-prefixed labels terminated by a zero byte.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | — |

**Returns:** `string`

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When a label is empty (e.g. an embedded ".." inside a non-root hostname — silently encoding it would emit a premature terminator byte and truncate the name on the wire), a label exceeds 63 bytes, or the total encoded name exceeds 255 bytes. |

</details>

<details>
<summary><code>buildOptRecord()</code></summary>

#### `DnsMessageEncoder buildOptRecord()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsMessageEncoder.php#L108)

```php
private static function buildOptRecord(): string
```

Builds the EDNS0 OPT pseudo-record (RFC 6891): root name, TYPE=OPT, CLASS=advertised UDP payload size, TTL carries ext-RCODE(0)+version(0)+ flags (DO bit set, requesting DNSSEC OK), empty RDATA.

**Returns:** `string`

</details>

## `DnsQueryException`

*class* — `rafalmasiarek\DnsResolver\DnsQueryException` · [source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsQueryException.php#L12)

Thrown when a DNS query cannot be completed.

extends `\RuntimeException`

## `DnsResolverInterface`

*interface* — `rafalmasiarek\DnsResolver\DnsResolverInterface` · [source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsResolverInterface.php#L12)

Resolves DNS records for a hostname.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`resolveA()`](#dnsresolverinterface-resolvea) | public | [`DnsAnswer`](#dnsanswer) | Resolves the A records for a hostname. |
| [`resolveAAAA()`](#dnsresolverinterface-resolveaaaa) | public | [`DnsAnswer`](#dnsanswer) | Resolves the AAAA records for a hostname. |
| [`resolveMx()`](#dnsresolverinterface-resolvemx) | public | [`DnsAnswer`](#dnsanswer) | Resolves the MX records for a domain. |
| [`resolveTxt()`](#dnsresolverinterface-resolvetxt) | public | [`DnsAnswer`](#dnsanswer) | Resolves the TXT records for a hostname. |
| [`resolvePtr()`](#dnsresolverinterface-resolveptr) | public | [`DnsAnswer`](#dnsanswer) | Resolves the PTR (reverse DNS) record for an IPv4 or IPv6 address. |
| [`resolve()`](#dnsresolverinterface-resolve) | public | [`DnsAnswer`](#dnsanswer) | Resolves the best available address for a hostname, trying IPv4 and IPv6 in whichever order the implementation is configured to prefer, falling back to the other family when the preferred one yields no records. |
| [`resolveManyA()`](#dnsresolverinterface-resolvemanya) | public | `array<string, DnsAnswer\|DnsQueryException>` | Resolves the A records for several hostnames concurrently instead of one at a time, so the total wait is bounded by the slowest single query rather than the sum of all of them. Duplicate hostnames are queried once. |

<details>
<summary><code>resolveA()</code></summary>

#### `DnsResolverInterface resolveA()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsResolverInterface.php#L21)

```php
public function resolveA(string $hostname): DnsAnswer
```

Resolves the A records for a hostname.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When the query cannot be completed. |

</details>

<details>
<summary><code>resolveAAAA()</code></summary>

#### `DnsResolverInterface resolveAAAA()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsResolverInterface.php#L30)

```php
public function resolveAAAA(string $hostname): DnsAnswer
```

Resolves the AAAA records for a hostname.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When the query cannot be completed. |

</details>

<details>
<summary><code>resolveMx()</code></summary>

#### `DnsResolverInterface resolveMx()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsResolverInterface.php#L40)

```php
public function resolveMx(string $hostname): DnsAnswer
```

Resolves the MX records for a domain.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified domain to query. |

**Returns:** [`DnsAnswer`](#dnsanswer) — Records are mail exchanger hostnames, ordered by ascending preference (lowest/most-preferred first).

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When the query cannot be completed. |

</details>

<details>
<summary><code>resolveTxt()</code></summary>

#### `DnsResolverInterface resolveTxt()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsResolverInterface.php#L50)

```php
public function resolveTxt(string $hostname): DnsAnswer
```

Resolves the TXT records for a hostname.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer) — Each record is one TXT record's full text (its character-strings concatenated, per convention).

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When the query cannot be completed. |

</details>

<details>
<summary><code>resolvePtr()</code></summary>

#### `DnsResolverInterface resolvePtr()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsResolverInterface.php#L60)

```php
public function resolvePtr(string $ip): DnsAnswer
```

Resolves the PTR (reverse DNS) record for an IPv4 or IPv6 address.

| Param | Type | Description |
|---|---|---|
| `$ip` | `string` | IPv4 or IPv6 address. |

**Returns:** [`DnsAnswer`](#dnsanswer) — Records are hostnames, not addresses. Empty on NXDOMAIN.

| Throws | When |
|---|---|
| `\InvalidArgumentException` | When $ip is not a valid IPv4 or IPv6 address. |
| [`DnsQueryException`](#dnsqueryexception) | When the query cannot be completed. |

</details>

<details>
<summary><code>resolve()</code></summary>

#### `DnsResolverInterface resolve()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsResolverInterface.php#L71)

```php
public function resolve(string $hostname): DnsAnswer
```

Resolves the best available address for a hostname, trying IPv4 and IPv6 in whichever order the implementation is configured to prefer, falling back to the other family when the preferred one yields no records.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When neither address family can be resolved. |

</details>

<details>
<summary><code>resolveManyA()</code></summary>

#### `DnsResolverInterface resolveManyA()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsResolverInterface.php#L87)

```php
public function resolveManyA(array $hostnames): array
```

Resolves the A records for several hostnames concurrently instead of one at a time, so the total wait is bounded by the slowest single query rather than the sum of all of them. Duplicate hostnames are queried once.

| Param | Type | Description |
|---|---|---|
| `$hostnames` | `list<string>` | Fully-qualified hostnames to query. |

**Returns:** `array<string, DnsAnswer\|DnsQueryException>` — Keyed by hostname. Each value is either a successful DnsAnswer or the DnsQueryException/DnsTimeoutException that occurred for that hostname — one host's failure never affects another's result.

</details>

## `DnsTimeoutException`

*class* — `rafalmasiarek\DnsResolver\DnsTimeoutException` · [source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/DnsTimeoutException.php#L14)

Thrown when no response arrives within the configured timeout. A subtype of DnsQueryException, so existing catch (DnsQueryException) call sites keep working without changes.

extends [`DnsQueryException`](#dnsqueryexception)

## `FailoverDnsClient`

*final class* — `rafalmasiarek\DnsResolver\FailoverDnsClient` · [source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/FailoverDnsClient.php#L27)

Queries a list of resolvers in order, falling over to the next one when a query fails (timeout or socket error). All resolvers are treated as equal peers — there is no primary/secondary distinction, just an ordered attempt list. Existing NXDOMAIN/success responses are never retried against another resolver, only failed queries. $totalTimeout, when set, bounds the sum of every resolver attempt for a single call: each attempt's own timeout is shrunk to whatever budget remains (via DnsClient::withTimeout()), so the call as a whole cannot run longer than $totalTimeout even across multiple resolver attempts. Only applies to the single-hostname methods below (A/AAAA/MX/TXT/PTR/resolve); resolveManyA() runs its own parallel batch per resolver and is unaffected.

implements [`DnsResolverInterface`](#dnsresolverinterface)

**Depends on:** `LoggerInterface`

| Property | Type | Visibility | Description |
|---|---|---|---|
| `$resolverLabels` | `list<string>` | private readonly | Resolver IP addresses, in attempt order — kept alongside for logging. |
| `$clients` | `list<DnsClient>` | private readonly | One DnsClient per configured resolver, in attempt order. |
| `$logger` | `LoggerInterface` | private readonly | Logger for per-attempt failures and, when audit is true, every attempt. |

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#failoverdnsclient-__construct) | public | — | — |
| [`resolveA()`](#failoverdnsclient-resolvea) | public | [`DnsAnswer`](#dnsanswer) | Resolves the A records for a hostname, trying each configured resolver in order. |
| [`resolveAAAA()`](#failoverdnsclient-resolveaaaa) | public | [`DnsAnswer`](#dnsanswer) | Resolves the AAAA records for a hostname, trying each configured resolver in order. |
| [`resolveMx()`](#failoverdnsclient-resolvemx) | public | [`DnsAnswer`](#dnsanswer) | Resolves the MX records for a domain, trying each configured resolver in order. |
| [`resolveTxt()`](#failoverdnsclient-resolvetxt) | public | [`DnsAnswer`](#dnsanswer) | Resolves the TXT records for a hostname, trying each configured resolver in order. |
| [`resolvePtr()`](#failoverdnsclient-resolveptr) | public | [`DnsAnswer`](#dnsanswer) | Resolves the PTR record for an IP address, trying each configured resolver in order. |
| [`resolve()`](#failoverdnsclient-resolve) | public | [`DnsAnswer`](#dnsanswer) | Resolves the best available address for a hostname: tries the preferred address family across all configured resolvers first, and only falls back to the other family when the preferred one yields no records. |
| [`resolveManyA()`](#failoverdnsclient-resolvemanya) | public | `array<string, DnsAnswer\|DnsQueryException>` | Resolves the A records for several hostnames concurrently per resolver: each configured resolver gets one parallel batch attempt (see DnsClient::resolveManyA()) for whatever hostnames are still unresolved, so failover across resolvers only kicks in for the hostnames that actually failed, not for ones that already succeeded. |
| [`attempt()`](#failoverdnsclient-attempt) | private | [`DnsAnswer`](#dnsanswer) | Runs $call against each configured resolver in order, logging failures (always) and successes (only in audit mode), until one succeeds or the total-timeout budget (when configured) is exhausted. |

<details>
<summary><code>__construct()</code></summary>

#### `FailoverDnsClient __construct()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/FailoverDnsClient.php#L55)

```php
public function __construct(array $resolvers, int $port, float $timeout, bool $preferIpv6, ?LoggerInterface $logger, bool $audit, ?float $totalTimeout)
```

| Param | Type | Description |
|---|---|---|
| `$resolvers` | `list<string>` | Resolver IP addresses, in attempt order. |
| `$port` | `int` | Resolver port, shared by all resolvers. |
| `$timeout` | `float` | Per-attempt timeout, in seconds. |
| `$preferIpv6` | `bool` | When true, resolve() tries AAAA before A; otherwise A before AAAA. |
| `$logger` | `LoggerInterface\|null` | Receives failure warnings/errors always, and (when $audit is true) a debug entry for every successful attempt. Defaults to a no-op logger when omitted. |
| `$audit` | `bool` | When true, logs a debug entry for every successful attempt (host, record type, resolver used, duration, result). Failures are always logged regardless of this flag. |
| `$totalTimeout` | `float\|null` | Bounds the sum of every resolver attempt for a single call, in seconds. Null (default) disables the budget — each resolver always gets its full $timeout. |

| Throws | When |
|---|---|
| `\InvalidArgumentException` | When $resolvers is empty. |

</details>

<details>
<summary><code>resolveA()</code></summary>

#### `FailoverDnsClient resolveA()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/FailoverDnsClient.php#L85)

```php
public function resolveA(string $hostname): DnsAnswer
```

Resolves the A records for a hostname, trying each configured resolver in order.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When every configured resolver fails. |

</details>

<details>
<summary><code>resolveAAAA()</code></summary>

#### `FailoverDnsClient resolveAAAA()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/FailoverDnsClient.php#L99)

```php
public function resolveAAAA(string $hostname): DnsAnswer
```

Resolves the AAAA records for a hostname, trying each configured resolver in order.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When every configured resolver fails. |

</details>

<details>
<summary><code>resolveMx()</code></summary>

#### `FailoverDnsClient resolveMx()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/FailoverDnsClient.php#L113)

```php
public function resolveMx(string $hostname): DnsAnswer
```

Resolves the MX records for a domain, trying each configured resolver in order.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified domain to query. |

**Returns:** [`DnsAnswer`](#dnsanswer) — Records are mail exchanger hostnames, ordered by ascending preference.

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When every configured resolver fails. |

</details>

<details>
<summary><code>resolveTxt()</code></summary>

#### `FailoverDnsClient resolveTxt()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/FailoverDnsClient.php#L127)

```php
public function resolveTxt(string $hostname): DnsAnswer
```

Resolves the TXT records for a hostname, trying each configured resolver in order.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When every configured resolver fails. |

</details>

<details>
<summary><code>resolvePtr()</code></summary>

#### `FailoverDnsClient resolvePtr()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/FailoverDnsClient.php#L141)

```php
public function resolvePtr(string $ip): DnsAnswer
```

Resolves the PTR record for an IP address, trying each configured resolver in order.

| Param | Type | Description |
|---|---|---|
| `$ip` | `string` | IPv4 or IPv6 address. |

**Returns:** [`DnsAnswer`](#dnsanswer) — Records are hostnames, not addresses. Empty on NXDOMAIN.

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When every configured resolver fails. |

</details>

<details>
<summary><code>resolve()</code></summary>

#### `FailoverDnsClient resolve()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/FailoverDnsClient.php#L157)

```php
public function resolve(string $hostname): DnsAnswer
```

Resolves the best available address for a hostname: tries the preferred address family across all configured resolvers first, and only falls back to the other family when the preferred one yields no records.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When neither address family can be resolved by any resolver. |

</details>

<details>
<summary><code>resolveManyA()</code></summary>

#### `FailoverDnsClient resolveManyA()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/FailoverDnsClient.php#L202)

```php
public function resolveManyA(array $hostnames): array
```

Resolves the A records for several hostnames concurrently per resolver: each configured resolver gets one parallel batch attempt (see DnsClient::resolveManyA()) for whatever hostnames are still unresolved, so failover across resolvers only kicks in for the hostnames that actually failed, not for ones that already succeeded.

| Param | Type | Description |
|---|---|---|
| `$hostnames` | `list<string>` | Fully-qualified hostnames to query. |

**Returns:** `array<string, DnsAnswer\|DnsQueryException>` — Keyed by hostname.

</details>

<details>
<summary><code>attempt()</code></summary>

#### `FailoverDnsClient attempt()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/FailoverDnsClient.php#L279)

```php
private function attempt(string $type, string $hostname, callable $call): DnsAnswer
```

Runs $call against each configured resolver in order, logging failures (always) and successes (only in audit mode), until one succeeds or the total-timeout budget (when configured) is exhausted.

| Param | Type | Description |
|---|---|---|
| `$type` | `string` | 'A', 'AAAA', 'MX', 'TXT', or 'PTR' — for log context only. |
| `$hostname` | `string` | Fully-qualified hostname to query. |
| `$call` | `callable` | — |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When every configured resolver fails, or the total-timeout budget is exhausted before any resolver is tried. |

</details>

## `InMemoryDnsCache`

*final class* — `rafalmasiarek\DnsResolver\InMemoryDnsCache` · [source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/InMemoryDnsCache.php#L15)

Process-lifetime DnsCacheInterface backed by a plain array. The default CachingDnsResolver store; stateless across requests in a classic PHP-FPM process-per-request model — a long-running worker or CLI process is where this actually saves repeat queries.

implements [`DnsCacheInterface`](#dnscacheinterface)

| Property | Type | Visibility | Description |
|---|---|---|---|
| `$entries` | `array<string, array{0: DnsAnswer, 1: float}>` | private | Keyed by cache key; value is [answer, expiresAt]. |

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`get()`](#inmemorydnscache-get) | public | `DnsAnswer\|null` | — |
| [`set()`](#inmemorydnscache-set) | public | `void` | — |

<details>
<summary><code>get()</code></summary>

#### `InMemoryDnsCache get()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/InMemoryDnsCache.php#L23)

```php
public function get(string $key): ?DnsAnswer
```

| Param | Type | Description |
|---|---|---|
| `$key` | `string` | — |

**Returns:** `DnsAnswer\|null` — Null on a cache miss or an expired entry.

</details>

<details>
<summary><code>set()</code></summary>

#### `InMemoryDnsCache set()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/InMemoryDnsCache.php#L42)

```php
public function set(string $key, DnsAnswer $answer, int $ttl): void
```

| Param | Type | Description |
|---|---|---|
| `$key` | `string` | — |
| `$answer` | [`DnsAnswer`](#dnsanswer) | — |
| `$ttl` | `int` | Seconds until the entry expires. Callers never pass 0 or negative values — CachingDnsResolver skips storing those. |

</details>

## `SystemDnsResolver`

*final class* — `rafalmasiarek\DnsResolver\SystemDnsResolver` · [source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/SystemDnsResolver.php#L22)

Resolves A/AAAA/MX/TXT/PTR records via PHP's own system resolver (dns_get_record(), gethostbyaddr() for PTR). Pins nothing: no explicit nameserver, no custom timeout — whatever the host's resolv.conf and PHP's default DNS timeout behavior already do. This is the baseline DnsResolverInterface implementation; an app that needs an explicit nameserver, a bounded timeout, or failover should provide its own. dns_get_record() has no access to the raw response header, so DnsAnswer::$authenticatedData is always false here — this resolver cannot observe whether the system resolver validated DNSSEC.

implements [`DnsResolverInterface`](#dnsresolverinterface)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#systemdnsresolver-__construct) | public | — | — |
| [`resolveA()`](#systemdnsresolver-resolvea) | public | [`DnsAnswer`](#dnsanswer) | Resolves the A records for a hostname via the system resolver. |
| [`resolveAAAA()`](#systemdnsresolver-resolveaaaa) | public | [`DnsAnswer`](#dnsanswer) | Resolves the AAAA records for a hostname via the system resolver. |
| [`resolveMx()`](#systemdnsresolver-resolvemx) | public | [`DnsAnswer`](#dnsanswer) | Resolves the MX records for a domain via the system resolver. |
| [`resolveTxt()`](#systemdnsresolver-resolvetxt) | public | [`DnsAnswer`](#dnsanswer) | Resolves the TXT records for a hostname via the system resolver. |
| [`resolvePtr()`](#systemdnsresolver-resolveptr) | public | [`DnsAnswer`](#dnsanswer) | Resolves the PTR (reverse DNS) record for an IP address via the system resolver. |
| [`resolveManyA()`](#systemdnsresolver-resolvemanya) | public | `array<string, DnsAnswer\|DnsQueryException>` | Resolves the A records for several hostnames, one at a time via the system resolver — dns_get_record() has no concurrent-query mode, unlike DnsClient's raw-socket resolveManyA(). Provided so SystemDnsResolver stays a drop-in DnsResolverInterface implementation; prefer DnsClient/FailoverDnsClient when resolveManyA()'s concurrency is actually needed. |
| [`resolve()`](#systemdnsresolver-resolve) | public | [`DnsAnswer`](#dnsanswer) | — |
| [`query()`](#systemdnsresolver-query) | private | [`DnsAnswer`](#dnsanswer) | — |

<details>
<summary><code>__construct()</code></summary>

#### `SystemDnsResolver __construct()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/SystemDnsResolver.php#L27)

```php
public function __construct(bool $preferIpv6)
```

| Param | Type | Description |
|---|---|---|
| `$preferIpv6` | `bool` | When true, resolve() tries AAAA before A; otherwise A before AAAA. |

</details>

<details>
<summary><code>resolveA()</code></summary>

#### `SystemDnsResolver resolveA()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/SystemDnsResolver.php#L39)

```php
public function resolveA(string $hostname): DnsAnswer
```

Resolves the A records for a hostname via the system resolver.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When the system resolver reports a lookup failure. |

</details>

<details>
<summary><code>resolveAAAA()</code></summary>

#### `SystemDnsResolver resolveAAAA()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/SystemDnsResolver.php#L51)

```php
public function resolveAAAA(string $hostname): DnsAnswer
```

Resolves the AAAA records for a hostname via the system resolver.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When the system resolver reports a lookup failure. |

</details>

<details>
<summary><code>resolveMx()</code></summary>

#### `SystemDnsResolver resolveMx()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/SystemDnsResolver.php#L63)

```php
public function resolveMx(string $hostname): DnsAnswer
```

Resolves the MX records for a domain via the system resolver.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified domain to query. |

**Returns:** [`DnsAnswer`](#dnsanswer) — Records are mail exchanger hostnames, ordered by ascending preference.

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When the system resolver reports a lookup failure. |

</details>

<details>
<summary><code>resolveTxt()</code></summary>

#### `SystemDnsResolver resolveTxt()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/SystemDnsResolver.php#L90)

```php
public function resolveTxt(string $hostname): DnsAnswer
```

Resolves the TXT records for a hostname via the system resolver.

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer) — Each record is one TXT record's full text.

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When the system resolver reports a lookup failure. |

</details>

<details>
<summary><code>resolvePtr()</code></summary>

#### `SystemDnsResolver resolvePtr()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/SystemDnsResolver.php#L116)

```php
public function resolvePtr(string $ip): DnsAnswer
```

Resolves the PTR (reverse DNS) record for an IP address via the system resolver.

| Param | Type | Description |
|---|---|---|
| `$ip` | `string` | IPv4 or IPv6 address. |

**Returns:** [`DnsAnswer`](#dnsanswer) — Records are hostnames, not addresses.

| Throws | When |
|---|---|
| `\InvalidArgumentException` | When $ip is not a valid IPv4 or IPv6 address. |
| [`DnsQueryException`](#dnsqueryexception) | When the system resolver reports a lookup failure. |

</details>

<details>
<summary><code>resolveManyA()</code></summary>

#### `SystemDnsResolver resolveManyA()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/SystemDnsResolver.php#L141)

```php
public function resolveManyA(array $hostnames): array
```

Resolves the A records for several hostnames, one at a time via the system resolver — dns_get_record() has no concurrent-query mode, unlike DnsClient's raw-socket resolveManyA(). Provided so SystemDnsResolver stays a drop-in DnsResolverInterface implementation; prefer DnsClient/FailoverDnsClient when resolveManyA()'s concurrency is actually needed.

| Param | Type | Description |
|---|---|---|
| `$hostnames` | `list<string>` | Fully-qualified hostnames to query. |

**Returns:** `array<string, DnsAnswer\|DnsQueryException>` — Keyed by hostname.

</details>

<details>
<summary><code>resolve()</code></summary>

#### `SystemDnsResolver resolve()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/SystemDnsResolver.php#L159)

```php
public function resolve(string $hostname): DnsAnswer
```

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When both address families fail to resolve. |

</details>

<details>
<summary><code>query()</code></summary>

#### `SystemDnsResolver query()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/SystemDnsResolver.php#L200)

```php
private function query(string $hostname, int $type, string $label): DnsAnswer
```

| Param | Type | Description |
|---|---|---|
| `$hostname` | `string` | Fully-qualified hostname to query. |
| `$type` | `int` | DNS_A or DNS_AAAA. |
| `$label` | `string` | 'A' or 'AAAA', matching dns_get_record()'s record 'type' field. |

**Returns:** [`DnsAnswer`](#dnsanswer)

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When the system resolver reports a lookup failure. |

</details>

## `DnsTransportInterface`

*interface* — `rafalmasiarek\DnsResolver\Transport\DnsTransportInterface` · [source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/Transport/DnsTransportInterface.php#L18)

Sends one already-encoded DNS query packet to a fixed resolver and returns the raw response. Implementations own a single resolver/port/timeout for their whole lifetime — constructed once per DnsClient (or per attempt, via withTimeout()), not parameterized per call.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`send()`](#dnstransportinterface-send) | public | `string` | — |

<details>
<summary><code>send()</code></summary>

#### `DnsTransportInterface send()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/Transport/DnsTransportInterface.php#L28)

```php
public function send(string $query): string
```

| Param | Type | Description |
|---|---|---|
| `$query` | `string` | Binary DNS query packet. |

**Returns:** `string` — Raw response packet.

| Throws | When |
|---|---|
| [`DnsTimeoutException`](#dnstimeoutexception) | When no response arrives within the timeout. |
| [`DnsQueryException`](#dnsqueryexception) | On socket failure. |

</details>

## `TcpTransport`

*final class* — `rafalmasiarek\DnsResolver\Transport\TcpTransport` · [source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/Transport/TcpTransport.php#L16)

Sends a DNS query over TCP (2-byte length prefix framing, RFC 1035 §4.2.2), used as a fallback when a UDP response comes back truncated.

implements [`DnsTransportInterface`](#dnstransportinterface)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#tcptransport-__construct) | public | — | — |
| [`send()`](#tcptransport-send) | public | `string` | — |
| [`writeFully()`](#tcptransport-writefully) | private | `void` | Writes the entire buffer, looping over partial writes — fwrite() on a TCP stream may accept fewer bytes than given (e.g. a full kernel send buffer), and silently sending only part of the length-prefixed frame would desync the stream for whatever is read next. |
| [`readExactly()`](#tcptransport-readexactly) | private | `string` | Reads exactly $length bytes from a TCP stream, looping over partial reads. |

<details>
<summary><code>__construct()</code></summary>

#### `TcpTransport __construct()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/Transport/TcpTransport.php#L26)

```php
public function __construct(string $resolver, int $port, float $timeout)
```

| Param | Type | Description |
|---|---|---|
| `$resolver` | `string` | Resolver IP address to query. |
| `$port` | `int` | Resolver port. |
| `$timeout` | `float` | Socket connect + read timeout, in seconds. |

</details>

<details>
<summary><code>send()</code></summary>

#### `TcpTransport send()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/Transport/TcpTransport.php#L36)

```php
public function send(string $query): string
```

| Param | Type | Description |
|---|---|---|
| `$query` | `string` | Binary DNS query packet. |

**Returns:** `string` — Raw response packet.

| Throws | When |
|---|---|
| [`DnsTimeoutException`](#dnstimeoutexception) | When no response arrives within the timeout. |
| [`DnsQueryException`](#dnsqueryexception) | On socket failure. |

</details>

<details>
<summary><code>writeFully()</code></summary>

#### `TcpTransport writeFully()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/Transport/TcpTransport.php#L89)

```php
private function writeFully( $socket, string $buffer): void
```

Writes the entire buffer, looping over partial writes — fwrite() on a TCP stream may accept fewer bytes than given (e.g. a full kernel send buffer), and silently sending only part of the length-prefixed frame would desync the stream for whatever is read next.

| Param | Type | Description |
|---|---|---|
| `$socket` | `resource` | — |
| `$buffer` | `string` | — |

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When the socket rejects or fails a write. |

</details>

<details>
<summary><code>readExactly()</code></summary>

#### `TcpTransport readExactly()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/Transport/TcpTransport.php#L113)

```php
private function readExactly( $socket, int $length): string
```

Reads exactly $length bytes from a TCP stream, looping over partial reads.

| Param | Type | Description |
|---|---|---|
| `$socket` | `resource` | — |
| `$length` | `int` | — |

**Returns:** `string`

| Throws | When |
|---|---|
| [`DnsQueryException`](#dnsqueryexception) | When the connection closes before $length bytes arrive. |

</details>

## `UdpTransport`

*final class* — `rafalmasiarek\DnsResolver\Transport\UdpTransport` · [source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/Transport/UdpTransport.php#L19)

Sends a DNS query over UDP and reads a single response datagram. A single fwrite() of a query this small (well under any realistic path MTU) does not partially write in practice, unlike the TCP transport's stream — see TcpTransport for why that one loops.

implements [`DnsTransportInterface`](#dnstransportinterface)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#udptransport-__construct) | public | — | — |
| [`send()`](#udptransport-send) | public | `string` | — |

<details>
<summary><code>__construct()</code></summary>

#### `UdpTransport __construct()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/Transport/UdpTransport.php#L29)

```php
public function __construct(string $resolver, int $port, float $timeout)
```

| Param | Type | Description |
|---|---|---|
| `$resolver` | `string` | Resolver IP address to query. |
| `$port` | `int` | Resolver port. |
| `$timeout` | `float` | Socket connect + read timeout, in seconds. |

</details>

<details>
<summary><code>send()</code></summary>

#### `UdpTransport send()`

[source](https://github.com/rafalmasiarek/php-dns-resolver/blob/main/src/Transport/UdpTransport.php#L39)

```php
public function send(string $query): string
```

| Param | Type | Description |
|---|---|---|
| `$query` | `string` | Binary DNS query packet. |

**Returns:** `string` — Raw response packet.

| Throws | When |
|---|---|
| [`DnsTimeoutException`](#dnstimeoutexception) | When no response arrives within the timeout. |
| [`DnsQueryException`](#dnsqueryexception) | On socket failure. |

</details>




<!-- references -->

[repo_link]: https://github.com/rafalmasiarek/php-dns-resolver
