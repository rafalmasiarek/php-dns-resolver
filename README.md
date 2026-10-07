# dns-resolver

DNS resolver contract with two implementations:

- `SystemDnsResolver` — zero-config, backed by PHP's own `dns_get_record()`/`gethostbyaddr()`.
- `DnsClient`/`FailoverDnsClient` — from-scratch raw UDP/TCP client targeting an explicit resolver, with its own timeout, independent of the system resolver.

## Features

- Record types: A, AAAA, MX (preference-sorted), TXT, PTR.
- EDNS0 (RFC 6891): 4096-byte UDP payload advertisement + DNSSEC OK bit, with automatic TCP fallback when a response still arrives truncated.
- AD (Authenticated Data) bit reporting on every answer — a soft signal that the queried resolver validated DNSSEC, not a cryptographic guarantee.
- `FailoverDnsClient`: ordered multi-resolver failover, PSR-3 audit logging, and an optional total-timeout bounding every attempt across all configured resolvers combined.
- `resolveManyA()`: concurrent batch A-record resolution over non-blocking sockets, with duplicate hostnames collapsed before querying.
- `CachingDnsResolver`: TTL-respecting decorator for any `DnsResolverInterface`, backed by the included `InMemoryDnsCache` or a custom `DnsCacheInterface` implementation.
