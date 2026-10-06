<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver;

/**
 * Result of a DNS query, including the TTL to honor for caching.
 *
 * @package rafalmasiarek\DnsResolver
 */
final readonly class DnsAnswer
{
    /**
     * @param list<string> $records         IPv4 or IPv6 addresses from the answer. Empty when
     *                                       the hostname has no record of the queried type.
     * @param int          $ttl             Seconds this answer may be cached for. 0 when
     *                                       unknown — callers should treat that as "do not cache".
     * @param bool         $authenticatedData Whether the resolver's response carried the DNS
     *                                       header's AD (Authenticated Data) bit, i.e. the
     *                                       resolver itself validated DNSSEC for this answer.
     *                                       Always false for resolvers that cannot observe the
     *                                       raw header (e.g. SystemDnsResolver).
     */
    public function __construct(
        public array $records,
        public int $ttl,
        public bool $authenticatedData = false,
    ) {
    }
}
