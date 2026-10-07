<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver;

/**
 * Storage backend for CachingDnsResolver. Deliberately not PSR-16 — this
 * package has no dependencies, and this contract is narrow enough (a single
 * value type, TTL-aware) that PSR-16's generic get/set/delete surface would
 * add nothing. Implement to back CachingDnsResolver with Redis, APCu, etc.
 *
 * @package rafalmasiarek\DnsResolver
 */
interface DnsCacheInterface
{
    /**
     * @param string $key
     *
     * @return DnsAnswer|null Null on a cache miss or an expired entry.
     */
    public function get(string $key): ?DnsAnswer;

    /**
     * @param string $key
     * @param DnsAnswer $answer
     * @param int $ttl Seconds until the entry expires. Callers never pass 0 or
     *                  negative values — CachingDnsResolver skips storing those.
     *
     * @return void
     */
    public function set(string $key, DnsAnswer $answer, int $ttl): void;
}
