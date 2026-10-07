<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver;

/**
 * Decorates any DnsResolverInterface with a TTL-respecting cache, keyed per
 * query type + hostname. Entries with a TTL of 0 (unknown/do-not-cache,
 * including every NXDOMAIN without an authority SOA) are never stored.
 * resolveManyA() is intentionally not cached here — it already fans out per
 * hostname in the wrapped resolver, and caching a batch result per-hostname
 * would need to special-case partial hits; cache the individual resolveA()
 * calls instead if that matters for your use case.
 *
 * @package rafalmasiarek\DnsResolver
 */
final class CachingDnsResolver implements DnsResolverInterface
{
    /**
     * @param DnsResolverInterface $inner Resolver to cache the results of.
     * @param DnsCacheInterface $cache Storage backend; a fresh InMemoryDnsCache when omitted.
     */
    public function __construct(
        private readonly DnsResolverInterface $inner,
        private readonly DnsCacheInterface $cache = new InMemoryDnsCache(),
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function resolveA(string $hostname): DnsAnswer
    {
        return $this->cached('A', $hostname, fn(): DnsAnswer => $this->inner->resolveA($hostname));
    }

    /**
     * {@inheritDoc}
     */
    public function resolveAAAA(string $hostname): DnsAnswer
    {
        return $this->cached('AAAA', $hostname, fn(): DnsAnswer => $this->inner->resolveAAAA($hostname));
    }

    /**
     * {@inheritDoc}
     */
    public function resolveMx(string $hostname): DnsAnswer
    {
        return $this->cached('MX', $hostname, fn(): DnsAnswer => $this->inner->resolveMx($hostname));
    }

    /**
     * {@inheritDoc}
     */
    public function resolveTxt(string $hostname): DnsAnswer
    {
        return $this->cached('TXT', $hostname, fn(): DnsAnswer => $this->inner->resolveTxt($hostname));
    }

    /**
     * {@inheritDoc}
     */
    public function resolvePtr(string $ip): DnsAnswer
    {
        return $this->cached('PTR', $ip, fn(): DnsAnswer => $this->inner->resolvePtr($ip));
    }

    /**
     * {@inheritDoc}
     */
    public function resolve(string $hostname): DnsAnswer
    {
        return $this->cached('ANY', $hostname, fn(): DnsAnswer => $this->inner->resolve($hostname));
    }

    /**
     * {@inheritDoc}
     */
    public function resolveManyA(array $hostnames): array
    {
        return $this->inner->resolveManyA($hostnames);
    }

    /**
     * @param string $type
     * @param string $key
     * @param callable(): DnsAnswer $resolve
     *
     * @return DnsAnswer
     */
    private function cached(string $type, string $key, callable $resolve): DnsAnswer
    {
        $cacheKey = "{$type}:{$key}";

        $cached = $this->cache->get($cacheKey);
        if ($cached !== null) {
            return $cached;
        }

        $answer = $resolve();

        if ($answer->ttl > 0) {
            $this->cache->set($cacheKey, $answer, $answer->ttl);
        }

        return $answer;
    }
}
