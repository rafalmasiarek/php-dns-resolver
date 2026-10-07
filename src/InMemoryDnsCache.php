<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver;

/**
 * Process-lifetime DnsCacheInterface backed by a plain array. The default
 * CachingDnsResolver store; stateless across requests in a classic PHP-FPM
 * process-per-request model — a long-running worker or CLI process is where
 * this actually saves repeat queries.
 *
 * @package rafalmasiarek\DnsResolver
 */
final class InMemoryDnsCache implements DnsCacheInterface
{
    /** @var array<string, array{0: DnsAnswer, 1: float}> Keyed by cache key; value is [answer, expiresAt]. */
    private array $entries = [];

    /**
     * {@inheritDoc}
     */
    public function get(string $key): ?DnsAnswer
    {
        $entry = $this->entries[$key] ?? null;
        if ($entry === null) {
            return null;
        }

        [$answer, $expiresAt] = $entry;
        if (\microtime(true) >= $expiresAt) {
            unset($this->entries[$key]);
            return null;
        }

        return $answer;
    }

    /**
     * {@inheritDoc}
     */
    public function set(string $key, DnsAnswer $answer, int $ttl): void
    {
        $this->entries[$key] = [$answer, \microtime(true) + $ttl];
    }
}
