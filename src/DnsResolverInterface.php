<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver;

/**
 * Resolves A/AAAA records for a hostname.
 *
 * @package rafalmasiarek\DnsResolver
 */
interface DnsResolverInterface
{
    /**
     * Resolves the A records for a hostname.
     *
     * @param  string $hostname Fully-qualified hostname to query.
     * @return DnsAnswer
     * @throws DnsQueryException When the query cannot be completed.
     */
    public function resolveA(string $hostname): DnsAnswer;

    /**
     * Resolves the AAAA records for a hostname.
     *
     * @param  string $hostname Fully-qualified hostname to query.
     * @return DnsAnswer
     * @throws DnsQueryException When the query cannot be completed.
     */
    public function resolveAAAA(string $hostname): DnsAnswer;

    /**
     * Resolves the best available address for a hostname, trying IPv4 and IPv6
     * in whichever order the implementation is configured to prefer, falling
     * back to the other family when the preferred one yields no records.
     *
     * @param  string $hostname Fully-qualified hostname to query.
     * @return DnsAnswer
     * @throws DnsQueryException When neither address family can be resolved.
     */
    public function resolve(string $hostname): DnsAnswer;
}
