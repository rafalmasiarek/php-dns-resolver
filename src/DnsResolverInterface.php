<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver;

/**
 * Resolves DNS records for a hostname.
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
     * Resolves the MX records for a domain.
     *
     * @param  string $hostname Fully-qualified domain to query.
     * @return DnsAnswer Records are mail exchanger hostnames, ordered by ascending preference
     *                    (lowest/most-preferred first).
     * @throws DnsQueryException When the query cannot be completed.
     */
    public function resolveMx(string $hostname): DnsAnswer;

    /**
     * Resolves the TXT records for a hostname.
     *
     * @param  string $hostname Fully-qualified hostname to query.
     * @return DnsAnswer Each record is one TXT record's full text (its character-strings
     *                    concatenated, per convention).
     * @throws DnsQueryException When the query cannot be completed.
     */
    public function resolveTxt(string $hostname): DnsAnswer;

    /**
     * Resolves the PTR (reverse DNS) record for an IPv4 or IPv6 address.
     *
     * @param  string $ip IPv4 or IPv6 address.
     * @return DnsAnswer Records are hostnames, not addresses. Empty on NXDOMAIN.
     * @throws \InvalidArgumentException When $ip is not a valid IPv4 or IPv6 address.
     * @throws DnsQueryException When the query cannot be completed.
     */
    public function resolvePtr(string $ip): DnsAnswer;

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

    /**
     * Resolves the A records for several hostnames concurrently instead of one
     * at a time, so the total wait is bounded by the slowest single query
     * rather than the sum of all of them. Duplicate hostnames are queried once.
     *
     * @param list<string> $hostnames Fully-qualified hostnames to query.
     *
     * @return array<string, DnsAnswer|DnsQueryException> Keyed by hostname. Each value is
     *                                                    either a successful DnsAnswer or the
     *                                                    DnsQueryException/DnsTimeoutException
     *                                                    that occurred for that hostname —
     *                                                    one host's failure never affects
     *                                                    another's result.
     */
    public function resolveManyA(array $hostnames): array;
}
