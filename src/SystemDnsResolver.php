<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver;

/**
 * Resolves A/AAAA/MX/TXT/PTR records via PHP's own system resolver
 * (dns_get_record(), gethostbyaddr() for PTR).
 *
 * Pins nothing: no explicit nameserver, no custom timeout — whatever the host's
 * resolv.conf and PHP's default DNS timeout behavior already do. This is the
 * baseline DnsResolverInterface implementation; an app that needs an explicit
 * nameserver, a bounded timeout, or failover should provide its own.
 *
 * dns_get_record() has no access to the raw response header, so
 * DnsAnswer::$authenticatedData is always false here — this resolver cannot
 * observe whether the system resolver validated DNSSEC.
 *
 * @package rafalmasiarek\DnsResolver
 */
final class SystemDnsResolver implements DnsResolverInterface
{
    /**
     * @param bool $preferIpv6 When true, resolve() tries AAAA before A; otherwise A before AAAA.
     */
    public function __construct(
        private readonly bool $preferIpv6 = false,
    ) {
    }

    /**
     * Resolves the A records for a hostname via the system resolver.
     *
     * @param  string $hostname Fully-qualified hostname to query.
     * @return DnsAnswer
     * @throws DnsQueryException When the system resolver reports a lookup failure.
     */
    public function resolveA(string $hostname): DnsAnswer
    {
        return $this->query($hostname, \DNS_A, 'A');
    }

    /**
     * Resolves the AAAA records for a hostname via the system resolver.
     *
     * @param  string $hostname Fully-qualified hostname to query.
     * @return DnsAnswer
     * @throws DnsQueryException When the system resolver reports a lookup failure.
     */
    public function resolveAAAA(string $hostname): DnsAnswer
    {
        return $this->query($hostname, \DNS_AAAA, 'AAAA');
    }

    /**
     * Resolves the MX records for a domain via the system resolver.
     *
     * @param  string $hostname Fully-qualified domain to query.
     * @return DnsAnswer Records are mail exchanger hostnames, ordered by ascending preference.
     * @throws DnsQueryException When the system resolver reports a lookup failure.
     */
    public function resolveMx(string $hostname): DnsAnswer
    {
        $records = @\dns_get_record($hostname, \DNS_MX);
        if ($records === false) {
            throw new DnsQueryException("System resolver failed to query MX records for \"{$hostname}\".");
        }

        $entries = [];
        foreach ($records as $record) {
            if (($record['type'] ?? null) !== 'MX' || !isset($record['target'])) {
                continue;
            }
            $entries[] = [(int) ($record['pri'] ?? 0), (string) $record['target']];
        }

        \usort($entries, static fn(array $a, array $b): int => $a[0] <=> $b[0]);

        return new DnsAnswer(\array_column($entries, 1), 0);
    }

    /**
     * Resolves the TXT records for a hostname via the system resolver.
     *
     * @param  string $hostname Fully-qualified hostname to query.
     * @return DnsAnswer Each record is one TXT record's full text.
     * @throws DnsQueryException When the system resolver reports a lookup failure.
     */
    public function resolveTxt(string $hostname): DnsAnswer
    {
        $records = @\dns_get_record($hostname, \DNS_TXT);
        if ($records === false) {
            throw new DnsQueryException("System resolver failed to query TXT records for \"{$hostname}\".");
        }

        $texts = [];
        foreach ($records as $record) {
            if (($record['type'] ?? null) !== 'TXT' || !isset($record['txt'])) {
                continue;
            }
            $texts[] = (string) $record['txt'];
        }

        return new DnsAnswer($texts, 0);
    }

    /**
     * Resolves the PTR (reverse DNS) record for an IP address via the system resolver.
     *
     * @param  string $ip IPv4 or IPv6 address.
     * @return DnsAnswer Records are hostnames, not addresses.
     * @throws \InvalidArgumentException When $ip is not a valid IPv4 or IPv6 address.
     * @throws DnsQueryException When the system resolver reports a lookup failure.
     */
    public function resolvePtr(string $ip): DnsAnswer
    {
        if (\filter_var($ip, \FILTER_VALIDATE_IP) === false) {
            throw new \InvalidArgumentException("Invalid IP address: {$ip}");
        }

        $hostname = @\gethostbyaddr($ip);
        if ($hostname === false || $hostname === $ip) {
            return new DnsAnswer([], 0);
        }

        return new DnsAnswer([$hostname], 0);
    }

    /**
     * Resolves the A records for several hostnames, one at a time via the system
     * resolver — dns_get_record() has no concurrent-query mode, unlike DnsClient's
     * raw-socket resolveManyA(). Provided so SystemDnsResolver stays a drop-in
     * DnsResolverInterface implementation; prefer DnsClient/FailoverDnsClient
     * when resolveManyA()'s concurrency is actually needed.
     *
     * @param list<string> $hostnames Fully-qualified hostnames to query.
     *
     * @return array<string, DnsAnswer|DnsQueryException> Keyed by hostname.
     */
    public function resolveManyA(array $hostnames): array
    {
        $results = [];
        foreach (\array_unique($hostnames) as $hostname) {
            try {
                $results[$hostname] = $this->resolveA($hostname);
            } catch (DnsQueryException $e) {
                $results[$hostname] = $e;
            }
        }
        return $results;
    }

    /**
     * @param  string $hostname Fully-qualified hostname to query.
     * @return DnsAnswer
     * @throws DnsQueryException When both address families fail to resolve.
     */
    public function resolve(string $hostname): DnsAnswer
    {
        $order = $this->preferIpv6
            ? [[\DNS_AAAA, 'AAAA'], [\DNS_A, 'A']]
            : [[\DNS_A, 'A'], [\DNS_AAAA, 'AAAA']];

        $lastError = null;
        $lastEmpty = null;

        foreach ($order as [$type, $label]) {
            try {
                $answer = $this->query($hostname, $type, $label);
            } catch (DnsQueryException $e) {
                $lastError = $e;
                continue;
            }

            if ($answer->records !== []) {
                return $answer;
            }
            $lastEmpty = $answer;
        }

        if ($lastEmpty !== null) {
            return $lastEmpty;
        }

        throw new DnsQueryException(
            "System resolver failed to query A/AAAA records for \"{$hostname}\".",
            0,
            $lastError
        );
    }

    /**
     * @param  string $hostname Fully-qualified hostname to query.
     * @param  int    $type     DNS_A or DNS_AAAA.
     * @param  string $label    'A' or 'AAAA', matching dns_get_record()'s record 'type' field.
     * @return DnsAnswer
     * @throws DnsQueryException When the system resolver reports a lookup failure.
     */
    private function query(string $hostname, int $type, string $label): DnsAnswer
    {
        $records = @\dns_get_record($hostname, $type);

        if ($records === false) {
            throw new DnsQueryException("System resolver failed to query {$label} records for \"{$hostname}\".");
        }

        $addresses = [];
        $ttl = 0;
        $ttlSet = false;
        $ipField = $label === 'AAAA' ? 'ipv6' : 'ip';

        foreach ($records as $record) {
            if (($record['type'] ?? null) !== $label || !isset($record[$ipField])) {
                continue;
            }
            $addresses[] = (string) $record[$ipField];
            $recordTtl = (int) ($record['ttl'] ?? 0);
            $ttl = $ttlSet ? \min($ttl, $recordTtl) : $recordTtl;
            $ttlSet = true;
        }

        return new DnsAnswer($addresses, $ttlSet ? $ttl : 0);
    }
}
