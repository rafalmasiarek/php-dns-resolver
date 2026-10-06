<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver;

/**
 * Resolves A/AAAA records via PHP's own system resolver (dns_get_record()).
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
