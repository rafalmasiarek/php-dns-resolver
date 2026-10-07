<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Queries a list of resolvers in order, falling over to the next one when a
 * query fails (timeout or socket error).
 *
 * All resolvers are treated as equal peers — there is no primary/secondary
 * distinction, just an ordered attempt list. Existing NXDOMAIN/success
 * responses are never retried against another resolver, only failed queries.
 *
 * $totalTimeout, when set, bounds the sum of every resolver attempt for a
 * single call: each attempt's own timeout is shrunk to whatever budget
 * remains (via DnsClient::withTimeout()), so the call as a whole cannot run
 * longer than $totalTimeout even across multiple resolver attempts. Only
 * applies to the single-hostname methods below (A/AAAA/MX/TXT/PTR/resolve);
 * resolveManyA() runs its own parallel batch per resolver and is unaffected.
 *
 * @package rafalmasiarek\DnsResolver
 */
final class FailoverDnsClient implements DnsResolverInterface
{
    /** @var list<string> Resolver IP addresses, in attempt order — kept alongside for logging. */
    private readonly array $resolverLabels;

    /** @var list<DnsClient> One DnsClient per configured resolver, in attempt order. */
    private readonly array $clients;

    /** @var LoggerInterface Logger for per-attempt failures and, when audit is true, every attempt. */
    private readonly LoggerInterface $logger;

    /**
     * @param list<string> $resolvers Resolver IP addresses, in attempt order.
     * @param int $port Resolver port, shared by all resolvers.
     * @param float $timeout Per-attempt timeout, in seconds.
     * @param bool $preferIpv6 When true, resolve() tries AAAA before A; otherwise A before AAAA.
     * @param LoggerInterface|null $logger Receives failure warnings/errors always, and (when
     *                                     $audit is true) a debug entry for every successful attempt.
     *                                     Defaults to a no-op logger when omitted.
     * @param bool $audit When true, logs a debug entry for every successful attempt (host, record
     *                    type, resolver used, duration, result). Failures are always logged
     *                    regardless of this flag.
     * @param float|null $totalTimeout Bounds the sum of every resolver attempt for a single call,
     *                                 in seconds. Null (default) disables the budget — each
     *                                 resolver always gets its full $timeout.
     *
     * @throws \InvalidArgumentException When $resolvers is empty.
     */
    public function __construct(
        array $resolvers,
        int $port,
        private readonly float $timeout,
        private readonly bool $preferIpv6 = false,
        ?LoggerInterface $logger = null,
        private readonly bool $audit = false,
        private readonly ?float $totalTimeout = null,
    ) {
        if ($resolvers === []) {
            throw new \InvalidArgumentException('FailoverDnsClient requires at least one resolver.');
        }

        $this->resolverLabels = \array_values($resolvers);
        $this->clients = \array_map(
            static fn(string $resolver): DnsClient => new DnsClient($resolver, $port, $timeout),
            $this->resolverLabels
        );
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * Resolves the A records for a hostname, trying each configured resolver in order.
     *
     * @param string $hostname Fully-qualified hostname to query.
     *
     * @throws DnsQueryException When every configured resolver fails.
     *
     * @return DnsAnswer
     */
    public function resolveA(string $hostname): DnsAnswer
    {
        return $this->attempt('A', $hostname, static fn(DnsClient $c): DnsAnswer => $c->resolveA($hostname));
    }

    /**
     * Resolves the AAAA records for a hostname, trying each configured resolver in order.
     *
     * @param string $hostname Fully-qualified hostname to query.
     *
     * @throws DnsQueryException When every configured resolver fails.
     *
     * @return DnsAnswer
     */
    public function resolveAAAA(string $hostname): DnsAnswer
    {
        return $this->attempt('AAAA', $hostname, static fn(DnsClient $c): DnsAnswer => $c->resolveAAAA($hostname));
    }

    /**
     * Resolves the MX records for a domain, trying each configured resolver in order.
     *
     * @param string $hostname Fully-qualified domain to query.
     *
     * @throws DnsQueryException When every configured resolver fails.
     *
     * @return DnsAnswer Records are mail exchanger hostnames, ordered by ascending preference.
     */
    public function resolveMx(string $hostname): DnsAnswer
    {
        return $this->attempt('MX', $hostname, static fn(DnsClient $c): DnsAnswer => $c->resolveMx($hostname));
    }

    /**
     * Resolves the TXT records for a hostname, trying each configured resolver in order.
     *
     * @param string $hostname Fully-qualified hostname to query.
     *
     * @throws DnsQueryException When every configured resolver fails.
     *
     * @return DnsAnswer
     */
    public function resolveTxt(string $hostname): DnsAnswer
    {
        return $this->attempt('TXT', $hostname, static fn(DnsClient $c): DnsAnswer => $c->resolveTxt($hostname));
    }

    /**
     * Resolves the PTR record for an IP address, trying each configured resolver in order.
     *
     * @param string $ip IPv4 or IPv6 address.
     *
     * @throws DnsQueryException When every configured resolver fails.
     *
     * @return DnsAnswer Records are hostnames, not addresses. Empty on NXDOMAIN.
     */
    public function resolvePtr(string $ip): DnsAnswer
    {
        return $this->attempt('PTR', $ip, static fn(DnsClient $c): DnsAnswer => $c->resolvePtr($ip));
    }

    /**
     * Resolves the best available address for a hostname: tries the preferred
     * address family across all configured resolvers first, and only falls
     * back to the other family when the preferred one yields no records.
     *
     * @param string $hostname Fully-qualified hostname to query.
     *
     * @throws DnsQueryException When neither address family can be resolved by any resolver.
     *
     * @return DnsAnswer
     */
    public function resolve(string $hostname): DnsAnswer
    {
        $order = $this->preferIpv6
            ? [fn(): DnsAnswer => $this->resolveAAAA($hostname), fn(): DnsAnswer => $this->resolveA($hostname)]
            : [fn(): DnsAnswer => $this->resolveA($hostname), fn(): DnsAnswer => $this->resolveAAAA($hostname)];

        $lastError = null;
        $lastEmpty = null;

        foreach ($order as $call) {
            try {
                $answer = $call();
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
            \sprintf('Unable to resolve either address family for "%s".', $hostname),
            0,
            $lastError
        );
    }

    /**
     * Resolves the A records for several hostnames concurrently per resolver:
     * each configured resolver gets one parallel batch attempt (see
     * DnsClient::resolveManyA()) for whatever hostnames are still unresolved,
     * so failover across resolvers only kicks in for the hostnames that
     * actually failed, not for ones that already succeeded.
     *
     * @param list<string> $hostnames Fully-qualified hostnames to query.
     *
     * @return array<string, DnsAnswer|DnsQueryException> Keyed by hostname.
     */
    public function resolveManyA(array $hostnames): array
    {
        $pending = \array_values(\array_unique($hostnames));
        $results = [];

        foreach ($this->clients as $index => $client) {
            if ($pending === []) {
                break;
            }

            $resolver = $this->resolverLabels[$index];
            $t0 = \microtime(true);
            $batch = $client->resolveManyA($pending);
            $batchMs = \round((\microtime(true) - $t0) * 1000, 2);

            $stillPending = [];

            foreach ($pending as $hostname) {
                $answer = $batch[$hostname] ?? new DnsQueryException("No result returned for \"{$hostname}\".");

                if ($answer instanceof DnsQueryException) {
                    $stillPending[] = $hostname;
                    $this->logger->warning('dns.resolve.failed', [
                        'host'     => $hostname,
                        'type'     => 'A',
                        'resolver' => $resolver,
                        'error'    => $answer->getMessage(),
                    ]);
                    continue;
                }

                $results[$hostname] = $answer;

                if ($this->audit) {
                    $this->logger->debug('dns.resolve.ok', [
                        'host'          => $hostname,
                        'type'          => 'A',
                        'resolver'      => $resolver,
                        'batch_ms'      => $batchMs,
                        'records'       => \count($answer->records),
                        'ttl'           => $answer->ttl,
                        'authenticated' => $answer->authenticatedData,
                    ]);
                }
            }

            $pending = $stillPending;
        }

        foreach ($pending as $hostname) {
            $results[$hostname] = new DnsQueryException(
                \sprintf('All %d configured resolver(s) failed for "%s".', \count($this->clients), $hostname)
            );
            $this->logger->error('dns.resolve.exhausted', [
                'host'      => $hostname,
                'type'      => 'A',
                'resolvers' => \count($this->clients),
            ]);
        }

        return $results;
    }

    /**
     * Runs $call against each configured resolver in order, logging failures
     * (always) and successes (only in audit mode), until one succeeds or the
     * total-timeout budget (when configured) is exhausted.
     *
     * @param string $type 'A', 'AAAA', 'MX', 'TXT', or 'PTR' — for log context only.
     * @param string $hostname Fully-qualified hostname to query.
     * @param callable(DnsClient): DnsAnswer $call
     *
     * @throws DnsQueryException When every configured resolver fails, or the total-timeout
     *                           budget is exhausted before any resolver is tried.
     *
     * @return DnsAnswer
     */
    private function attempt(string $type, string $hostname, callable $call): DnsAnswer
    {
        $lastError = null;
        $deadline = $this->totalTimeout !== null ? \microtime(true) + $this->totalTimeout : null;

        foreach ($this->clients as $index => $client) {
            if ($deadline !== null) {
                $remaining = $deadline - \microtime(true);
                if ($remaining <= 0) {
                    $this->logger->error('dns.resolve.budget_exhausted', [
                        'host'          => $hostname,
                        'type'          => $type,
                        'total_timeout' => $this->totalTimeout,
                    ]);
                    throw new DnsTimeoutException(
                        \sprintf('Total DNS resolution timeout (%.1fs) exhausted for "%s".', $this->totalTimeout, $hostname),
                        0,
                        $lastError
                    );
                }
                // Shrink this attempt's own timeout to whatever budget remains, so the
                // call as a whole cannot run longer than $totalTimeout even mid-attempt.
                $client = $client->withTimeout(\min($this->timeout, $remaining));
            }

            $resolver = $this->resolverLabels[$index];
            $t0 = \microtime(true);

            try {
                $answer = $call($client);
            } catch (DnsQueryException $e) {
                $lastError = $e;
                $this->logger->warning('dns.resolve.failed', [
                    'host'        => $hostname,
                    'type'        => $type,
                    'resolver'    => $resolver,
                    'duration_ms' => \round((\microtime(true) - $t0) * 1000, 2),
                    'error'       => $e->getMessage(),
                ]);
                continue;
            }

            if ($this->audit) {
                $this->logger->debug('dns.resolve.ok', [
                    'host'         => $hostname,
                    'type'         => $type,
                    'resolver'     => $resolver,
                    'duration_ms'  => \round((\microtime(true) - $t0) * 1000, 2),
                    'records'      => \count($answer->records),
                    'ttl'          => $answer->ttl,
                    'authenticated' => $answer->authenticatedData,
                ]);
            }

            return $answer;
        }

        $this->logger->error('dns.resolve.exhausted', [
            'host'      => $hostname,
            'type'      => $type,
            'resolvers' => \count($this->clients),
        ]);

        throw new DnsQueryException(
            \sprintf('All %d configured resolver(s) failed for "%s".', \count($this->clients), $hostname),
            0,
            $lastError
        );
    }
}
