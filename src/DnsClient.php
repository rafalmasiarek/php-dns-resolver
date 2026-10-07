<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver;

use rafalmasiarek\DnsResolver\Transport\TcpTransport;
use rafalmasiarek\DnsResolver\Transport\UdpTransport;

/**
 * From-scratch DNS client (RFC 1035) resolving over raw UDP/TCP against an
 * explicit resolver, with its own connect/read timeout.
 *
 * Does not use the system resolver (dns_get_record()/checkdnsrr() always
 * query whatever is configured in /etc/resolv.conf and have no per-call
 * timeout) — this client always targets the resolver IP given at
 * construction time.
 *
 * Sends EDNS0 (RFC 6891): an OPT pseudo-record advertising a 4096-byte UDP
 * payload size and requesting the DNSSEC OK (DO) bit, so most answers that
 * would otherwise truncate at the classic 512-byte UDP limit (large TXT/SPF
 * records, domains with many MX records) fit in a single UDP response.
 * When a response still arrives with the TC (truncated) bit set, the same
 * query is retried once over TCP.
 *
 * Message encoding/decoding lives in DnsMessageEncoder/DnsMessageDecoder
 * (pure, socket-free); the wire transport lives in Transport\UdpTransport/
 * TcpTransport. This class owns only the per-type public API, the
 * UDP-then-TCP-on-truncation orchestration, and the concurrent batch path.
 *
 * @package rafalmasiarek\DnsResolver
 */
final class DnsClient implements DnsResolverInterface
{
    /** @var int DNS record type A (host address). */
    private const TYPE_A = 1;

    /** @var int DNS record type MX (mail exchanger). */
    private const TYPE_MX = 15;

    /** @var int DNS record type TXT (text). */
    private const TYPE_TXT = 16;

    /** @var int DNS record type AAAA (IPv6 host address). */
    private const TYPE_AAAA = 28;

    /** @var int DNS record type PTR (reverse-lookup pointer). */
    private const TYPE_PTR = 12;

    /** @var int Maximum UDP response size accepted — matches the EDNS0 payload size advertised.
     *            Duplicated from Transport\UdpTransport: resolveManyA() manages its own
     *            non-blocking sockets directly (concurrent across many hostnames via a
     *            single stream_select() loop) rather than delegating to that transport. */
    private const MAX_UDP_RESPONSE_BYTES = 4096;

    private readonly UdpTransport $udpTransport;
    private readonly TcpTransport $tcpTransport;

    /**
     * @param string $resolver Resolver IP address to query.
     * @param int $port Resolver port.
     * @param float $timeout Socket connect + read timeout, in seconds.
     */
    public function __construct(
        private readonly string $resolver,
        private readonly int    $port,
        private readonly float  $timeout,
    ) {
        $this->udpTransport = new UdpTransport($resolver, $port, $timeout);
        $this->tcpTransport = new TcpTransport($resolver, $port, $timeout);
    }

    /**
     * Returns a clone of this client with a different timeout — used by
     * FailoverDnsClient to shrink the per-attempt timeout to whatever budget
     * remains under a total-timeout cap, without affecting this instance.
     *
     * @param float $timeout
     *
     * @return self
     */
    public function withTimeout(float $timeout): self
    {
        return new self($this->resolver, $this->port, $timeout);
    }

    /**
     * Resolves the A records for a hostname.
     *
     * @param string $hostname Fully-qualified hostname to query.
     *
     * @throws DnsTimeoutException When no response arrives within the timeout.
     * @throws DnsQueryException On socket failure or a malformed/non-NXDOMAIN error response.
     *
     * @return DnsAnswer
     */
    public function resolveA(string $hostname): DnsAnswer
    {
        return $this->query($hostname, self::TYPE_A);
    }

    /**
     * Resolves the AAAA records for a hostname.
     *
     * @param string $hostname Fully-qualified hostname to query.
     *
     * @throws DnsTimeoutException When no response arrives within the timeout.
     * @throws DnsQueryException On socket failure or a malformed/non-NXDOMAIN error response.
     *
     * @return DnsAnswer
     */
    public function resolveAAAA(string $hostname): DnsAnswer
    {
        return $this->query($hostname, self::TYPE_AAAA);
    }

    /**
     * Resolves the MX records for a domain.
     *
     * @param string $hostname Fully-qualified domain to query.
     *
     * @throws DnsTimeoutException When no response arrives within the timeout.
     * @throws DnsQueryException On socket failure or a malformed/non-NXDOMAIN error response.
     *
     * @return DnsAnswer Records are mail exchanger hostnames, ordered by ascending preference.
     */
    public function resolveMx(string $hostname): DnsAnswer
    {
        return $this->query($hostname, self::TYPE_MX);
    }

    /**
     * Resolves the TXT records for a hostname.
     *
     * @param string $hostname Fully-qualified hostname to query.
     *
     * @throws DnsTimeoutException When no response arrives within the timeout.
     * @throws DnsQueryException On socket failure or a malformed/non-NXDOMAIN error response.
     *
     * @return DnsAnswer Each record is one TXT record's full text.
     */
    public function resolveTxt(string $hostname): DnsAnswer
    {
        return $this->query($hostname, self::TYPE_TXT);
    }

    /**
     * Resolves the PTR (reverse DNS) record for an IPv4 or IPv6 address.
     *
     * @param string $ip IPv4 or IPv6 address.
     *
     * @throws \InvalidArgumentException When $ip is not a valid IPv4 or IPv6 address.
     * @throws DnsTimeoutException When no response arrives within the timeout.
     * @throws DnsQueryException On socket failure or a malformed/non-NXDOMAIN error response.
     *
     * @return DnsAnswer Records are hostnames, not addresses. Empty on NXDOMAIN.
     */
    public function resolvePtr(string $ip): DnsAnswer
    {
        return $this->query(self::reverseDnsName($ip), self::TYPE_PTR);
    }

    /**
     * Builds the in-addr.arpa (IPv4) or ip6.arpa (IPv6) query name for an address.
     *
     * @param string $ip IPv4 or IPv6 address.
     *
     * @throws \InvalidArgumentException When $ip is not a valid IPv4 or IPv6 address.
     *
     * @return string
     */
    private static function reverseDnsName(string $ip): string
    {
        if (\filter_var($ip, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4) !== false) {
            return \implode('.', \array_reverse(\explode('.', $ip))) . '.in-addr.arpa';
        }

        $packed = @\inet_pton($ip);
        if ($packed === false) {
            throw new \InvalidArgumentException("Invalid IP address: {$ip}");
        }

        $nibbles = \str_split(\bin2hex($packed));
        return \implode('.', \array_reverse($nibbles)) . '.ip6.arpa';
    }

    /**
     * Resolves the best available address for a hostname, always trying A first
     * then AAAA — this single resolver has no notion of family preference; that
     * policy lives in FailoverDnsClient, which queries this method's two siblings
     * directly instead of calling this one.
     *
     * @param string $hostname Fully-qualified hostname to query.
     *
     * @throws DnsTimeoutException When no response arrives within the timeout.
     * @throws DnsQueryException On socket failure or a malformed/non-NXDOMAIN error response.
     *
     * @return DnsAnswer
     */
    public function resolve(string $hostname): DnsAnswer
    {
        $answer = $this->resolveA($hostname);
        return $answer->records !== [] ? $answer : $this->resolveAAAA($hostname);
    }

    /**
     * Resolves the A records for several hostnames concurrently: one UDP socket
     * per hostname (duplicates collapsed first), all queries sent immediately,
     * then a single stream_select() loop collects whichever responses arrive
     * first — so the total wait is bounded by the slowest single query (up to
     * $this->timeout) rather than the sum of every query's own timeout.
     *
     * No TCP-truncation fallback here — A-record responses for the handful of
     * addresses a single query returns do not truncate in practice, and adding
     * a second, sequential TCP round-trip per truncated host would defeat the
     * point of resolving concurrently.
     *
     * @param list<string> $hostnames Fully-qualified hostnames to query.
     *
     * @return array<string, DnsAnswer|DnsQueryException> Keyed by hostname.
     */
    public function resolveManyA(array $hostnames): array
    {
        $unique = \array_values(\array_unique($hostnames));
        if ($unique === []) {
            return [];
        }

        /** @var array<int, array{hostname: string, id: int, socket: resource}> $pending */
        $pending = [];
        $results = [];

        foreach ($unique as $hostname) {
            $id = \random_int(0, 0xFFFF);
            $query = DnsMessageEncoder::buildQuery($hostname, $id, self::TYPE_A);

            $socket = @\stream_socket_client(
                "udp://{$this->resolver}:{$this->port}",
                $errno,
                $errstr,
                $this->timeout,
                \STREAM_CLIENT_CONNECT
            );

            if ($socket === false) {
                $results[$hostname] = new DnsQueryException(
                    "Unable to connect to resolver {$this->resolver}:{$this->port}: {$errstr}"
                );
                continue;
            }

            \stream_set_blocking($socket, false);

            if (@\fwrite($socket, $query) === false) {
                $results[$hostname] = new DnsQueryException(
                    "Unable to send DNS query to {$this->resolver}:{$this->port}"
                );
                \fclose($socket);
                continue;
            }

            $pending[] = ['hostname' => $hostname, 'id' => $id, 'socket' => $socket];
        }

        $deadline = \microtime(true) + $this->timeout;

        while ($pending !== []) {
            $remaining = $deadline - \microtime(true);
            if ($remaining <= 0) {
                break;
            }

            $read = \array_map(static fn(array $item) => $item['socket'], $pending);
            $write = null;
            $except = null;
            $sec = (int) $remaining;
            $usec = (int) (($remaining - $sec) * 1_000_000);

            $changed = @\stream_select($read, $write, $except, $sec, $usec);

            if ($changed === false || $changed === 0) {
                break;
            }

            foreach ($pending as $key => $item) {
                if (!\in_array($item['socket'], $read, true)) {
                    continue;
                }

                unset($pending[$key]);

                $response = @\fread($item['socket'], self::MAX_UDP_RESPONSE_BYTES);
                \fclose($item['socket']);

                if ($response === false || $response === '') {
                    $results[$item['hostname']] = new DnsQueryException(
                        "Empty response from resolver {$this->resolver}:{$this->port}"
                    );
                    continue;
                }

                try {
                    $results[$item['hostname']] = DnsMessageDecoder::decode($response, $item['id'], self::TYPE_A);
                } catch (DnsQueryException $e) {
                    $results[$item['hostname']] = $e;
                }
            }
        }

        foreach ($pending as $item) {
            \fclose($item['socket']);
            $results[$item['hostname']] = new DnsTimeoutException(
                "DNS query to {$this->resolver}:{$this->port} timed out after {$this->timeout}s"
            );
        }

        return $results;
    }

    /**
     * Sends a single-question query of the given type over UDP, retrying once
     * over TCP if the UDP response comes back truncated, and parses the result.
     *
     * @param string $hostname Fully-qualified hostname to query.
     * @param int $type DNS record type.
     *
     * @throws DnsTimeoutException When no response arrives within the timeout.
     * @throws DnsQueryException On socket failure or a malformed/non-NXDOMAIN error response.
     *
     * @return DnsAnswer
     */
    private function query(string $hostname, int $type): DnsAnswer
    {
        $id = \random_int(0, 0xFFFF);
        $query = DnsMessageEncoder::buildQuery($hostname, $id, $type);

        $response = $this->udpTransport->send($query);

        if (DnsMessageDecoder::isTruncated($response)) {
            $response = $this->tcpTransport->send($query);
        }

        return DnsMessageDecoder::decode($response, $id, $type);
    }
}
