<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver;

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
 * @package rafalmasiarek\DnsResolver
 */
final class DnsClient implements DnsResolverInterface
{
    /** @var int DNS record type A (host address). */
    private const TYPE_A = 1;

    /** @var int DNS record type NS, read only as part of the authority-section SOA scan. */
    private const TYPE_SOA = 6;

    /** @var int DNS record type MX (mail exchanger). */
    private const TYPE_MX = 15;

    /** @var int DNS record type TXT (text). */
    private const TYPE_TXT = 16;

    /** @var int DNS record type AAAA (IPv6 host address). */
    private const TYPE_AAAA = 28;

    /** @var int DNS record type PTR (reverse-lookup pointer). */
    private const TYPE_PTR = 12;

    /** @var int DNS record type OPT (EDNS0 pseudo-record). */
    private const TYPE_OPT = 41;

    /** @var int DNS class IN (internet). */
    private const CLASS_IN = 1;

    /** @var int UDP payload size advertised via EDNS0. */
    private const EDNS0_UDP_PAYLOAD_SIZE = 4096;

    /** @var int Maximum UDP response size accepted — matches the EDNS0 payload size advertised. */
    private const MAX_UDP_RESPONSE_BYTES = 4096;

    /** @var int Maximum TCP response size accepted (the 2-byte length prefix's own ceiling). */
    private const MAX_TCP_RESPONSE_BYTES = 65535;

    /** @var int Bitmask for the TC (Truncated) flag within the 16-bit flags word. */
    private const FLAG_TC = 0x0200;

    /** @var int Bitmask for the AD (Authenticated Data) flag within the 16-bit flags word. */
    private const FLAG_AD = 0x0020;

    /**
     * @param string $resolver Resolver IP address to query.
     * @param int $port Resolver port.
     * @param float $timeout Socket connect + read timeout, in seconds.
     */
    public function __construct(
        private readonly string $resolver,
        private readonly int    $port,
        private readonly float  $timeout,
    ) {}

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
            $query = $this->buildQuery($hostname, $id, self::TYPE_A);

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
                    $results[$item['hostname']] = $this->parseResponse($response, $item['id'], self::TYPE_A);
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
        $query = $this->buildQuery($hostname, $id, $type);

        $response = $this->sendUdp($query);

        if ($this->isTruncated($response)) {
            $response = $this->sendTcp($query);
        }

        return $this->parseResponse($response, $id, $type);
    }

    /**
     * Sends a query over UDP and returns the raw response.
     *
     * @param string $query Binary DNS query packet.
     *
     * @throws DnsTimeoutException When no response arrives within the timeout.
     * @throws DnsQueryException On socket failure.
     *
     * @return string
     */
    private function sendUdp(string $query): string
    {
        $socket = @\stream_socket_client(
            "udp://{$this->resolver}:{$this->port}",
            $errno,
            $errstr,
            $this->timeout,
            \STREAM_CLIENT_CONNECT
        );

        if ($socket === false) {
            throw new DnsQueryException("Unable to connect to resolver {$this->resolver}:{$this->port}: {$errstr}");
        }

        try {
            \stream_set_timeout($socket, (int) $this->timeout, (int) (\fmod($this->timeout, 1.0) * 1_000_000));

            if (@\fwrite($socket, $query) === false) {
                throw new DnsQueryException("Unable to send DNS query to {$this->resolver}:{$this->port}");
            }

            $response = @\fread($socket, self::MAX_UDP_RESPONSE_BYTES);
            $meta = \stream_get_meta_data($socket);

            if ($meta['timed_out']) {
                throw new DnsTimeoutException("DNS query to {$this->resolver}:{$this->port} timed out after {$this->timeout}s");
            }

            if ($response === false || $response === '') {
                throw new DnsQueryException("Empty response from resolver {$this->resolver}:{$this->port}");
            }
        } finally {
            \fclose($socket);
        }

        return $response;
    }

    /**
     * Sends a query over TCP (2-byte length prefix framing, RFC 1035 §4.2.2)
     * and returns the raw response, for when the UDP response was truncated.
     *
     * @param string $query Binary DNS query packet.
     *
     * @throws DnsTimeoutException When no response arrives within the timeout.
     * @throws DnsQueryException On socket failure.
     *
     * @return string
     */
    private function sendTcp(string $query): string
    {
        $socket = @\stream_socket_client(
            "tcp://{$this->resolver}:{$this->port}",
            $errno,
            $errstr,
            $this->timeout,
            \STREAM_CLIENT_CONNECT
        );

        if ($socket === false) {
            throw new DnsQueryException("Unable to connect to resolver {$this->resolver}:{$this->port} over TCP: {$errstr}");
        }

        try {
            \stream_set_timeout($socket, (int) $this->timeout, (int) (\fmod($this->timeout, 1.0) * 1_000_000));

            $framed = \pack('n', \strlen($query)) . $query;
            if (@\fwrite($socket, $framed) === false) {
                throw new DnsQueryException("Unable to send DNS query to {$this->resolver}:{$this->port} over TCP");
            }

            $lengthPrefix = $this->readExactly($socket, 2);
            $meta = \stream_get_meta_data($socket);
            if ($meta['timed_out']) {
                throw new DnsTimeoutException("DNS query to {$this->resolver}:{$this->port} over TCP timed out after {$this->timeout}s");
            }

            $length = \unpack('n', $lengthPrefix)[1];
            $response = $this->readExactly($socket, \min($length, self::MAX_TCP_RESPONSE_BYTES));

            $meta = \stream_get_meta_data($socket);
            if ($meta['timed_out']) {
                throw new DnsTimeoutException("DNS query to {$this->resolver}:{$this->port} over TCP timed out after {$this->timeout}s");
            }
        } finally {
            \fclose($socket);
        }

        return $response;
    }

    /**
     * Reads exactly $length bytes from a TCP stream, looping over partial reads.
     *
     * @param resource $socket
     * @param int $length
     *
     * @throws DnsQueryException When the connection closes before $length bytes arrive.
     *
     * @return string
     */
    private function readExactly($socket, int $length): string
    {
        $buffer = '';
        while (\strlen($buffer) < $length) {
            $chunk = @\fread($socket, $length - \strlen($buffer));
            if ($chunk === false || $chunk === '') {
                $meta = \stream_get_meta_data($socket);
                if ($meta['timed_out']) {
                    return $buffer;
                }
                throw new DnsQueryException("TCP connection to {$this->resolver}:{$this->port} closed unexpectedly");
            }
            $buffer .= $chunk;
        }
        return $buffer;
    }

    /**
     * Whether a raw response packet has the TC (truncated) flag set.
     *
     * @param string $data
     *
     * @return bool
     */
    private function isTruncated(string $data): bool
    {
        if (\strlen($data) < 4) {
            return false;
        }
        $flags = \unpack('n', \substr($data, 2, 2))[1];
        return ($flags & self::FLAG_TC) !== 0;
    }

    /**
     * Builds a single-question DNS query packet with an EDNS0 OPT pseudo-record
     * advertising a 4096-byte UDP payload size and requesting the DNSSEC OK bit.
     *
     * @param string $hostname
     * @param int $id 16-bit query identifier, echoed back in the response.
     * @param int $type DNS record type.
     *
     * @return string Binary DNS query packet.
     */
    private function buildQuery(string $hostname, int $id, int $type): string
    {
        $header = \pack(
            'nnnnnn',
            $id,
            0x0120, // RD=1 (recursion desired) + AD=1 (signals interest in a meaningful AD bit back)
            1,      // QDCOUNT
            0,      // ANCOUNT
            0,      // NSCOUNT
            1       // ARCOUNT — the EDNS0 OPT record below
        );

        $question = $this->encodeName($hostname) . \pack('nn', $type, self::CLASS_IN);
        $opt = $this->buildOptRecord();

        return $header . $question . $opt;
    }

    /**
     * Builds the EDNS0 OPT pseudo-record (RFC 6891): root name, TYPE=OPT,
     * CLASS=advertised UDP payload size, TTL carries ext-RCODE(0)+version(0)+
     * flags (DO bit set, requesting DNSSEC OK), empty RDATA.
     *
     * @return string
     */
    private function buildOptRecord(): string
    {
        return "\x00"
            . \pack('n', self::TYPE_OPT)
            . \pack('n', self::EDNS0_UDP_PAYLOAD_SIZE)
            . \pack('N', 0x00008000) // ext-rcode=0, version=0, flags: DO=1
            . \pack('n', 0);          // RDLENGTH=0
    }

    /**
     * Encodes a hostname as a sequence of length-prefixed labels terminated by a zero byte.
     *
     * @param string $hostname
     *
     * @throws DnsQueryException When a label exceeds 63 bytes.
     *
     * @return string
     */
    private function encodeName(string $hostname): string
    {
        $encoded = '';

        foreach (\explode('.', \trim($hostname, '.')) as $label) {
            $length = \strlen($label);
            if ($length > 63) {
                throw new DnsQueryException("DNS label too long: {$label}");
            }
            $encoded .= \chr($length) . $label;
        }

        return $encoded . "\x00";
    }

    /**
     * Parses a DNS response packet and extracts records of the queried type and a cache TTL.
     *
     * @param string $data Raw response packet.
     * @param int $expectedId Query id the response must echo back.
     * @param int $type DNS record type queried; only answer records of this type are collected.
     *
     * @throws DnsQueryException On a truncated/malformed packet, id mismatch,
     *                           or an error RCODE other than NXDOMAIN (3).
     *
     * @return DnsAnswer
     */
    private function parseResponse(string $data, int $expectedId, int $type): DnsAnswer
    {
        if (\strlen($data) < 12) {
            throw new DnsQueryException('DNS response shorter than header');
        }

        [$id, $flags, $qdcount, $ancount, $nscount] = \array_values(\unpack('nid/nflags/nqdcount/nancount/nnscount/narcount', $data));

        if ($id !== $expectedId) {
            throw new DnsQueryException('DNS response id mismatch (possible spoofing or stale reply)');
        }

        $authenticatedData = ($flags & self::FLAG_AD) !== 0;

        $offset = 12;

        for ($i = 0; $i < $qdcount; $i++) {
            $this->decodeName($data, $offset);
            $offset += 4; // QTYPE + QCLASS
        }

        $rcode = $flags & 0x000F;

        if ($rcode === 3) {
            // NXDOMAIN: not listed. A legitimate, successful result. The negative-caching
            // TTL comes from the authority section's SOA record (RFC 2308), when present.
            return new DnsAnswer([], $this->findSoaTtl($data, $offset, $nscount), $authenticatedData);
        }
        if ($rcode !== 0) {
            throw new DnsQueryException("DNS response error RCODE={$rcode}");
        }

        $records = [];
        $ttl = 0;
        $ttlSet = false;
        /** @var list<array{0: int, 1: string}> $mxEntries [preference, exchange] pairs, sorted into $records after the loop. */
        $mxEntries = [];

        for ($i = 0; $i < $ancount; $i++) {
            $this->decodeName($data, $offset);

            $meta = \unpack('ntype/nclass/Nttl/nrdlength', \substr($data, $offset, 10));
            if ($meta === false) {
                throw new DnsQueryException('Malformed answer record header');
            }
            $offset += 10;

            $rdata = \substr($data, $offset, $meta['rdlength']);
            $offset += $meta['rdlength'];

            if ($meta['type'] !== $type) {
                continue;
            }

            if ($type === self::TYPE_A && \strlen($rdata) === 4) {
                $records[] = \sprintf('%d.%d.%d.%d', ...\array_values(\unpack('C4', $rdata)));
                $ttl = $ttlSet ? \min($ttl, $meta['ttl']) : $meta['ttl'];
                $ttlSet = true;
            } elseif ($type === self::TYPE_AAAA && \strlen($rdata) === 16) {
                $address = @\inet_ntop($rdata);
                if ($address !== false) {
                    $records[] = $address;
                    $ttl = $ttlSet ? \min($ttl, $meta['ttl']) : $meta['ttl'];
                    $ttlSet = true;
                }
            } elseif ($type === self::TYPE_PTR) {
                // PTR rdata is a (possibly compressed) domain name, so it must be decoded
                // against the full packet, not the already-extracted $rdata substring —
                // a compression pointer inside it is an absolute offset into $data.
                $nameOffset = $offset - $meta['rdlength'];
                $name = $this->decodeName($data, $nameOffset);
                if ($name !== '') {
                    $records[] = $name;
                    $ttl = $ttlSet ? \min($ttl, $meta['ttl']) : $meta['ttl'];
                    $ttlSet = true;
                }
            } elseif ($type === self::TYPE_MX && \strlen($rdata) >= 3) {
                $preference = \unpack('n', $rdata)[1];
                // Exchange name follows the 2-byte preference; may be compressed, so
                // decode against the full packet at its absolute offset, same as PTR above.
                $nameOffset = $offset - $meta['rdlength'] + 2;
                $exchange = $this->decodeName($data, $nameOffset);
                if ($exchange !== '') {
                    $mxEntries[] = [$preference, $exchange];
                    $ttl = $ttlSet ? \min($ttl, $meta['ttl']) : $meta['ttl'];
                    $ttlSet = true;
                }
            } elseif ($type === self::TYPE_TXT) {
                $text = $this->decodeCharacterStrings($rdata);
                $records[] = $text;
                $ttl = $ttlSet ? \min($ttl, $meta['ttl']) : $meta['ttl'];
                $ttlSet = true;
            }
        }

        if ($type === self::TYPE_MX && $mxEntries !== []) {
            \usort($mxEntries, static fn(array $a, array $b): int => $a[0] <=> $b[0]);
            $records = \array_column($mxEntries, 1);
        }

        return new DnsAnswer($records, $ttlSet ? $ttl : 0, $authenticatedData);
    }

    /**
     * Decodes a TXT record's RDATA: one or more length-prefixed character-strings,
     * concatenated into a single string per the common resolver convention.
     *
     * @param string $rdata
     *
     * @return string
     */
    private function decodeCharacterStrings(string $rdata): string
    {
        $text = '';
        $cursor = 0;
        $len = \strlen($rdata);

        while ($cursor < $len) {
            $chunkLength = \ord($rdata[$cursor]);
            $cursor++;
            $text .= \substr($rdata, $cursor, $chunkLength);
            $cursor += $chunkLength;
        }

        return $text;
    }

    /**
     * Scans the authority section for an SOA record and returns its TTL.
     *
     * @param string $data Raw response packet.
     * @param int $offset Byte offset of the authority section (past the question section).
     * @param int $nscount Number of authority records to scan.
     *
     * @throws DnsQueryException On a malformed authority record header.
     *
     * @return int The SOA record's TTL, or 0 when no SOA record is present.
     */
    private function findSoaTtl(string $data, int $offset, int $nscount): int
    {
        for ($i = 0; $i < $nscount; $i++) {
            $this->decodeName($data, $offset);

            $meta = \unpack('ntype/nclass/Nttl/nrdlength', \substr($data, $offset, 10));
            if ($meta === false) {
                throw new DnsQueryException('Malformed authority record header');
            }
            $offset += 10 + $meta['rdlength'];

            if ($meta['type'] === self::TYPE_SOA) {
                return $meta['ttl'];
            }
        }

        return 0;
    }

    /**
     * Decodes a (possibly compressed) domain name starting at $offset, advancing it past the name.
     *
     * @param string $data
     * @param int $offset Byte offset to start reading at; advanced past the encoded name.
     *
     * @throws DnsQueryException On a truncated name or a compression pointer loop.
     *
     * @return string Decoded, dot-separated domain name.
     */
    private function decodeName(string $data, int &$offset): string
    {
        $labels = [];
        $seenPointers = [];
        $cursor = $offset;
        $jumped = false;

        while (true) {
            if ($cursor >= \strlen($data)) {
                throw new DnsQueryException('Truncated domain name in DNS response');
            }

            $length = \ord($data[$cursor]);

            if ($length === 0) {
                $cursor++;
                if (!$jumped) {
                    $offset = $cursor;
                }
                break;
            }

            if (($length & 0xC0) === 0xC0) {
                if ($cursor + 1 >= \strlen($data)) {
                    throw new DnsQueryException('Truncated compression pointer in DNS response');
                }
                $pointer = (($length & 0x3F) << 8) | \ord($data[$cursor + 1]);
                if (isset($seenPointers[$pointer])) {
                    throw new DnsQueryException('DNS name compression pointer loop detected');
                }
                $seenPointers[$pointer] = true;

                if (!$jumped) {
                    $offset = $cursor + 2;
                    $jumped = true;
                }
                $cursor = $pointer;
                continue;
            }

            $labels[] = \substr($data, $cursor + 1, $length);
            $cursor += 1 + $length;
        }

        return \implode('.', $labels);
    }
}
