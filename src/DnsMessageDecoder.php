<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver;

/**
 * Parses binary DNS response packets (RFC 1035 §4.1.1-4.1.4) into a DnsAnswer.
 * Pure, side-effect-free — no sockets, so testable without a transport.
 *
 * Every field read from the packet is bounds-checked against the packet's
 * actual remaining length before use. A malformed or truncated packet always
 * throws DnsQueryException rather than being silently treated as partially
 * valid — e.g. an answer record whose declared RDLENGTH would read past the
 * end of the packet, or a TXT character-string whose declared length would
 * do the same, is rejected outright instead of returning truncated data.
 *
 * @package rafalmasiarek\DnsResolver
 */
final class DnsMessageDecoder
{
    /** @var int DNS record type A (host address). */
    private const TYPE_A = 1;

    /** @var int DNS record type SOA, read only as part of the authority-section scan. */
    private const TYPE_SOA = 6;

    /** @var int DNS record type MX (mail exchanger). */
    private const TYPE_MX = 15;

    /** @var int DNS record type TXT (text). */
    private const TYPE_TXT = 16;

    /** @var int DNS record type AAAA (IPv6 host address). */
    private const TYPE_AAAA = 28;

    /** @var int DNS record type PTR (reverse-lookup pointer). */
    private const TYPE_PTR = 12;

    /** @var int Bitmask for the TC (Truncated) flag within the 16-bit flags word. */
    private const FLAG_TC = 0x0200;

    /** @var int Bitmask for the AD (Authenticated Data) flag within the 16-bit flags word. */
    private const FLAG_AD = 0x0020;

    /** @var int Maximum total decoded domain name length in bytes (RFC 1035 §3.1), enforced
     *            while walking (possibly compressed) names to bound both memory and the
     *            number of labels a single name can assemble. */
    private const MAX_DECODED_NAME_LENGTH = 255;

    /**
     * Whether a raw response packet has the TC (truncated) flag set.
     *
     * @param string $data
     *
     * @return bool
     */
    public static function isTruncated(string $data): bool
    {
        if (\strlen($data) < 4) {
            return false;
        }
        $flags = \unpack('n', \substr($data, 2, 2))[1];
        return ($flags & self::FLAG_TC) !== 0;
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
    public static function decode(string $data, int $expectedId, int $type): DnsAnswer
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
            self::decodeName($data, $offset);
            if ($offset + 4 > \strlen($data)) {
                throw new DnsQueryException('DNS question section extends past end of packet');
            }
            $offset += 4; // QTYPE + QCLASS
        }

        $rcode = $flags & 0x000F;

        if ($rcode === 3) {
            // NXDOMAIN: not listed. A legitimate, successful result. The negative-caching
            // TTL comes from the authority section's SOA record (RFC 2308), when present.
            return new DnsAnswer([], self::findSoaTtl($data, $offset, $nscount), $authenticatedData);
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
            self::decodeName($data, $offset);

            if ($offset + 10 > \strlen($data)) {
                throw new DnsQueryException('Answer record header extends past end of packet');
            }
            $meta = \unpack('ntype/nclass/Nttl/nrdlength', \substr($data, $offset, 10));
            if ($meta === false) {
                throw new DnsQueryException('Malformed answer record header');
            }
            $offset += 10;

            if ($offset + $meta['rdlength'] > \strlen($data)) {
                throw new DnsQueryException('Answer record RDATA extends past end of packet');
            }
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
                $name = self::decodeName($data, $nameOffset);
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
                $exchange = self::decodeName($data, $nameOffset);
                if ($exchange !== '') {
                    $mxEntries[] = [$preference, $exchange];
                    $ttl = $ttlSet ? \min($ttl, $meta['ttl']) : $meta['ttl'];
                    $ttlSet = true;
                }
            } elseif ($type === self::TYPE_TXT) {
                $text = self::decodeCharacterStrings($rdata);
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
     * @throws DnsQueryException When a character-string's declared length extends past
     *                           the end of $rdata — a malformed record is rejected
     *                           outright rather than silently returning truncated text.
     *
     * @return string
     */
    private static function decodeCharacterStrings(string $rdata): string
    {
        $text = '';
        $cursor = 0;
        $len = \strlen($rdata);

        while ($cursor < $len) {
            $chunkLength = \ord($rdata[$cursor]);
            $cursor++;

            if ($cursor + $chunkLength > $len) {
                throw new DnsQueryException('TXT record character-string length extends past end of RDATA');
            }

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
     * @throws DnsQueryException On a malformed authority record header or RDATA extending
     *                           past the end of the packet.
     *
     * @return int The SOA record's TTL, or 0 when no SOA record is present.
     */
    private static function findSoaTtl(string $data, int $offset, int $nscount): int
    {
        for ($i = 0; $i < $nscount; $i++) {
            self::decodeName($data, $offset);

            if ($offset + 10 > \strlen($data)) {
                throw new DnsQueryException('Authority record header extends past end of packet');
            }
            $meta = \unpack('ntype/nclass/Nttl/nrdlength', \substr($data, $offset, 10));
            if ($meta === false) {
                throw new DnsQueryException('Malformed authority record header');
            }

            if ($offset + 10 + $meta['rdlength'] > \strlen($data)) {
                throw new DnsQueryException('Authority record RDATA extends past end of packet');
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
     * @throws DnsQueryException On a truncated name, a compression pointer loop, or a
     *                           decoded name exceeding 255 bytes (RFC 1035 §3.1) — the
     *                           pointer-loop guard alone bounds the number of jumps to the
     *                           packet size, but not the total assembled name length.
     *
     * @return string Decoded, dot-separated domain name.
     */
    public static function decodeName(string $data, int &$offset): string
    {
        $labels = [];
        $seenPointers = [];
        $cursor = $offset;
        $jumped = false;
        $totalLength = 0;

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

            if ($cursor + 1 + $length > \strlen($data)) {
                throw new DnsQueryException('Truncated domain name label in DNS response');
            }

            $totalLength += 1 + $length;
            if ($totalLength > self::MAX_DECODED_NAME_LENGTH) {
                throw new DnsQueryException('Decoded DNS name exceeds ' . self::MAX_DECODED_NAME_LENGTH . ' bytes');
            }

            $labels[] = \substr($data, $cursor + 1, $length);
            $cursor += 1 + $length;
        }

        return \implode('.', $labels);
    }
}
