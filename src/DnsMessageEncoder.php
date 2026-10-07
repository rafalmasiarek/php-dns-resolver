<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver;

/**
 * Builds binary DNS query packets (RFC 1035 §4.1.1-4.1.3, EDNS0 RFC 6891).
 * Pure, side-effect-free — no sockets, so testable without a transport.
 *
 * @package rafalmasiarek\DnsResolver
 */
final class DnsMessageEncoder
{
    /** @var int DNS record type OPT (EDNS0 pseudo-record). */
    private const TYPE_OPT = 41;

    /** @var int DNS class IN (internet). */
    private const CLASS_IN = 1;

    /** @var int UDP payload size advertised via EDNS0. */
    private const EDNS0_UDP_PAYLOAD_SIZE = 4096;

    /** @var int Maximum total encoded domain name length in bytes (RFC 1035 §3.1). */
    private const MAX_ENCODED_NAME_LENGTH = 255;

    /**
     * Builds a single-question DNS query packet with an EDNS0 OPT pseudo-record
     * advertising a 4096-byte UDP payload size and requesting the DNSSEC OK bit.
     *
     * @param string $hostname
     * @param int $id 16-bit query identifier, echoed back in the response.
     * @param int $type DNS record type.
     *
     * @throws DnsQueryException When $hostname cannot be encoded (see encodeName()).
     *
     * @return string Binary DNS query packet.
     */
    public static function buildQuery(string $hostname, int $id, int $type): string
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

        $question = self::encodeName($hostname) . \pack('nn', $type, self::CLASS_IN);
        $opt = self::buildOptRecord();

        return $header . $question . $opt;
    }

    /**
     * Encodes a hostname as a sequence of length-prefixed labels terminated by a zero byte.
     *
     * @param string $hostname
     *
     * @throws DnsQueryException When a label is empty (e.g. an embedded ".." inside a
     *                           non-root hostname — silently encoding it would emit a
     *                           premature terminator byte and truncate the name on the
     *                           wire), a label exceeds 63 bytes, or the total encoded
     *                           name exceeds 255 bytes.
     *
     * @return string
     */
    public static function encodeName(string $hostname): string
    {
        $trimmed = \trim($hostname, '.');
        if ($trimmed === '') {
            return "\x00"; // the root domain itself — legitimately has zero labels
        }

        $encoded = '';
        $totalLength = 1; // the final zero-length terminator byte

        foreach (\explode('.', $trimmed) as $label) {
            $length = \strlen($label);

            if ($length === 0) {
                throw new DnsQueryException("Empty DNS label in hostname: {$hostname}");
            }
            if ($length > 63) {
                throw new DnsQueryException("DNS label too long: {$label}");
            }

            $totalLength += 1 + $length;
            if ($totalLength > self::MAX_ENCODED_NAME_LENGTH) {
                throw new DnsQueryException("Encoded DNS name exceeds {$totalLength} > " . self::MAX_ENCODED_NAME_LENGTH . " bytes: {$hostname}");
            }

            $encoded .= \chr($length) . $label;
        }

        return $encoded . "\x00";
    }

    /**
     * Builds the EDNS0 OPT pseudo-record (RFC 6891): root name, TYPE=OPT,
     * CLASS=advertised UDP payload size, TTL carries ext-RCODE(0)+version(0)+
     * flags (DO bit set, requesting DNSSEC OK), empty RDATA.
     *
     * @return string
     */
    private static function buildOptRecord(): string
    {
        return "\x00"
            . \pack('n', self::TYPE_OPT)
            . \pack('n', self::EDNS0_UDP_PAYLOAD_SIZE)
            . \pack('N', 0x00008000) // ext-rcode=0, version=0, flags: DO=1
            . \pack('n', 0);          // RDLENGTH=0
    }
}
