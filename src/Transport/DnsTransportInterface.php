<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver\Transport;

use rafalmasiarek\DnsResolver\DnsQueryException;
use rafalmasiarek\DnsResolver\DnsTimeoutException;

/**
 * Sends one already-encoded DNS query packet to a fixed resolver and returns
 * the raw response. Implementations own a single resolver/port/timeout for
 * their whole lifetime — constructed once per DnsClient (or per attempt, via
 * withTimeout()), not parameterized per call.
 *
 * @package rafalmasiarek\DnsResolver\Transport
 */
interface DnsTransportInterface
{
    /**
     * @param string $query Binary DNS query packet.
     *
     * @throws DnsTimeoutException When no response arrives within the timeout.
     * @throws DnsQueryException On socket failure.
     *
     * @return string Raw response packet.
     */
    public function send(string $query): string;
}
