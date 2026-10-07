<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver\Transport;

use rafalmasiarek\DnsResolver\DnsQueryException;
use rafalmasiarek\DnsResolver\DnsTimeoutException;

/**
 * Sends a DNS query over UDP and reads a single response datagram.
 *
 * A single fwrite() of a query this small (well under any realistic path
 * MTU) does not partially write in practice, unlike the TCP transport's
 * stream — see TcpTransport for why that one loops.
 *
 * @package rafalmasiarek\DnsResolver\Transport
 */
final class UdpTransport implements DnsTransportInterface
{
    /** @var int Maximum UDP response size accepted — matches the EDNS0 payload size advertised. */
    private const MAX_RESPONSE_BYTES = 4096;

    /**
     * @param string $resolver Resolver IP address to query.
     * @param int $port Resolver port.
     * @param float $timeout Socket connect + read timeout, in seconds.
     */
    public function __construct(
        private readonly string $resolver,
        private readonly int $port,
        private readonly float $timeout,
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function send(string $query): string
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

            $response = @\fread($socket, self::MAX_RESPONSE_BYTES);
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
}
