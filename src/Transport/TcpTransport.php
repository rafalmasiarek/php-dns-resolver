<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver\Transport;

use rafalmasiarek\DnsResolver\DnsQueryException;
use rafalmasiarek\DnsResolver\DnsTimeoutException;

/**
 * Sends a DNS query over TCP (2-byte length prefix framing, RFC 1035 §4.2.2),
 * used as a fallback when a UDP response comes back truncated.
 *
 * @package rafalmasiarek\DnsResolver\Transport
 */
final class TcpTransport implements DnsTransportInterface
{
    /** @var int Maximum TCP response size accepted (the 2-byte length prefix's own ceiling). */
    private const MAX_RESPONSE_BYTES = 65535;

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
            $this->writeFully($socket, $framed);

            $lengthPrefix = $this->readExactly($socket, 2);
            $meta = \stream_get_meta_data($socket);
            if ($meta['timed_out']) {
                throw new DnsTimeoutException("DNS query to {$this->resolver}:{$this->port} over TCP timed out after {$this->timeout}s");
            }

            $length = \unpack('n', $lengthPrefix)[1];
            $response = $this->readExactly($socket, \min($length, self::MAX_RESPONSE_BYTES));

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
     * Writes the entire buffer, looping over partial writes — fwrite() on a TCP
     * stream may accept fewer bytes than given (e.g. a full kernel send buffer),
     * and silently sending only part of the length-prefixed frame would desync
     * the stream for whatever is read next.
     *
     * @param resource $socket
     * @param string $buffer
     *
     * @throws DnsQueryException When the socket rejects or fails a write.
     *
     * @return void
     */
    private function writeFully($socket, string $buffer): void
    {
        $total = \strlen($buffer);
        $written = 0;

        while ($written < $total) {
            $n = @\fwrite($socket, \substr($buffer, $written));
            if ($n === false || $n === 0) {
                throw new DnsQueryException("Unable to send DNS query to {$this->resolver}:{$this->port} over TCP");
            }
            $written += $n;
        }
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
}
