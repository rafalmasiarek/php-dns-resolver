<?php

declare(strict_types=1);

namespace rafalmasiarek\DnsResolver;

/**
 * Thrown when no response arrives within the configured timeout. A subtype
 * of DnsQueryException, so existing catch (DnsQueryException) call sites
 * keep working without changes.
 *
 * @package rafalmasiarek\DnsResolver
 */
class DnsTimeoutException extends DnsQueryException
{
}
