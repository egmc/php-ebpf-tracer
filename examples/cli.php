<?php
/**
 * CLI variant of the demo: one process == one request__startup /
 * request__shutdown pair. Run it under the tracer with
 *
 *   php-ebpf-tracer -binary /usr/local/bin/php -min-duration 50ms
 */

declare(strict_types=1);

function work(int $depth, int $sleepUs): int
{
    usleep($sleepUs);
    if ($depth <= 0) {
        return 0;
    }

    return $depth + work($depth - 1, $sleepUs);
}

$sleepUs = (int) ($argv[1] ?? 20000);
printf("result=%d\n", work(5, $sleepUs));
