<?php
/**
 * Demo application for php-ebpf-tracer.
 *
 * Served by PHP's built-in web server, so every HTTP request fires
 * php:request__startup / php:request__shutdown in the same process, and the
 * nested calls below fire php:function__entry / php:function__return.
 *
 * Endpoints:
 *   /fast    a few hundred microseconds  -> below the default threshold
 *   /slow    ~250 ms                     -> exported
 *   /random  0-400 ms                    -> exported roughly half the time
 *   /error   throws, to show an unwound stack
 */

declare(strict_types=1);

final class Repository
{
    public function __construct(private readonly int $latencyUs) {}

    public function findAll(int $rows): array
    {
        $this->connect();
        $out = [];
        for ($i = 0; $i < $rows; $i++) {
            $out[] = $this->hydrate($i);
        }

        return $out;
    }

    private function connect(): void
    {
        usleep($this->latencyUs);
    }

    private function hydrate(int $id): array
    {
        return ['id' => $id, 'name' => sha1((string) $id)];
    }
}

final class Renderer
{
    public function render(array $rows): string
    {
        $parts = [];
        foreach ($rows as $row) {
            $parts[] = $this->renderRow($row);
        }

        return implode("\n", $parts);
    }

    private function renderRow(array $row): string
    {
        return sprintf('%d: %s', $row['id'], $row['name']);
    }
}

function handle_fast(): string
{
    $repo = new Repository(100);

    return (new Renderer())->render($repo->findAll(3));
}

function handle_slow(): string
{
    $repo = new Repository(150_000);
    $rows = $repo->findAll(20);
    expensive_post_processing($rows);

    return (new Renderer())->render($rows);
}

function expensive_post_processing(array $rows): void
{
    usleep(80_000);
    foreach ($rows as $row) {
        checksum($row['name']);
    }
}

function checksum(string $value): string
{
    return hash('sha256', $value);
}

function handle_random(): string
{
    $repo = new Repository(random_int(0, 400_000));

    return (new Renderer())->render($repo->findAll(5));
}

function handle_error(): string
{
    deep_call(0);

    return 'unreachable';
}

function deep_call(int $depth): void
{
    usleep(20_000);
    if ($depth >= 5) {
        throw new RuntimeException('boom at depth ' . $depth);
    }
    deep_call($depth + 1);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

header('Content-Type: text/plain');

try {
    $body = match ($path) {
        '/fast'   => handle_fast(),
        '/slow'   => handle_slow(),
        '/random' => handle_random(),
        '/error'  => handle_error(),
        default   => "php-ebpf-tracer demo\n/fast /slow /random /error\n",
    };
    echo $body, "\n";
} catch (Throwable $e) {
    http_response_code(500);
    echo 'error: ', $e->getMessage(), "\n";
}
