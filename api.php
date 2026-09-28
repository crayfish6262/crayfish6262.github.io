<?php
/**
 * api.php — Minimal single-file backend for DX Helper.
 *
 *   - Stores everything in one JSON file (dx_data.json) next to this script.
 *   - Admin PIN is hashed with bcrypt (password_hash / password_verify).
 *   - No database required.
 *   - First run auto-creates the store with default PIN "1234".
 *
 * Requires PHP 7.4+ (8.x recommended). No extensions beyond the defaults.
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('X-Content-Type-Options: nosniff');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const STORE_FILE   = __DIR__ . '/dx_data.json';
const DEFAULT_PIN  = '1234';               // used only on first run
const MIN_PIN_LEN  = 3;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function default_store(): array {
    return [
        'station' => null,
        'queue'   => [],
        'logs'    => [],
        'active'  => null,
        'pinHash' => null,
    ];
}

function load_store(string $file): array {
    if (!is_file($file)) return default_store();
    $raw = @file_get_contents($file);
    if ($raw === false || $raw === '') return default_store();
    $data = json_decode($raw, true);
    if (!is_array($data)) return default_store();
    return $data + default_store();
}

function save_store(string $file, array $data): bool {
    $tmp = $file . '.tmp';
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($json === false) return false;
    if (@file_put_contents($tmp, $json, LOCK_EX) === false) return false;
    return @rename($tmp, $file);
}

function respond($data, int $code = 200): void {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

function request_body(): array {
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') return $_POST;
    $j = json_decode($raw, true);
    return is_array($j) ? $j : $_POST;
}

function client_ip(): string {
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

// Very small per-IP rate limiter for the "join" action to stop spam.
// Allows 8 joins per 5 minutes. Uses the store file itself (single file goal).
function rate_limit_join(array &$store): void {
    $ip = client_ip();
    $now = time();
    if (!isset($store['_ratelimits']) || !is_array($store['_ratelimits'])) {
        $store['_ratelimits'] = [];
    }
    // prune old
    foreach ($store['_ratelimits'] as $k => $times) {
        $store['_ratelimits'][$k] = array_values(array_filter(
            (array)$times, fn($t) => ($now - (int)$t) < 300
        ));
        if (empty($store['_ratelimits'][$k])) unset($store['_ratelimits'][$k]);
    }
    $bucket = $store['_ratelimits'][$ip] ?? [];
    if (count($bucket) >= 8) {
        respond(['error' => 'Too many requests, slow down.'], 429);
    }
    $bucket[] = $now;
    $store['_ratelimits'][$ip] = $bucket;
}

// ---------------------------------------------------------------------------
// Bootstrap: make sure the store file exists and has a hashed PIN
// ---------------------------------------------------------------------------
$store = load_store(STORE_FILE);
if (empty($store['pinHash']) || !is_string($store['pinHash'])) {
    $store['pinHash'] = password_hash(DEFAULT_PIN, PASSWORD_DEFAULT);
    save_store(STORE_FILE, $store);
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
function require_admin(array $store): void {
    $pin = $_SERVER['HTTP_X_ADMIN_PIN'] ?? '';
    if (!is_string($pin) || $pin === '' || !password_verify($pin, $store['pinHash'])) {
        respond(['error' => 'Unauthorized'], 401);
    }
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------
$action = $_GET['action'] ?? '';

switch ($action) {

    // ---------- PUBLIC: read entire state ----------
    case 'load':
        respond([
            'station' => $store['station'],
            'queue'   => $store['queue'],
            'logs'    => $store['logs'],
            'active'  => $store['active'],
        ]);

    // ---------- PUBLIC: join queue ----------
    case 'join':
        // Re-load so we're looking at fresh state, then rate-limit
        $store = load_store(STORE_FILE);
        rate_limit_join($store);

        $in = request_body();
        $callsign = strtoupper(trim((string)($in['callsign'] ?? '')));
        $grid     = strtoupper(trim((string)($in['grid'] ?? '')));
        $rst      = trim((string)($in['rst']   ?? '59'));
        $band     = trim((string)($in['band']  ?? '20m'));
        $mode     = trim((string)($in['mode']  ?? 'SSB'));
        $notes    = trim((string)($in['notes'] ?? ''));

        if ($callsign === '' || $grid === '') {
            respond(['error' => 'Callsign and Grid required'], 400);
        }
        if (strlen($callsign) > 12 || strlen($grid) > 8) {
            respond(['error' => 'Field too long'], 400);
        }

        foreach ($store['queue'] as $q) {
            if (($q['callsign'] ?? '') === $callsign) {
                respond(['error' => 'Callsign already in queue'], 409);
            }
        }

        $item = [
            'id'        => 'q_' . round(microtime(true) * 1000),
            'callsign'  => $callsign,
            'grid'      => $grid,
            'rst'       => $rst,
            'band'      => $band,
            'mode'      => $mode,
            'notes'     => $notes,
            'timestamp' => round(microtime(true) * 1000),
        ];
        $store['queue'][] = $item;

        if (!save_store(STORE_FILE, $store)) {
            respond(['error' => 'Failed to save'], 500);
        }
        respond(['ok' => true, 'item' => $item]);

    // ---------- AUTH: login ----------
    case 'login':
        $in = request_body();
        $pin = (string)($in['pin'] ?? '');
        if ($pin !== '' && password_verify($pin, $store['pinHash'])) {
            respond(['ok' => true]);
        }
        respond(['error' => 'Incorrect PIN'], 401);

    // ---------- ADMIN: change password ----------
    case 'changePassword':
        require_admin($store);
        $in = request_body();
        $new = trim((string)($in['new'] ?? ''));
        if (strlen($new) < MIN_PIN_LEN) {
            respond(['error' => 'PIN too short'], 400);
        }
        $store['pinHash'] = password_hash($new, PASSWORD_DEFAULT);
        if (!save_store(STORE_FILE, $store)) {
            respond(['error' => 'Save failed'], 500);
        }
        respond(['ok' => true]);

    // ---------- ADMIN: save station params ----------
    case 'saveStation':
        require_admin($store);
        $in = request_body();
        // whitelist keys
        $allowed = ['callsign','grid','rig','band','freq','mode','status','notice'];
        $clean = [];
        foreach ($allowed as $k) {
            if (array_key_exists($k, $in) && is_string($in[$k])) {
                $clean[$k] = substr($in[$k], 0, 500);
            }
        }
        $store['station'] = $clean;
        if (!save_store(STORE_FILE, $store)) respond(['error' => 'Save failed'], 500);
        respond(['ok' => true]);

    // ---------- ADMIN: save queue ----------
    case 'saveQueue':
        require_admin($store);
        $in = request_body();
        if (!is_array($in)) respond(['error' => 'Invalid queue'], 400);
        $store['queue'] = array_values(array_slice($in, 0, 500));
        if (!save_store(STORE_FILE, $store)) respond(['error' => 'Save failed'], 500);
        respond(['ok' => true]);

    // ---------- ADMIN: save logs ----------
    case 'saveLogs':
        require_admin($store);
        $in = request_body();
        if (!is_array($in)) respond(['error' => 'Invalid logs'], 400);
        $store['logs'] = array_values(array_slice($in, 0, 5000));
        if (!save_store(STORE_FILE, $store)) respond(['error' => 'Save failed'], 500);
        respond(['ok' => true]);

    // ---------- ADMIN: save active contact ----------
    case 'saveActive':
        require_admin($store);
        $in = request_body();
        $store['active'] = $in === [] ? null : $in;
        if (!save_store(STORE_FILE, $store)) respond(['error' => 'Save failed'], 500);
        respond(['ok' => true]);

    // ---------- ADMIN: reset all data (keeps pinHash) ----------
    case 'reset':
        require_admin($store);
        $store['station'] = null;
        $store['queue']   = [];
        $store['logs']    = [];
        $store['active']  = null;
        $store['_ratelimits'] = [];
        if (!save_store(STORE_FILE, $store)) respond(['error' => 'Save failed'], 500);
        respond(['ok' => true]);

    default:
        respond(['error' => 'Unknown action'], 400);
}
