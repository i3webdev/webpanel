<?php

declare(strict_types=1);

const PANEL_CONFIG_FILE = '/home/painel_srv/.ultra-panel/panel.env';
const PANEL_HELPER_BIN = '/usr/local/sbin/ultra-panel-helper';
const PANEL_AUTH_COOKIE = 'ultra_panel_auth';
const PANEL_FLASH_COOKIE = 'ultra_panel_flash';
const PANEL_CSRF_COOKIE = 'ultra_panel_csrf';

function loadEnvFile(string $path): array
{
    $result = [];
    if (!is_file($path)) {
        return $result;
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        return $result;
    }

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }

        $parts = explode('=', $line, 2);
        if (count($parts) !== 2) {
            continue;
        }

        $key = trim($parts[0]);
        $value = trim($parts[1]);
        $result[$key] = $value;
    }

    return $result;
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function panelExec(array $args, string $stdin = ''): array
{
    $cmd = 'sudo ' . escapeshellarg(PANEL_HELPER_BIN);
    foreach ($args as $arg) {
        $cmd .= ' ' . escapeshellarg($arg);
    }

    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];

    $proc = proc_open($cmd, $descriptors, $pipes);
    if (!is_resource($proc)) {
        return [1, '', 'Falha ao executar helper'];
    }

    fwrite($pipes[0], $stdin);
    fclose($pipes[0]);

    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[2]);

    $code = proc_close($proc);

    return [$code, (string) $stdout, trim((string) $stderr)];
}

function redirectTo(string $url): never
{
    header('Location: ' . $url);
    exit;
}

function baseUrl(array $params = []): string
{
    if ($params === []) {
        return $_SERVER['PHP_SELF'] ?? '/';
    }

    return ($_SERVER['PHP_SELF'] ?? '/') . '?' . http_build_query($params);
}

function isHttpsRequest(): bool
{
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }

    return (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
}

function cookieSecret(): string
{
    static $secret = '';
    if ($secret !== '') {
        return $secret;
    }

    $raw = @file_get_contents(PANEL_CONFIG_FILE);
    if ($raw === false || $raw === '') {
        $raw = PANEL_CONFIG_FILE;
    }

    $secret = hash('sha256', $raw . '|' . __FILE__);
    return $secret;
}

function b64urlEncode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function b64urlDecode(string $data): string
{
    $pad = strlen($data) % 4;
    if ($pad > 0) {
        $data .= str_repeat('=', 4 - $pad);
    }
    return (string) base64_decode(strtr($data, '-_', '+/'), true);
}

function setCookieValue(string $name, string $value, int $expires, bool $httpOnly = true): void
{
    setcookie($name, $value, [
        'expires' => $expires,
        'path' => '/',
        'secure' => isHttpsRequest(),
        'httponly' => $httpOnly,
        'samesite' => 'Lax',
    ]);
}

function deleteCookieValue(string $name): void
{
    setCookieValue($name, '', time() - 3600);
    unset($_COOKIE[$name]);
}

function signedEncode(array $payload): string
{
    $json = json_encode($payload, JSON_UNESCAPED_UNICODE);
    if (!is_string($json)) {
        return '';
    }
    $data = b64urlEncode($json);
    $sig = hash_hmac('sha256', $data, cookieSecret());
    return $data . '.' . $sig;
}

function signedDecode(string $value): ?array
{
    $parts = explode('.', $value, 2);
    if (count($parts) !== 2) {
        return null;
    }

    [$data, $sig] = $parts;
    $expected = hash_hmac('sha256', $data, cookieSecret());
    if (!hash_equals($expected, $sig)) {
        return null;
    }

    $json = b64urlDecode($data);
    if ($json === '') {
        return null;
    }

    $decoded = json_decode($json, true);
    return is_array($decoded) ? $decoded : null;
}

function setAuthCookie(string $user): void
{
    $payload = [
        'u' => $user,
        'iat' => time(),
        'exp' => time() + 86400 * 7,
    ];
    $encoded = signedEncode($payload);
    if ($encoded !== '') {
        setCookieValue(PANEL_AUTH_COOKIE, $encoded, $payload['exp']);
        $_COOKIE[PANEL_AUTH_COOKIE] = $encoded;
    }
}

function authUserFromCookie(): ?string
{
    $raw = (string) ($_COOKIE[PANEL_AUTH_COOKIE] ?? '');
    if ($raw === '') {
        return null;
    }

    $payload = signedDecode($raw);
    if (!is_array($payload)) {
        return null;
    }

    $exp = (int) ($payload['exp'] ?? 0);
    $user = (string) ($payload['u'] ?? '');
    if ($exp < time() || $user === '') {
        return null;
    }

    return $user;
}

function clearAuthCookie(): void
{
    deleteCookieValue(PANEL_AUTH_COOKIE);
}

function csrfToken(): string
{
    $current = (string) ($_COOKIE[PANEL_CSRF_COOKIE] ?? '');
    if (!preg_match('/^[a-f0-9]{64}$/', $current)) {
        $current = bin2hex(random_bytes(32));
        setCookieValue(PANEL_CSRF_COOKIE, $current, time() + 86400 * 30, true);
        $_COOKIE[PANEL_CSRF_COOKIE] = $current;
    }

    return $current;
}

function assertCsrf(): void
{
    $token = (string) ($_POST['csrf_token'] ?? '');
    if (!hash_equals(csrfToken(), $token)) {
        throw new RuntimeException('Token CSRF invalido.');
    }
}

function setFlash(string $type, string $text): void
{
    $payload = [
        'type' => $type,
        'text' => $text,
        'exp' => time() + 120,
    ];
    $encoded = signedEncode($payload);
    if ($encoded !== '') {
        setCookieValue(PANEL_FLASH_COOKIE, $encoded, $payload['exp']);
        $_COOKIE[PANEL_FLASH_COOKIE] = $encoded;
    }
}

function pullFlash(): ?array
{
    $raw = (string) ($_COOKIE[PANEL_FLASH_COOKIE] ?? '');
    if ($raw === '') {
        return null;
    }

    deleteCookieValue(PANEL_FLASH_COOKIE);

    $payload = signedDecode($raw);
    if (!is_array($payload)) {
        return null;
    }

    if ((int) ($payload['exp'] ?? 0) < time()) {
        return null;
    }

    $type = (string) ($payload['type'] ?? '');
    $text = (string) ($payload['text'] ?? '');
    if ($type === '' || $text === '') {
        return null;
    }

    return ['type' => $type, 'text' => $text];
}

function sanitizeRelPath(string $path): string
{
    $path = trim($path);
    if ($path === '') {
        return '';
    }

    $path = str_replace('\\', '/', $path);
    $parts = explode('/', $path);
    $safe = [];

    foreach ($parts as $part) {
        $part = trim($part);
        if ($part === '' || $part === '.') {
            continue;
        }

        if ($part === '..') {
            return '';
        }

        if (preg_match('/[\x00-\x1F\x7F]/', $part) === 1) {
            return '';
        }

        $safe[] = $part;
    }

    return implode('/', $safe);
}

function sanitizeSiteUser(string $value): string
{
    $value = trim($value);
    return preg_match('/^[a-z_][a-z0-9_-]{0,30}$/', $value) === 1 ? $value : '';
}

function sanitizeDomainInput(string $value): string
{
    $value = strtolower(trim($value));
    $value = preg_replace('#^https?://#', '', $value) ?? $value;
    $value = strtok($value, '/');
    if (!is_string($value)) {
        return '';
    }

    return preg_match('/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $value) === 1 ? $value : '';
}

function sanitizeCronExpression(string $value): string
{
    $value = trim(preg_replace('/\s+/', ' ', $value) ?? '');
    if ($value === '') {
        return '';
    }

    if (preg_match('/^@[a-zA-Z]+$/', $value) === 1) {
        return $value;
    }

    $parts = preg_split('/\s+/', $value);
    if (!is_array($parts) || count($parts) !== 5) {
        return '';
    }

    return $value;
}

function sanitizeCronCommand(string $value): string
{
    $value = trim($value);
    if ($value === '' || str_contains($value, "\n") || str_contains($value, "\r")) {
        return '';
    }

    return $value;
}

function sanitizeGithubUsername(string $value): string
{
    $value = trim($value);
    return preg_match('/^[A-Za-z0-9-]{1,39}$/', $value) === 1 ? $value : '';
}

function sanitizeGithubToken(string $value): string
{
    $value = trim($value);
    if ($value === '' || strlen($value) < 20 || str_contains($value, "\n") || str_contains($value, "\r") || preg_match('/\s/', $value) === 1) {
        return '';
    }

    return $value;
}

function sanitizeGithubClientId(string $value): string
{
    $value = trim($value);
    if ($value === '' || strlen($value) > 120 || str_contains($value, "\n") || str_contains($value, "\r") || preg_match('/\s/', $value) === 1) {
        return '';
    }

    return $value;
}

function sanitizeGithubScopes(string $value): string
{
    $value = trim(preg_replace('/\s+/', ' ', $value) ?? '');
    if ($value === '' || strlen($value) > 120 || preg_match('/^[A-Za-z0-9:_ -]+$/', $value) !== 1) {
        return '';
    }

    return $value;
}

function sanitizeGithubRepoSlug(string $value): string
{
    $value = trim($value);
    return preg_match('/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/', $value) === 1 ? $value : '';
}

function sanitizeGithubBranch(string $value): string
{
    $value = trim($value);
    if ($value === '') {
        return '';
    }
    if (preg_match('/^[A-Za-z0-9._\/-]{1,120}$/', $value) !== 1) {
        return '';
    }
    if (str_contains($value, '..') || str_starts_with($value, '/') || str_ends_with($value, '/')) {
        return '';
    }

    return $value;
}

function sanitizeGithubAuthorName(string $value): string
{
    $value = trim($value);
    if ($value === '' || strlen($value) > 80 || str_contains($value, "\n") || str_contains($value, "\r")) {
        return '';
    }

    return $value;
}

function sanitizeGithubAuthorEmail(string $value): string
{
    $value = trim($value);
    return filter_var($value, FILTER_VALIDATE_EMAIL) ? $value : '';
}

function sanitizeCommitMessage(string $value): string
{
    $value = trim($value);
    if ($value === '' || strlen($value) > 200 || str_contains($value, "\n") || str_contains($value, "\r")) {
        return '';
    }

    return $value;
}

function decodeJson(string $json): array
{
    $decoded = json_decode($json, true);
    return is_array($decoded) ? $decoded : [];
}

function flashUiClass(string $type): string
{
    if ($type === 'success') {
        return 'border-emerald-200 bg-emerald-50 text-emerald-800';
    }

    return 'border-rose-200 bg-rose-50 text-rose-700';
}

function serviceStatusUiClass(string $status): string
{
    if ($status === 'active') {
        return 'bg-emerald-100 text-emerald-700 ring-1 ring-emerald-200';
    }

    if ($status === 'inactive') {
        return 'bg-amber-100 text-amber-700 ring-1 ring-amber-200';
    }

    return 'bg-slate-100 text-slate-700 ring-1 ring-slate-200';
}

function formatBytesUi(int $bytes): string
{
    if ($bytes < 1024) {
        return $bytes . ' B';
    }

    $units = ['KB', 'MB', 'GB', 'TB'];
    $value = $bytes;

    foreach ($units as $unit) {
        $value /= 1024;
        if ($value < 1024 || $unit === 'TB') {
            return number_format($value, $value >= 10 ? 0 : 1, ',', '.') . ' ' . $unit;
        }
    }

    return $bytes . ' B';
}

function formatUnixTimeUi(int $timestamp): string
{
    if ($timestamp <= 0) {
        return '-';
    }

    return date('d/m/Y H:i', $timestamp);
}

function formatIsoTimeUi(string $value): string
{
    $value = trim($value);
    if ($value === '') {
        return '-';
    }

    try {
        $dt = new DateTimeImmutable($value);
    } catch (Throwable) {
        return $value;
    }

    return $dt->setTimezone(new DateTimeZone(date_default_timezone_get()))->format('d/m/Y H:i');
}

function formatPercentUi(float $value): string
{
    if ($value < 0) {
        $value = 0;
    }
    if ($value > 100) {
        $value = 100;
    }

    return number_format($value, 1, ',', '.') . '%';
}

function formatUptimeUi(int $seconds): string
{
    if ($seconds <= 0) {
        return '-';
    }

    $days = intdiv($seconds, 86400);
    $hours = intdiv($seconds % 86400, 3600);
    $minutes = intdiv($seconds % 3600, 60);
    $parts = [];

    if ($days > 0) {
        $parts[] = $days . 'd';
    }
    if ($hours > 0 || $days > 0) {
        $parts[] = $hours . 'h';
    }
    $parts[] = $minutes . 'min';

    return implode(' ', $parts);
}

function metricBarClass(float $percent): string
{
    if ($percent >= 85) {
        return 'bg-rose-500';
    }
    if ($percent >= 65) {
        return 'bg-amber-500';
    }

    return 'bg-emerald-500';
}

function fileTypeLabel(string $type): string
{
    if ($type === 'dir') {
        return 'Pasta';
    }

    if ($type === 'link') {
        return 'Link';
    }

    return 'Arquivo';
}

function fileTypeBadgeClass(string $type): string
{
    if ($type === 'dir') {
        return 'bg-amber-100 text-amber-800 ring-1 ring-amber-200';
    }

    if ($type === 'link') {
        return 'bg-sky-100 text-sky-800 ring-1 ring-sky-200';
    }

    return 'bg-slate-100 text-slate-700 ring-1 ring-slate-200';
}

function fileTypeIcon(string $type): string
{
    if ($type === 'dir') {
        return '<svg viewBox="0 0 24 24" fill="none" class="h-5 w-5 text-amber-500" stroke="currentColor" stroke-width="1.8"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z" stroke-linejoin="round"/></svg>';
    }

    if ($type === 'link') {
        return '<svg viewBox="0 0 24 24" fill="none" class="h-5 w-5 text-sky-500" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 0 0 7.07 0l1.41-1.41a5 5 0 0 0-7.07-7.07L10 5"/><path d="M14 11a5 5 0 0 0-7.07 0L5.5 12.43a5 5 0 0 0 7.07 7.07L14 18"/></svg>';
    }

    return '<svg viewBox="0 0 24 24" fill="none" class="h-5 w-5 text-slate-500" stroke="currentColor" stroke-width="1.8"><path d="M7 3h7l5 5v13H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z"/><path d="M14 3v6h6"/></svg>';
}

function buildFileBreadcrumbs(string $current): array
{
    $breadcrumbs = [
        ['label' => 'public_html', 'path' => ''],
    ];

    if ($current === '') {
        return $breadcrumbs;
    }

    $segments = explode('/', $current);
    $path = '';

    foreach ($segments as $segment) {
        if ($segment === '') {
            continue;
        }

        $path = $path === '' ? $segment : $path . '/' . $segment;
        $breadcrumbs[] = ['label' => $segment, 'path' => $path];
    }

    return $breadcrumbs;
}

function tabIcon(string $tab): string
{
    switch ($tab) {
        case 'sites':
            return '<svg viewBox="0 0 24 24" fill="none" class="h-5 w-5" stroke="currentColor" stroke-width="1.8"><path d="M4 6h16M4 12h16M4 18h16" stroke-linecap="round"/><circle cx="7" cy="6" r="1.5"/><circle cx="7" cy="12" r="1.5"/><circle cx="7" cy="18" r="1.5"/></svg>';
        case 'files':
            return '<svg viewBox="0 0 24 24" fill="none" class="h-5 w-5" stroke="currentColor" stroke-width="1.8"><path d="M3 6a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6Z"/></svg>';
        case 'database':
            return '<svg viewBox="0 0 24 24" fill="none" class="h-5 w-5" stroke="currentColor" stroke-width="1.8"><ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6"/><path d="M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/></svg>';
        case 'system':
            return '<svg viewBox="0 0 24 24" fill="none" class="h-5 w-5" stroke="currentColor" stroke-width="1.8"><path d="M10.3 4.3a1 1 0 0 1 1.4 0l.6.6a1 1 0 0 0 1 .24l.82-.22a1 1 0 0 1 1.22.7l.2.8a1 1 0 0 0 .74.73l.8.2a1 1 0 0 1 .7 1.22l-.22.82a1 1 0 0 0 .24 1l.6.6a1 1 0 0 1 0 1.4l-.6.6a1 1 0 0 0-.24 1l.22.82a1 1 0 0 1-.7 1.22l-.8.2a1 1 0 0 0-.73.74l-.2.8a1 1 0 0 1-1.22.7l-.82-.22a1 1 0 0 0-1 .24l-.6.6a1 1 0 0 1-1.4 0l-.6-.6a1 1 0 0 0-1-.24l-.82.22a1 1 0 0 1-1.22-.7l-.2-.8a1 1 0 0 0-.74-.73l-.8-.2a1 1 0 0 1-.7-1.22l.22-.82a1 1 0 0 0-.24-1l-.6-.6a1 1 0 0 1 0-1.4l.6-.6a1 1 0 0 0 .24-1l-.22-.82a1 1 0 0 1 .7-1.22l.8-.2a1 1 0 0 0 .73-.74l.2-.8a1 1 0 0 1 1.22-.7l.82.22a1 1 0 0 0 1-.24l.6-.6Z"/><circle cx="12" cy="12" r="3.2"/></svg>';
        case 'dashboard':
        default:
            return '<svg viewBox="0 0 24 24" fill="none" class="h-5 w-5" stroke="currentColor" stroke-width="1.8"><path d="M4 13h7V4H4v9Zm9 7h7V4h-7v16ZM4 20h7v-5H4v5Z"/></svg>';
    }
}

$config = loadEnvFile(PANEL_CONFIG_FILE);
$panelTitle = $config['PANEL_TITLE'] ?? 'ULTRA Web Panel';
$panelUser = $config['PANEL_USER'] ?? 'admin';
$panelPassHash = $config['PANEL_PASS_HASH'] ?? '';

$action = (string) ($_POST['action'] ?? '');

if ($action === 'login') {
    $username = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');

    if ($username === $panelUser && $panelPassHash !== '' && password_verify($password, $panelPassHash)) {
        setAuthCookie($panelUser);
        setFlash('success', 'Login realizado com sucesso.');
        redirectTo(baseUrl(['tab' => 'dashboard']));
    }

    setFlash('error', 'Usuario ou senha invalidos.');
    redirectTo(baseUrl());
}

if ($action === 'logout') {
    clearAuthCookie();
    deleteCookieValue(PANEL_CSRF_COOKIE);
    setFlash('success', 'Sessao encerrada.');
    redirectTo(baseUrl());
}

$authed = (authUserFromCookie() === $panelUser);
$flash = pullFlash();

if (!$authed) {
    ?>
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title><?= h($panelTitle) ?> - Login</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@500;600;700&family=Public+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      theme: {
        extend: {
          fontFamily: {
            body: ['Public Sans', 'sans-serif'],
            display: ['Outfit', 'sans-serif']
          }
        }
      }
    };
  </script>
</head>
<body class="min-h-screen bg-slate-100 font-body text-slate-800 antialiased">
  <main class="mx-auto grid min-h-screen max-w-6xl items-center gap-8 px-4 py-8 sm:px-6 lg:grid-cols-2 lg:px-8">
    <section class="hidden rounded-3xl bg-gradient-to-br from-blue-700 to-blue-500 p-10 text-white shadow-2xl lg:block">
      <p class="inline-flex rounded-full border border-white/35 px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em]">Server Control</p>
      <h1 class="mt-6 font-display text-4xl font-semibold leading-tight">Visual limpo para gerenciar seus sites.</h1>
      <p class="mt-4 text-blue-100">Interface inspirada em paineis de hospedagem, com foco em clareza, velocidade e operacao do dia a dia.</p>
      <ul class="mt-8 space-y-3 text-sm text-blue-50">
        <li class="rounded-xl bg-white/15 px-4 py-3">Gestao de sites e servicos</li>
        <li class="rounded-xl bg-white/15 px-4 py-3">Gerenciador de arquivos direto no navegador</li>
        <li class="rounded-xl bg-white/15 px-4 py-3">Acesso rapido ao banco de dados</li>
      </ul>
    </section>

    <section class="rounded-3xl border border-slate-200 bg-white p-6 shadow-xl sm:p-8">
      <p class="text-xs font-semibold uppercase tracking-[0.2em] text-blue-600">ULTRA PANEL</p>
      <h2 class="mt-3 font-display text-3xl font-semibold text-slate-900"><?= h($panelTitle) ?></h2>
      <p class="mt-2 text-sm text-slate-500">Acesso administrativo protegido.</p>

      <?php if ($flash): ?>
        <div class="mt-5 rounded-xl border px-4 py-3 text-sm <?= h(flashUiClass((string) ($flash['type'] ?? 'error'))) ?>">
          <?= h((string) ($flash['text'] ?? 'Falha inesperada.')) ?>
        </div>
      <?php endif; ?>

      <form method="post" autocomplete="off" class="mt-6 space-y-4">
        <input type="hidden" name="action" value="login">

        <div>
          <label class="mb-2 block text-sm font-semibold text-slate-700">Usuario</label>
          <input type="text" name="username" required class="w-full rounded-xl border border-slate-300 bg-white px-4 py-3 text-slate-900 outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
        </div>

        <div>
          <label class="mb-2 block text-sm font-semibold text-slate-700">Senha</label>
          <input type="password" name="password" required class="w-full rounded-xl border border-slate-300 bg-white px-4 py-3 text-slate-900 outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
        </div>

        <button type="submit" class="w-full rounded-xl bg-blue-600 px-4 py-3 font-semibold text-white shadow-lg shadow-blue-500/25 transition hover:bg-blue-700">Entrar no Painel</button>
      </form>
    </section>
  </main>
</body>
</html>
    <?php
    exit;
}

$requestedTab = (string) ($_GET['tab'] ?? ($_POST['return_tab'] ?? 'dashboard'));
$tab = $requestedTab;
$allowedTabs = ['dashboard', 'sites', 'files', 'database', 'system'];
if (!in_array($tab, $allowedTabs, true)) {
    $tab = 'dashboard';
}

$actionResult = null;

try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action !== '') {
        assertCsrf();

        if ($action === 'restart_services') {
            [$code, , $stderr] = panelExec(['restart-services']);
            if ($code === 0) {
                setFlash('success', 'Servicos reiniciados.');
            } else {
                setFlash('error', 'Falha ao reiniciar servicos: ' . $stderr);
            }
            redirectTo(baseUrl(['tab' => 'system']));
        }

        if ($action === 'site_create') {
            $domain = sanitizeDomainInput((string) ($_POST['site_domain'] ?? ''));
            $phpVersion = trim((string) ($_POST['php_version'] ?? '8.4'));
            $installWp = !empty($_POST['install_wp']) ? '1' : '0';
            $createTunnel = !empty($_POST['create_tunnel']) ? '1' : '0';

            if ($domain === '') {
                throw new RuntimeException('Dominio invalido para criar site.');
            }
            if (!in_array($phpVersion, ['8.4', '8.3', '8.2', '8.1'], true)) {
                throw new RuntimeException('Versao de PHP invalida.');
            }

            [$code, $out, $stderr] = panelExec(['site-create', $domain, $phpVersion, $installWp, $createTunnel]);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $siteUser = (string) ($payload['user'] ?? '');
                $siteDomain = (string) ($payload['domain'] ?? $domain);
                $dbName = (string) (($payload['db']['name'] ?? '') ?: '');
                $dbUser = (string) (($payload['db']['user'] ?? '') ?: '');
                $msg = 'Site criado: ' . $siteDomain;
                if ($siteUser !== '') {
                    $msg .= ' (usuario ' . $siteUser . ')';
                }
                if ($dbName !== '' && $dbUser !== '') {
                    $msg .= ' | Banco: ' . $dbName . ' / ' . $dbUser;
                }
                setFlash('success', $msg);
            } else {
                $apiError = (string) ($payload['error'] ?? '');
                $detail = $apiError !== '' ? $apiError : ($stderr !== '' ? $stderr : 'falha desconhecida');
                setFlash('error', 'Falha ao criar site: ' . $detail);
            }
            redirectTo(baseUrl(['tab' => 'sites']));
        }

        if ($action === 'site_clone') {
            $sourceUser = sanitizeSiteUser((string) ($_POST['source_user'] ?? ''));
            $targetDomain = sanitizeDomainInput((string) ($_POST['target_domain'] ?? ''));
            $phpVersion = trim((string) ($_POST['php_version'] ?? '8.4'));
            $createTunnel = !empty($_POST['create_tunnel']) ? '1' : '0';

            if ($sourceUser === '') {
                throw new RuntimeException('Site de origem invalido para clone.');
            }
            if ($targetDomain === '') {
                throw new RuntimeException('Dominio de destino invalido para clone.');
            }
            if (!in_array($phpVersion, ['8.4', '8.3', '8.2', '8.1'], true)) {
                throw new RuntimeException('Versao de PHP invalida.');
            }

            [$code, $out, $stderr] = panelExec(['site-clone', $sourceUser, $targetDomain, $phpVersion, $createTunnel]);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $destUser = (string) (($payload['destination']['user'] ?? '') ?: '');
                $msg = 'Clone concluido para ' . $targetDomain;
                if ($destUser !== '') {
                    $msg .= ' (usuario ' . $destUser . ')';
                }
                setFlash('success', $msg);
            } else {
                $apiError = (string) ($payload['error'] ?? '');
                $detail = $apiError !== '' ? $apiError : ($stderr !== '' ? $stderr : 'falha desconhecida');
                setFlash('error', 'Falha ao clonar site: ' . $detail);
            }
            redirectTo(baseUrl(['tab' => 'sites']));
        }

        if ($action === 'site_remove') {
            $siteUser = sanitizeSiteUser((string) ($_POST['site_user'] ?? ''));
            $withBackup = !empty($_POST['with_backup']) ? '1' : '0';

            if ($siteUser === '') {
                throw new RuntimeException('Site invalido para remocao.');
            }

            [$code, $out, $stderr] = panelExec(['site-remove', $siteUser, $withBackup]);
            $payload = decodeJson($out);
            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $backup = (string) ($payload['backup'] ?? '');
                $msg = 'Site removido: ' . $siteUser;
                if ($backup !== '') {
                    $msg .= ' | Backup: ' . $backup;
                }
                setFlash('success', $msg);
            } else {
                $apiError = (string) ($payload['error'] ?? '');
                $detail = $apiError !== '' ? $apiError : ($stderr !== '' ? $stderr : 'falha desconhecida');
                setFlash('error', 'Falha ao remover site: ' . $detail);
            }
            redirectTo(baseUrl(['tab' => 'sites']));
        }

        if ($action === 'db_create_additional') {
            $siteUser = sanitizeSiteUser((string) ($_POST['site_user'] ?? ''));
            $suffixRaw = trim((string) ($_POST['db_suffix'] ?? ''));
            $suffix = preg_replace('/[^a-z0-9_-]/i', '', $suffixRaw) ?? '';
            $suffix = strtolower(str_replace('-', '_', $suffix));

            if ($siteUser === '') {
                throw new RuntimeException('Site invalido para criar banco adicional.');
            }
            if (strlen($suffix) > 20) {
                $suffix = substr($suffix, 0, 20);
            }

            $args = ['db-create-additional', $siteUser];
            if ($suffix !== '') {
                $args[] = $suffix;
            }

            [$code, $out, $stderr] = panelExec($args);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $dbName = (string) (($payload['db']['name'] ?? '') ?: '');
                $dbUser = (string) (($payload['db']['user'] ?? '') ?: '');
                $msg = 'Banco adicional criado';
                if ($dbName !== '' && $dbUser !== '') {
                    $msg .= ': ' . $dbName . ' / ' . $dbUser;
                }
                setFlash('success', $msg);
            } else {
                $apiError = (string) ($payload['error'] ?? '');
                $detail = $apiError !== '' ? $apiError : ($stderr !== '' ? $stderr : 'falha desconhecida');
                setFlash('error', 'Falha ao criar banco adicional: ' . $detail);
            }

            redirectTo(baseUrl(['tab' => 'database']));
        }

        if ($action === 'cron_add') {
            $siteUser = sanitizeSiteUser((string) ($_POST['site_user'] ?? ''));
            $expression = sanitizeCronExpression((string) ($_POST['cron_expression'] ?? ''));
            $command = sanitizeCronCommand((string) ($_POST['cron_command'] ?? ''));
            $runInPublicHtml = !empty($_POST['run_in_public_html']) ? '1' : '0';

            if ($siteUser === '') {
                throw new RuntimeException('Site invalido para cron.');
            }
            if ($expression === '' || $command === '') {
                throw new RuntimeException('Expressao ou comando cron invalido.');
            }

            [$code, $out, $stderr] = panelExec(['cron-add', $siteUser, $expression, $command, $runInPublicHtml]);
            $payload = decodeJson($out);
            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                setFlash('success', 'Entrada cron adicionada para ' . $siteUser . '.');
            } else {
                $apiError = (string) ($payload['error'] ?? '');
                $detail = $apiError !== '' ? $apiError : ($stderr !== '' ? $stderr : 'falha desconhecida');
                setFlash('error', 'Falha ao adicionar cron: ' . $detail);
            }
            redirectTo(baseUrl(['tab' => 'system', 'cron_site' => $siteUser]));
        }

        if ($action === 'cron_remove') {
            $siteUser = sanitizeSiteUser((string) ($_POST['site_user'] ?? ''));
            $lineToken = trim((string) ($_POST['cron_line_token'] ?? ''));
            $line = b64urlDecode($lineToken);

            if ($siteUser === '' || $line === '') {
                throw new RuntimeException('Dados invalidos para remover cron.');
            }

            [$code, $out, $stderr] = panelExec(['cron-remove', $siteUser, $line]);
            $payload = decodeJson($out);
            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                setFlash('success', 'Entrada cron removida para ' . $siteUser . '.');
            } else {
                $apiError = (string) ($payload['error'] ?? '');
                $detail = $apiError !== '' ? $apiError : ($stderr !== '' ? $stderr : 'falha desconhecida');
                setFlash('error', 'Falha ao remover cron: ' . $detail);
            }
            redirectTo(baseUrl(['tab' => 'system', 'cron_site' => $siteUser]));
        }

        if ($action === 'suspend_site' || $action === 'reactivate_site') {
            $siteUser = sanitizeSiteUser((string) ($_POST['site_user'] ?? ''));
            if ($siteUser === '') {
                throw new RuntimeException('Site invalido.');
            }

            $cmd = $action === 'suspend_site' ? 'suspend-site' : 'reactivate-site';
            [$code, , $stderr] = panelExec([$cmd, $siteUser]);
            if ($code === 0) {
                setFlash('success', 'Acao executada para ' . $siteUser . '.');
            } else {
                setFlash('error', 'Falha na acao: ' . $stderr);
            }
            redirectTo(baseUrl(['tab' => 'sites']));
        }

        if ($action === 'file_save') {
            $siteUser = sanitizeSiteUser((string) ($_POST['site_user'] ?? ''));
            $filePath = sanitizeRelPath((string) ($_POST['file_path'] ?? ''));
            $fileContent = (string) ($_POST['file_content'] ?? '');

            if ($siteUser === '' || $filePath === '') {
                throw new RuntimeException('Parametros invalidos para salvar arquivo.');
            }

            [$code, , $stderr] = panelExec(['file-write', $siteUser, $filePath], $fileContent);
            if ($code === 0) {
                setFlash('success', 'Arquivo salvo: ' . $filePath);
            } else {
                setFlash('error', 'Falha ao salvar arquivo: ' . $stderr);
            }

            redirectTo(baseUrl([
                'tab' => 'files',
                'site' => $siteUser,
                'path' => dirname($filePath) === '.' ? '' : dirname($filePath),
                'edit' => $filePath,
            ]));
        }

        if ($action === 'file_delete') {
            $siteUser = sanitizeSiteUser((string) ($_POST['site_user'] ?? ''));
            $targetPath = sanitizeRelPath((string) ($_POST['target_path'] ?? ''));
            $currentPath = sanitizeRelPath((string) ($_POST['current_path'] ?? ''));

            if ($siteUser === '' || $targetPath === '') {
                throw new RuntimeException('Parametros invalidos para exclusao.');
            }

            [$code, , $stderr] = panelExec(['file-delete', $siteUser, $targetPath]);
            if ($code === 0) {
                setFlash('success', 'Alvo removido: ' . $targetPath);
            } else {
                setFlash('error', 'Falha ao remover alvo: ' . $stderr);
            }

            redirectTo(baseUrl(['tab' => 'files', 'site' => $siteUser, 'path' => $currentPath]));
        }

        if ($action === 'file_mkdir') {
            $siteUser = sanitizeSiteUser((string) ($_POST['site_user'] ?? ''));
            $currentPath = sanitizeRelPath((string) ($_POST['current_path'] ?? ''));
            $newDir = trim((string) ($_POST['new_dir'] ?? ''));
            $newDir = trim($newDir, '/ ');

            if ($siteUser === '' || $newDir === '' || str_contains($newDir, '..')) {
                throw new RuntimeException('Nome de diretorio invalido.');
            }

            $target = sanitizeRelPath(($currentPath === '' ? '' : $currentPath . '/') . $newDir);
            if ($target === '') {
                throw new RuntimeException('Diretorio invalido.');
            }

            [$code, , $stderr] = panelExec(['file-mkdir', $siteUser, $target]);
            if ($code === 0) {
                setFlash('success', 'Diretorio criado: ' . $target);
            } else {
                setFlash('error', 'Falha ao criar diretorio: ' . $stderr);
            }

            redirectTo(baseUrl(['tab' => 'files', 'site' => $siteUser, 'path' => $currentPath]));
        }

        if ($action === 'file_upload') {
            $siteUser = sanitizeSiteUser((string) ($_POST['site_user'] ?? ''));
            $currentPath = sanitizeRelPath((string) ($_POST['current_path'] ?? ''));
            $file = $_FILES['upload_file'] ?? null;

            if ($siteUser === '' || !is_array($file) || ($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                throw new RuntimeException('Falha no upload.');
            }

            $name = basename((string) ($file['name'] ?? 'arquivo.bin'));
            if ($name === '' || str_contains($name, '..')) {
                throw new RuntimeException('Nome de arquivo invalido.');
            }

            $target = sanitizeRelPath(($currentPath === '' ? '' : $currentPath . '/') . $name);
            $content = file_get_contents((string) $file['tmp_name']);
            if ($content === false) {
                throw new RuntimeException('Nao foi possivel ler arquivo temporario.');
            }

            [$code, , $stderr] = panelExec(['file-write', $siteUser, $target], $content);
            if ($code === 0) {
                setFlash('success', 'Upload concluido: ' . $target);
            } else {
                setFlash('error', 'Falha no upload: ' . $stderr);
            }

            redirectTo(baseUrl(['tab' => 'files', 'site' => $siteUser, 'path' => $currentPath]));
        }

        if ($action === 'stack_install_base') {
            $tab = 'system';
            [$code, $out, $stderr] = panelExec(['install-stack-base']);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $details = ['OpenLiteSpeed panel: ' . (string) ($payload['panel_url'] ?? 'http://localhost:7080')];
                if (($payload['phpmyadmin'] ?? 'ok') !== 'ok') {
                    $details[] = 'phpMyAdmin reported a warning during installation.';
                }
                $actionResult = [
                    'type' => 'success',
                    'title' => 'Stack base instalada',
                    'text' => 'Repositorios e servicos principais foram processados.',
                    'details' => $details,
                ];
            } else {
                $detail = (string) ($payload['error'] ?? ($stderr !== '' ? $stderr : 'falha desconhecida'));
                $actionResult = [
                    'type' => 'error',
                    'title' => 'Falha ao instalar stack base',
                    'text' => $detail,
                ];
            }
        }

        if ($action === 'cloudflare_login_start') {
            $tab = 'system';
            [$code, $out, $stderr] = panelExec(['cloudflare-login-start']);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $authenticated = !empty($payload['authenticated']);
                $details = [];
                $title = 'Status do Cloudflare';
                $text = $authenticated
                    ? 'Cloudflare ja autenticado para criacao de tunnels.'
                    : 'Fluxo de login do Cloudflare iniciado.';

                $loginUrl = (string) ($payload['login_url'] ?? '');
                $logFile = (string) ($payload['log_file'] ?? '');
                if ($loginUrl !== '') {
                    $details[] = 'Abra a URL de autorizacao: ' . $loginUrl;
                }
                if ($logFile !== '') {
                    $details[] = 'Log do processo: ' . $logFile;
                }

                $actionResult = [
                    'type' => 'success',
                    'title' => $title,
                    'text' => $text,
                    'details' => $details,
                    'pre' => (string) ($payload['log_excerpt'] ?? ''),
                ];
            } else {
                $detail = (string) ($payload['error'] ?? ($stderr !== '' ? $stderr : 'falha desconhecida'));
                $actionResult = [
                    'type' => 'error',
                    'title' => 'Falha ao iniciar login do Cloudflare',
                    'text' => $detail,
                ];
            }
        }

        if ($action === 'ols_set_admin_password') {
            $tab = 'system';
            $adminUser = trim((string) ($_POST['ols_admin_user'] ?? 'admin'));
            $adminPass = (string) ($_POST['ols_admin_password'] ?? '');
            $adminPassConfirm = (string) ($_POST['ols_admin_password_confirm'] ?? '');

            if ($adminUser === '' || preg_match('/^[a-zA-Z0-9._-]{1,32}$/', $adminUser) !== 1) {
                throw new RuntimeException('Usuario do OLS invalido.');
            }
            if ($adminPass === '' || strlen($adminPass) < 8) {
                throw new RuntimeException('A senha do OLS deve ter ao menos 8 caracteres.');
            }
            if (!hash_equals($adminPass, $adminPassConfirm)) {
                throw new RuntimeException('A confirmacao da senha do OLS nao confere.');
            }

            [$code, $out, $stderr] = panelExec(['ols-set-admin', $adminUser, $adminPass]);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $actionResult = [
                    'type' => 'success',
                    'title' => 'Credenciais do OLS atualizadas',
                    'text' => 'Usuario atualizado: ' . (string) ($payload['user'] ?? $adminUser),
                    'pre' => (string) ($payload['output'] ?? ''),
                ];
            } else {
                $detail = (string) ($payload['error'] ?? ($stderr !== '' ? $stderr : 'falha desconhecida'));
                $actionResult = [
                    'type' => 'error',
                    'title' => 'Falha ao atualizar credenciais do OLS',
                    'text' => $detail,
                ];
            }
        }

        if ($action === 'panel_configure_domain') {
            $tab = 'system';
            $domain = sanitizeDomainInput((string) ($_POST['panel_domain'] ?? ''));
            $createTunnel = !empty($_POST['panel_create_tunnel']) ? '1' : '0';

            if ($domain === '') {
                throw new RuntimeException('Dominio invalido para o painel web.');
            }

            [$code, $out, $stderr] = panelExec(['configure-panel-domain', $domain, $createTunnel]);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $actionResult = [
                    'type' => 'success',
                    'title' => 'Dominio do painel configurado',
                    'text' => 'Painel publicado em https://' . (string) ($payload['domain'] ?? $domain),
                    'details' => [
                        'Usuario: ' . (string) (($payload['login']['user'] ?? '') ?: 'admin'),
                        'Senha: ' . (string) (($payload['login']['pass'] ?? '') ?: '-'),
                        'Arquivo de credenciais: ' . (string) ($payload['credentials_file'] ?? ''),
                        'Tunnel: ' . (string) ($payload['tunnel'] ?? 'nao_solicitado'),
                    ],
                ];
            } else {
                $detail = (string) ($payload['error'] ?? ($stderr !== '' ? $stderr : 'falha desconhecida'));
                $actionResult = [
                    'type' => 'error',
                    'title' => 'Falha ao configurar dominio do painel',
                    'text' => $detail,
                ];
            }
        }

        if ($action === 'phpmyadmin_configure_domain') {
            $tab = 'database';
            $domain = sanitizeDomainInput((string) ($_POST['phpmyadmin_domain'] ?? ''));
            $removeOthers = !empty($_POST['phpmyadmin_remove_others']) ? '1' : '0';
            $createTunnel = !empty($_POST['phpmyadmin_create_tunnel']) ? '1' : '0';

            if ($domain === '') {
                throw new RuntimeException('Dominio invalido para o phpMyAdmin.');
            }

            [$code, $out, $stderr] = panelExec(['configure-phpmyadmin-domain', $domain, $removeOthers, $createTunnel]);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $actionResult = [
                    'type' => 'success',
                    'title' => 'phpMyAdmin configurado',
                    'text' => 'Acesso publicado em https://' . (string) ($payload['domain'] ?? $domain),
                    'details' => [
                        'Usuario dedicado: ' . (string) ($payload['user'] ?? 'phpmyadmin_srv'),
                        'Tunnel: ' . (string) ($payload['tunnel'] ?? 'nao_solicitado'),
                    ],
                ];
            } else {
                $detail = (string) ($payload['error'] ?? ($stderr !== '' ? $stderr : 'falha desconhecida'));
                $actionResult = [
                    'type' => 'error',
                    'title' => 'Falha ao configurar phpMyAdmin',
                    'text' => $detail,
                ];
            }
        }

        if ($action === 'db_rotate_password') {
            $tab = 'database';
            $siteUser = sanitizeSiteUser((string) ($_POST['site_user'] ?? ''));
            if ($siteUser === '') {
                throw new RuntimeException('Site invalido para trocar senha do banco.');
            }

            [$code, $out, $stderr] = panelExec(['db-rotate-password', $siteUser]);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $actionResult = [
                    'type' => 'success',
                    'title' => 'Senha do banco atualizada',
                    'details' => [
                        'Site: ' . (string) ($payload['site_user'] ?? $siteUser),
                        'Usuario do banco: ' . (string) ($payload['db_user'] ?? ''),
                        'Nova senha: ' . (string) ($payload['new_password'] ?? ''),
                    ],
                ];
            } else {
                $detail = (string) ($payload['error'] ?? ($stderr !== '' ? $stderr : 'falha desconhecida'));
                $actionResult = [
                    'type' => 'error',
                    'title' => 'Falha ao trocar senha do banco',
                    'text' => $detail,
                ];
            }
        }

        if ($action === 'wordpress_fix_permalink') {
            $tab = 'system';
            $siteUser = sanitizeSiteUser((string) ($_POST['site_user'] ?? ''));
            if ($siteUser === '') {
                throw new RuntimeException('Site invalido para corrigir permalink.');
            }

            [$code, $out, $stderr] = panelExec(['wordpress-fix-permalink', $siteUser]);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $actionResult = [
                    'type' => 'success',
                    'title' => 'Permalink do WordPress corrigido',
                    'text' => 'Site: ' . (string) ($payload['domain'] ?? $siteUser),
                ];
            } else {
                $detail = (string) ($payload['error'] ?? ($stderr !== '' ? $stderr : 'falha desconhecida'));
                $actionResult = [
                    'type' => 'error',
                    'title' => 'Falha ao corrigir permalink do WordPress',
                    'text' => $detail,
                ];
            }
        }

        if ($action === 'site_fix_rewrite') {
            $tab = 'system';
            $siteUser = sanitizeSiteUser((string) ($_POST['site_user'] ?? ''));
            $frontController = trim((string) ($_POST['front_controller'] ?? 'index.php'));
            if ($siteUser === '') {
                throw new RuntimeException('Site invalido para corrigir rewrite.');
            }
            if ($frontController === '' || preg_match('/^[a-zA-Z0-9._\/-]+$/', $frontController) !== 1) {
                throw new RuntimeException('Front controller invalido.');
            }

            [$code, $out, $stderr] = panelExec(['site-fix-rewrite', $siteUser, $frontController]);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $actionResult = [
                    'type' => 'success',
                    'title' => 'Rewrite padrao aplicado',
                    'details' => [
                        'Site: ' . (string) ($payload['domain'] ?? $siteUser),
                        'Front controller: ' . (string) ($payload['front_controller'] ?? $frontController),
                        '.htaccess: ' . (string) ($payload['htaccess'] ?? ''),
                    ],
                ];
            } else {
                $detail = (string) ($payload['error'] ?? ($stderr !== '' ? $stderr : 'falha desconhecida'));
                $actionResult = [
                    'type' => 'error',
                    'title' => 'Falha ao corrigir rewrite',
                    'text' => $detail,
                ];
            }
        }

        if ($action === 'github_oauth_app_save') {
            $tab = 'system';
            $clientId = sanitizeGithubClientId((string) ($_POST['github_client_id'] ?? ''));
            $scopes = sanitizeGithubScopes((string) ($_POST['github_scopes'] ?? ''));

            if ($clientId === '') {
                throw new RuntimeException('Informe um Client ID valido do GitHub OAuth App.');
            }

            if ($scopes === '') {
                $scopes = 'repo read:user user:email';
            }

            [$code, $out, $stderr] = panelExec(['github-oauth-app-set', $clientId, $scopes]);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $actionResult = [
                    'type' => 'success',
                    'title' => 'App OAuth salvo',
                    'text' => 'O painel ja pode iniciar a conexao oficial com o GitHub.',
                    'details' => [
                        'Client ID: ' . (string) ($payload['oauth_client_id'] ?? $clientId),
                        'Escopos: ' . (string) ($payload['oauth_scopes'] ?? $scopes),
                    ],
                ];
            } else {
                $detail = (string) ($payload['error'] ?? ($stderr !== '' ? $stderr : 'falha desconhecida'));
                $actionResult = [
                    'type' => 'error',
                    'title' => 'Falha ao salvar App OAuth',
                    'text' => $detail,
                ];
            }
        }

        if ($action === 'github_device_start') {
            $tab = 'system';
            [$code, $out, $stderr] = panelExec(['github-device-start']);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $verificationUri = (string) ($payload['verification_uri'] ?? '');
                $actionResult = [
                    'type' => 'success',
                    'title' => 'Autorizacao iniciada',
                    'text' => 'Abra o GitHub, informe o codigo abaixo e depois volte para verificar a conexao.',
                    'details' => array_values(array_filter([
                        (($payload['user_code'] ?? '') !== '' ? 'Codigo: ' . (string) $payload['user_code'] : ''),
                        ($verificationUri !== '' ? 'URL: ' . $verificationUri : ''),
                    ])),
                ];
            } else {
                $detail = (string) ($payload['error'] ?? ($stderr !== '' ? $stderr : 'falha desconhecida'));
                $actionResult = [
                    'type' => 'error',
                    'title' => 'Falha ao iniciar autorizacao do GitHub',
                    'text' => $detail,
                ];
            }
        }

        if ($action === 'github_device_poll') {
            $tab = 'system';
            [$code, $out, $stderr] = panelExec(['github-device-poll', '1']);
            $payload = decodeJson($out);
            $pending = !empty($payload['device_flow']['pending']);

            if ($code === 0 && ($payload['ok'] ?? false) === true && !empty($payload['configured']) && !$pending) {
                $actionResult = [
                    'type' => 'success',
                    'title' => 'GitHub conectado',
                    'text' => 'A conta foi autorizada e ja pode ser usada nos repositorios privados do painel.',
                    'details' => array_values(array_filter([
                        (($payload['username'] ?? '') !== '' ? 'Usuario: ' . (string) $payload['username'] : ''),
                        ((($payload['author_name'] ?? '') !== '' || ($payload['author_email'] ?? '') !== '') ? 'Autor Git: ' . trim((string) (($payload['author_name'] ?? '') . ' <' . ($payload['author_email'] ?? '') . '>'), ' <>') : ''),
                    ])),
                ];
            } elseif ($code === 0 && ($payload['ok'] ?? false) === true && $pending) {
                $secondsLeft = (int) ($payload['device_flow']['seconds_left'] ?? 0);
                $actionResult = [
                    'type' => 'success',
                    'title' => 'Autorizacao ainda pendente',
                    'text' => 'Finalize a permissao no GitHub e clique novamente para verificar.',
                    'details' => array_values(array_filter([
                        (($payload['device_flow']['user_code'] ?? '') !== '' ? 'Codigo: ' . (string) $payload['device_flow']['user_code'] : ''),
                        (($payload['device_flow']['verification_uri'] ?? '') !== '' ? 'URL: ' . (string) $payload['device_flow']['verification_uri'] : ''),
                        ($secondsLeft > 0 ? 'Expira em: ' . $secondsLeft . 's' : ''),
                    ])),
                ];
            } else {
                $detail = (string) ($payload['error'] ?? ($stderr !== '' ? $stderr : 'falha desconhecida'));
                $actionResult = [
                    'type' => 'error',
                    'title' => 'Falha ao verificar conexao com GitHub',
                    'text' => $detail,
                ];
            }
        }

        if ($action === 'github_config_save') {
            $tab = 'system';
            $username = sanitizeGithubUsername((string) ($_POST['github_username'] ?? ''));
            $token = sanitizeGithubToken((string) ($_POST['github_token'] ?? ''));
            $authorName = sanitizeGithubAuthorName((string) ($_POST['github_author_name'] ?? ''));
            $authorEmail = sanitizeGithubAuthorEmail((string) ($_POST['github_author_email'] ?? ''));

            if ($username === '' || $token === '' || $authorName === '' || $authorEmail === '') {
                throw new RuntimeException('Preencha usuario, token, nome e email validos para integrar o GitHub.');
            }

            [$code, $out, $stderr] = panelExec(['github-config-set', $username, $token, $authorName, $authorEmail]);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $actionResult = [
                    'type' => 'success',
                    'title' => 'GitHub configurado',
                    'text' => 'Credencial central salva para uso com repositorios privados.',
                    'details' => [
                        'Usuario: ' . (string) ($payload['username'] ?? $username),
                        'Autor Git: ' . (string) (($payload['author_name'] ?? $authorName) . ' <' . ($payload['author_email'] ?? $authorEmail) . '>'),
                        'Arquivo: ' . (string) ($payload['config_file'] ?? ''),
                    ],
                ];
            } else {
                $detail = (string) ($payload['error'] ?? ($stderr !== '' ? $stderr : 'falha desconhecida'));
                $actionResult = [
                    'type' => 'error',
                    'title' => 'Falha ao salvar credenciais do GitHub',
                    'text' => $detail,
                ];
            }
        }

        if ($action === 'github_config_clear') {
            $tab = 'system';
            [$code, $out, $stderr] = panelExec(['github-config-clear']);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $actionResult = [
                    'type' => 'success',
                    'title' => 'Credenciais do GitHub removidas',
                    'text' => 'A integracao central foi limpa do painel.',
                ];
            } else {
                $detail = (string) ($payload['error'] ?? ($stderr !== '' ? $stderr : 'falha desconhecida'));
                $actionResult = [
                    'type' => 'error',
                    'title' => 'Falha ao remover credenciais do GitHub',
                    'text' => $detail,
                ];
            }
        }

        if ($action === 'github_site_clone_start') {
            $tab = 'files';
            $siteUser = sanitizeSiteUser((string) ($_POST['site_user'] ?? ''));
            $repoSlug = sanitizeGithubRepoSlug((string) ($_POST['github_repo_slug'] ?? ''));
            $branch = sanitizeGithubBranch((string) ($_POST['github_branch'] ?? ''));
            $cleanTarget = !empty($_POST['github_clean_target']) ? '1' : '0';

            if ($siteUser === '' || $repoSlug === '') {
                throw new RuntimeException('Informe um site valido e o repositorio no formato owner/repo.');
            }

            [$code, $out, $stderr] = panelExec(['github-site-clone-start', $siteUser, $repoSlug, $branch, $cleanTarget]);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $details = [
                    'Repositorio: ' . (string) ($payload['repo'] ?? $repoSlug),
                    'Destino: ' . (string) ($payload['path'] ?? ''),
                ];
                if (($payload['branch'] ?? '') !== '') {
                    $details[] = 'Branch: ' . (string) $payload['branch'];
                }
                if (($payload['job_id'] ?? '') !== '') {
                    $details[] = 'Job: ' . (string) $payload['job_id'];
                }
                $actionResult = [
                    'type' => 'success',
                    'title' => 'Clone iniciado',
                    'text' => 'O clone foi iniciado em background para o site ' . $siteUser . '. Acompanhe o progresso logo abaixo.',
                    'details' => $details,
                ];
            } else {
                $detail = (string) ($payload['error'] ?? ($stderr !== '' ? $stderr : 'falha desconhecida'));
                $actionResult = [
                    'type' => 'error',
                    'title' => 'Falha ao iniciar clone',
                    'text' => $detail,
                ];
            }
        }

        if ($action === 'github_site_pull') {
            $tab = 'files';
            $siteUser = sanitizeSiteUser((string) ($_POST['site_user'] ?? ''));
            if ($siteUser === '') {
                throw new RuntimeException('Site invalido para atualizar repositorio.');
            }

            [$code, $out, $stderr] = panelExec(['github-site-pull', $siteUser]);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                $actionResult = [
                    'type' => 'success',
                    'title' => 'Repositorio atualizado',
                    'text' => 'Alteracoes remotas aplicadas no site ' . $siteUser . '.',
                    'details' => [
                        'Branch: ' . (string) ($payload['branch'] ?? ''),
                        'Pasta: ' . (string) ($payload['path'] ?? ''),
                    ],
                    'pre' => (string) ($payload['output'] ?? ''),
                ];
            } else {
                $detail = (string) ($payload['error'] ?? ($stderr !== '' ? $stderr : 'falha desconhecida'));
                $actionResult = [
                    'type' => 'error',
                    'title' => 'Falha ao executar pull',
                    'text' => $detail,
                ];
            }
        }

        if ($action === 'github_site_commit_push') {
            $tab = 'files';
            $siteUser = sanitizeSiteUser((string) ($_POST['site_user'] ?? ''));
            $commitMessage = sanitizeCommitMessage((string) ($_POST['github_commit_message'] ?? ''));

            if ($siteUser === '' || $commitMessage === '') {
                throw new RuntimeException('Informe um site valido e uma mensagem de commit sem quebras de linha.');
            }

            [$code, $out, $stderr] = panelExec(['github-site-commit-push', $siteUser, $commitMessage]);
            $payload = decodeJson($out);

            if ($code === 0 && ($payload['ok'] ?? false) === true) {
                if (!empty($payload['no_changes'])) {
                    $actionResult = [
                        'type' => 'success',
                        'title' => 'Nenhuma alteracao para enviar',
                        'text' => 'O repositório do site ' . $siteUser . ' ja estava sem mudancas pendentes.',
                    ];
                } else {
                    $actionResult = [
                        'type' => 'success',
                        'title' => 'Commit e push concluidos',
                        'text' => 'Alteracoes enviadas para o GitHub no site ' . $siteUser . '.',
                        'details' => [
                            'Branch: ' . (string) ($payload['branch'] ?? ''),
                            'Pasta: ' . (string) ($payload['path'] ?? ''),
                        ],
                        'pre' => trim((string) ($payload['commit_output'] ?? '') . "\n\n" . (string) ($payload['push_output'] ?? '')),
                    ];
                }
            } else {
                $detail = (string) ($payload['error'] ?? ($stderr !== '' ? $stderr : 'falha desconhecida'));
                $actionResult = [
                    'type' => 'error',
                    'title' => 'Falha ao fazer commit/push',
                    'text' => $detail,
                ];
            }
        }
    }
} catch (Throwable $e) {
    setFlash('error', $e->getMessage());
    redirectTo(baseUrl(['tab' => $tab]));
}

[$siteCode, $siteOut, $siteErr] = panelExec(['list-sites']);
$sites = $siteCode === 0 ? decodeJson($siteOut) : [];

$phpmyadminDomain = '';
$panelDomain = '';
foreach ($sites as $site) {
    if (($site['user'] ?? '') === 'phpmyadmin_srv') {
        $phpmyadminDomain = (string) ($site['domain'] ?? '');
    }
    if (($site['user'] ?? '') === 'painel_srv') {
        $panelDomain = (string) ($site['domain'] ?? '');
    }
}

$fileSite = sanitizeSiteUser((string) ($_GET['site'] ?? ''));
$filePath = sanitizeRelPath((string) ($_GET['path'] ?? ''));
$fileEdit = sanitizeRelPath((string) ($_GET['edit'] ?? ''));

$fileSites = array_values(array_filter($sites, static function (array $s): bool {
    return ($s['kind'] ?? 'site') === 'site';
}));

if ($fileSite === '' && isset($fileSites[0]['user'])) {
    $fileSite = (string) $fileSites[0]['user'];
}

$fileList = ['current' => '', 'parent' => '', 'items' => []];
$fileContent = '';
$fileReadError = '';

if ($tab === 'files' && $fileSite !== '') {
    [$code, $out, $err] = panelExec(['file-list', $fileSite, $filePath]);
    if ($code === 0) {
        $decoded = decodeJson($out);
        if ($decoded !== []) {
            $fileList = $decoded;
        }
    } else {
        $fileReadError = $err;
    }

    if ($fileEdit !== '') {
        [$code, $out, $err] = panelExec(['file-read', $fileSite, $fileEdit]);
        if ($code === 0) {
            $fileContent = $out;
        } else {
            $fileReadError = $err;
        }
    }
}

$fileItems = isset($fileList['items']) && is_array($fileList['items']) ? array_values($fileList['items']) : [];
$fileCurrentPath = (string) ($fileList['current'] ?? '');
$fileParentPath = (string) ($fileList['parent'] ?? '');
$fileBreadcrumbs = buildFileBreadcrumbs($fileCurrentPath);
$fileDirectoryCount = count(array_filter($fileItems, static fn(array $item): bool => (($item['type'] ?? 'file') === 'dir')));
$fileEntryCount = count($fileItems);
$fileTotalSize = 0;
$fileEditingItem = null;
$githubConfigStatus = [];
$githubSiteStatus = [];
$githubRepoList = [];
$githubCloneStatus = [];

foreach ($fileItems as $item) {
    $fileTotalSize += (int) ($item['size'] ?? 0);
    if ($fileEdit !== '' && (string) ($item['relpath'] ?? '') === $fileEdit) {
        $fileEditingItem = $item;
    }
}

if ($tab === 'system' || $tab === 'files') {
    [$code, $out, $err] = panelExec(['github-config-status']);
    if ($code === 0) {
        $githubConfigStatus = decodeJson($out);
    } else {
        $githubConfigStatus = ['ok' => false, 'error' => $err];
    }
}

if ($tab === 'files' && $fileSite !== '') {
    [$code, $out, $err] = panelExec(['github-site-status', $fileSite]);
    if ($code === 0) {
        $githubSiteStatus = decodeJson($out);
    } else {
        $githubSiteStatus = ['ok' => false, 'error' => $err];
    }

    [$code, $out, $err] = panelExec(['github-site-clone-status', $fileSite]);
    if ($code === 0) {
        $githubCloneStatus = decodeJson($out);
    } else {
        $githubCloneStatus = ['ok' => false, 'error' => $err];
    }

    if (!empty($githubConfigStatus['configured'])) {
        [$code, $out, $err] = panelExec(['github-repos-list']);
        if ($code === 0) {
            $githubRepoList = decodeJson($out);
        } else {
            $githubRepoList = ['ok' => false, 'error' => $err];
        }
    }
}

$githubRepos = isset($githubRepoList['repos']) && is_array($githubRepoList['repos']) ? array_values($githubRepoList['repos']) : [];
$githubCloneRunning = !empty($githubCloneStatus['running']);
$githubClonePercent = max(0, min(100, (int) ($githubCloneStatus['percent'] ?? 0)));

$serverMetrics = [];
if ($tab === 'system' || $tab === 'dashboard') {
    [$code, $out, $err] = panelExec(['server-metrics']);
    if ($code === 0) {
        $serverMetrics = decodeJson($out);
    } else {
        $serverMetrics = ['ok' => false, 'error' => $err];
    }
}

$serviceStatus = [];
if ($tab === 'system' || $tab === 'dashboard') {
    [$code, $out] = panelExec(['service-status']);
    if ($code === 0) {
        $serviceStatus = decodeJson($out);
    }
}

$cronSite = sanitizeSiteUser((string) ($_GET['cron_site'] ?? ''));
if ($cronSite === '' && isset($fileSites[0]['user'])) {
    $cronSite = (string) $fileSites[0]['user'];
}

$cronItems = [];
$cronReadError = '';
if ($tab === 'system' && $cronSite !== '') {
    [$code, $out, $err] = panelExec(['cron-list', $cronSite]);
    if ($code === 0) {
        $payload = decodeJson($out);
        if (isset($payload['items']) && is_array($payload['items'])) {
            $cronItems = $payload['items'];
        }
    } else {
        $cronReadError = $err;
    }
}

$cloudflareStatus = [];
if ($tab === 'system') {
    [$code, $out, $err] = panelExec(['cloudflare-status']);
    if ($code === 0) {
        $cloudflareStatus = decodeJson($out);
    } else {
        $cloudflareStatus = ['ok' => false, 'error' => $err];
    }
}

$diagnosticSite = sanitizeSiteUser((string) ($_GET['diag_site'] ?? ''));
if ($diagnosticSite === '' && isset($fileSites[0]['user'])) {
    $diagnosticSite = (string) $fileSites[0]['user'];
}

$diagnosticLinesRaw = trim((string) ($_GET['diag_lines'] ?? '80'));
$diagnosticLines = preg_match('/^[0-9]+$/', $diagnosticLinesRaw) === 1 ? $diagnosticLinesRaw : '80';
$diagnosticAction = (string) ($_GET['diag_action'] ?? '');
$diagnosticLog = null;
$diagnosticHtaccess = null;
$diagnosticError = '';

if ($tab === 'system' && $diagnosticSite !== '' && $diagnosticAction === 'log') {
    [$code, $out, $err] = panelExec(['site-error-log', $diagnosticSite, $diagnosticLines]);
    if ($code === 0) {
        $diagnosticLog = decodeJson($out);
    } else {
        $diagnosticError = $err;
    }
}

if ($tab === 'system' && $diagnosticSite !== '' && $diagnosticAction === 'htaccess') {
    [$code, $out, $err] = panelExec(['htaccess-verify', $diagnosticSite]);
    if ($code === 0) {
        $diagnosticHtaccess = decodeJson($out);
    } else {
        $diagnosticError = $err;
    }
}

$tabs = [
    'dashboard' => 'Dashboard',
    'sites' => 'Sites',
    'files' => 'Arquivos',
    'database' => 'Banco de Dados',
    'system' => 'Sistema',
];

$flash = pullFlash() ?? $flash;
$csrf = csrfToken();
$totalSites = count($sites);
$suspendedSites = count(array_filter($sites, static fn(array $s): bool => !empty($s['suspended'])));
$activeTunnelSites = count(array_filter($sites, static fn(array $s): bool => (($s['tunnel'] ?? '') === 'ativo')));
$cpuPercent = (float) ($serverMetrics['cpu']['percent'] ?? 0);
$memoryPercent = (float) ($serverMetrics['memory']['percent'] ?? 0);
$diskRootPercent = (float) ($serverMetrics['disk']['root']['percent'] ?? 0);
$uptimeSeconds = (int) ($serverMetrics['uptime']['seconds'] ?? 0);
$activeTabTitle = $tabs[$tab] ?? 'Dashboard';
?>
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title><?= h($panelTitle) ?></title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@500;600;700&family=Public+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      theme: {
        extend: {
          fontFamily: {
            body: ['Public Sans', 'sans-serif'],
            display: ['Outfit', 'sans-serif']
          },
          boxShadow: {
            panel: '0 10px 30px rgba(15, 23, 42, 0.08)'
          }
        }
      }
    };
  </script>
</head>
<body class="min-h-screen bg-slate-100 font-body text-slate-800 antialiased">
  <div class="min-h-screen lg:grid lg:grid-cols-[260px_1fr]">
    <aside class="border-b border-slate-200 bg-white px-4 py-5 shadow-sm lg:min-h-screen lg:border-b-0 lg:border-r lg:px-5">
      <div class="mb-6">
        <p class="text-xs font-semibold uppercase tracking-[0.2em] text-blue-600">Ultra Control</p>
        <h1 class="mt-2 font-display text-2xl font-semibold text-slate-900"><?= h($panelTitle) ?></h1>
        <p class="mt-1 text-xs text-slate-500">Painel estilo hosting admin</p>
      </div>

      <nav class="space-y-1">
        <?php foreach ($tabs as $key => $label): ?>
          <?php $active = $tab === $key; ?>
          <a href="<?= h(baseUrl(['tab' => $key])) ?>" class="group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-semibold transition <?= $active ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/30' : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900' ?>">
            <span class="<?= $active ? 'text-white' : 'text-slate-400 group-hover:text-slate-700' ?>"><?= tabIcon($key) ?></span>
            <span><?= h($label) ?></span>
          </a>
        <?php endforeach; ?>
      </nav>

      <div class="mt-6 rounded-xl border border-slate-200 bg-slate-50 p-4">
        <p class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Resumo</p>
        <dl class="mt-3 space-y-2 text-sm">
          <div class="flex items-center justify-between">
            <dt class="text-slate-600">Sites</dt>
            <dd class="font-semibold text-slate-900"><?= $totalSites ?></dd>
          </div>
          <div class="flex items-center justify-between">
            <dt class="text-slate-600">Suspensos</dt>
            <dd class="font-semibold text-amber-700"><?= $suspendedSites ?></dd>
          </div>
          <div class="flex items-center justify-between">
            <dt class="text-slate-600">Tunnel ativo</dt>
            <dd class="font-semibold text-emerald-700"><?= $activeTunnelSites ?></dd>
          </div>
        </dl>
      </div>

      <form method="post" class="mt-6">
        <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
        <input type="hidden" name="action" value="logout">
        <button type="submit" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm font-semibold text-slate-700 transition hover:bg-slate-100">Sair do painel</button>
      </form>
    </aside>

    <main class="p-4 sm:p-6 lg:p-8">
      <header class="mb-5 rounded-2xl border border-slate-200 bg-white p-4 shadow-panel sm:p-5">
        <div class="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p class="text-xs font-semibold uppercase tracking-[0.18em] text-blue-600">Area ativa</p>
            <h2 class="mt-1 font-display text-2xl font-semibold text-slate-900"><?= h($activeTabTitle) ?></h2>
          </div>
          <div class="text-xs text-slate-500">Dominio do painel: <span class="font-semibold text-slate-700"><?= h($panelDomain !== '' ? $panelDomain : 'nao configurado') ?></span></div>
        </div>
      </header>

      <?php if ($flash): ?>
        <div class="mb-5 rounded-xl border px-4 py-3 text-sm <?= h(flashUiClass((string) ($flash['type'] ?? 'error'))) ?>">
          <?= h((string) ($flash['text'] ?? 'Falha inesperada.')) ?>
        </div>
      <?php endif; ?>

      <?php if (is_array($actionResult)): ?>
        <div class="mb-5 rounded-xl border px-4 py-3 text-sm <?= h(flashUiClass((string) ($actionResult['type'] ?? 'error'))) ?>">
          <p class="font-semibold"><?= h((string) ($actionResult['title'] ?? 'Resultado')) ?></p>
          <?php if (($actionResult['text'] ?? '') !== ''): ?>
            <p class="mt-1"><?= h((string) $actionResult['text']) ?></p>
          <?php endif; ?>
          <?php foreach (($actionResult['details'] ?? []) as $detail): ?>
            <p class="mt-1 font-mono text-xs break-all"><?= h((string) $detail) ?></p>
          <?php endforeach; ?>
          <?php if (($actionResult['pre'] ?? '') !== ''): ?>
            <pre class="mt-3 overflow-x-auto rounded-lg bg-white/60 p-3 font-mono text-xs text-slate-800"><?= h((string) $actionResult['pre']) ?></pre>
          <?php endif; ?>
        </div>
      <?php endif; ?>

      <?php if ($siteCode !== 0): ?>
        <div class="mb-5 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">Falha ao carregar sites: <?= h($siteErr) ?></div>
      <?php endif; ?>

      <?php if ($tab === 'dashboard'): ?>
        <?php if (($serverMetrics['error'] ?? '') !== ''): ?>
          <div class="mb-5 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">Falha ao carregar metricas do servidor: <?= h((string) $serverMetrics['error']) ?></div>
        <?php endif; ?>

        <section class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <article class="rounded-2xl border border-slate-200 bg-white p-5 shadow-panel">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">Sites totais</p>
            <p class="mt-3 font-display text-3xl font-semibold text-slate-900"><?= $totalSites ?></p>
          </article>
          <article class="rounded-2xl border border-slate-200 bg-white p-5 shadow-panel">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">Sites suspensos</p>
            <p class="mt-3 font-display text-3xl font-semibold text-amber-700"><?= $suspendedSites ?></p>
          </article>
          <article class="rounded-2xl border border-slate-200 bg-white p-5 shadow-panel">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">Tunnel ativo</p>
            <p class="mt-3 font-display text-3xl font-semibold text-emerald-700"><?= $activeTunnelSites ?></p>
          </article>
          <article class="rounded-2xl border border-slate-200 bg-white p-5 shadow-panel">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">Dominio</p>
            <p class="mt-3 break-all text-sm font-semibold text-slate-700"><?= h($panelDomain !== '' ? $panelDomain : '-') ?></p>
          </article>
        </section>

        <section class="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <article class="rounded-2xl border border-slate-200 bg-white p-5 shadow-panel">
            <div class="flex items-center justify-between gap-3">
              <p class="text-xs uppercase tracking-[0.16em] text-slate-500">Uso de CPU</p>
              <span class="text-xs font-semibold text-slate-400"><?= h((string) ($serverMetrics['cpu']['cores'] ?? '-')) ?> core(s)</span>
            </div>
            <p class="mt-3 font-display text-3xl font-semibold text-slate-900"><?= h(formatPercentUi($cpuPercent)) ?></p>
            <div class="mt-3 h-2 rounded-full bg-slate-100">
              <div class="h-2 rounded-full <?= h(metricBarClass($cpuPercent)) ?>" style="width: <?= h((string) max(2, min(100, $cpuPercent))) ?>%"></div>
            </div>
            <p class="mt-3 text-xs text-slate-500">Load: <?= h((string) (($serverMetrics['cpu']['load']['one'] ?? '0') . ' / ' . ($serverMetrics['cpu']['load']['five'] ?? '0') . ' / ' . ($serverMetrics['cpu']['load']['fifteen'] ?? '0'))) ?></p>
          </article>

          <article class="rounded-2xl border border-slate-200 bg-white p-5 shadow-panel">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">Uso de RAM</p>
            <p class="mt-3 font-display text-3xl font-semibold text-slate-900"><?= h(formatPercentUi($memoryPercent)) ?></p>
            <div class="mt-3 h-2 rounded-full bg-slate-100">
              <div class="h-2 rounded-full <?= h(metricBarClass($memoryPercent)) ?>" style="width: <?= h((string) max(2, min(100, $memoryPercent))) ?>%"></div>
            </div>
            <p class="mt-3 text-xs text-slate-500"><?= h(formatBytesUi((int) ($serverMetrics['memory']['used'] ?? 0))) ?> de <?= h(formatBytesUi((int) ($serverMetrics['memory']['total'] ?? 0))) ?></p>
          </article>

          <article class="rounded-2xl border border-slate-200 bg-white p-5 shadow-panel">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">Disco raiz</p>
            <p class="mt-3 font-display text-3xl font-semibold text-slate-900"><?= h(formatPercentUi($diskRootPercent)) ?></p>
            <div class="mt-3 h-2 rounded-full bg-slate-100">
              <div class="h-2 rounded-full <?= h(metricBarClass($diskRootPercent)) ?>" style="width: <?= h((string) max(2, min(100, $diskRootPercent))) ?>%"></div>
            </div>
            <p class="mt-3 text-xs text-slate-500"><?= h(formatBytesUi((int) ($serverMetrics['disk']['root']['used'] ?? 0))) ?> usados em <?= h((string) ($serverMetrics['disk']['root']['mount'] ?? '/')) ?></p>
          </article>

          <article class="rounded-2xl border border-slate-200 bg-white p-5 shadow-panel">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">Uptime</p>
            <p class="mt-3 font-display text-3xl font-semibold text-slate-900"><?= h(formatUptimeUi($uptimeSeconds)) ?></p>
            <p class="mt-3 text-xs text-slate-500">Servidor ativo continuamente desde o ultimo boot.</p>
          </article>
        </section>

        <section class="mt-5 rounded-2xl border border-slate-200 bg-white p-5 shadow-panel">
          <h3 class="font-display text-xl font-semibold text-slate-900">Status de servicos</h3>
          <div class="mt-4 flex flex-wrap gap-2">
            <?php foreach ($serviceStatus as $svc): ?>
              <?php
              $svcName = (string) ($svc['service'] ?? '-');
              $svcState = (string) ($svc['status'] ?? 'missing');
              ?>
              <span class="rounded-full px-3 py-1 text-sm font-semibold <?= h(serviceStatusUiClass($svcState)) ?>">
                <?= h($svcName) ?>: <?= h($svcState) ?>
              </span>
            <?php endforeach; ?>
          </div>
        </section>

        <?php if (!empty($serverMetrics['disk']['mounts']) && is_array($serverMetrics['disk']['mounts'])): ?>
          <section class="mt-5 rounded-2xl border border-slate-200 bg-white p-5 shadow-panel">
            <h3 class="font-display text-xl font-semibold text-slate-900">Uso de disco por particao</h3>
            <div class="mt-4 overflow-x-auto rounded-xl border border-slate-200">
              <table class="min-w-full divide-y divide-slate-200 text-sm">
                <thead class="bg-slate-50 text-left text-xs uppercase tracking-[0.14em] text-slate-500">
                  <tr>
                    <th class="px-4 py-3">Mount</th>
                    <th class="px-4 py-3">Filesystem</th>
                    <th class="px-4 py-3">Uso</th>
                    <th class="px-4 py-3">Livre</th>
                    <th class="px-4 py-3">Percentual</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-200 bg-white">
                  <?php foreach ($serverMetrics['disk']['mounts'] as $mount): ?>
                    <?php $mountPercent = (float) ($mount['percent'] ?? 0); ?>
                    <tr class="hover:bg-slate-50">
                      <td class="px-4 py-3 font-semibold text-slate-900"><?= h((string) ($mount['mount'] ?? '-')) ?></td>
                      <td class="px-4 py-3 text-slate-600"><?= h((string) ($mount['filesystem'] ?? '-')) ?></td>
                      <td class="px-4 py-3 text-slate-600"><?= h(formatBytesUi((int) ($mount['used'] ?? 0))) ?></td>
                      <td class="px-4 py-3 text-slate-600"><?= h(formatBytesUi((int) ($mount['available'] ?? 0))) ?></td>
                      <td class="px-4 py-3">
                        <div class="flex min-w-[180px] items-center gap-3">
                          <div class="h-2 flex-1 rounded-full bg-slate-100">
                            <div class="h-2 rounded-full <?= h(metricBarClass($mountPercent)) ?>" style="width: <?= h((string) max(2, min(100, $mountPercent))) ?>%"></div>
                          </div>
                          <span class="w-14 text-right text-xs font-semibold text-slate-700"><?= h(formatPercentUi($mountPercent)) ?></span>
                        </div>
                      </td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
          </section>
        <?php endif; ?>
      <?php endif; ?>

      <?php if ($tab === 'sites'): ?>
        <section class="rounded-2xl border border-slate-200 bg-white p-5 shadow-panel">
          <div class="mb-4 flex items-center justify-between gap-4">
            <h3 class="font-display text-xl font-semibold text-slate-900">Gerenciamento de sites</h3>
            <span class="rounded-full bg-blue-50 px-3 py-1 text-xs font-semibold uppercase tracking-[0.14em] text-blue-700"><?= $totalSites ?> registros</span>
          </div>

          <form method="post" class="mb-5 rounded-xl border border-slate-200 bg-slate-50 p-4">
            <h4 class="font-display text-lg font-semibold text-slate-900">Criar novo site</h4>
            <p class="mt-1 text-sm text-slate-600">Fluxo completo: usuário Linux, vhost, banco principal e opcionalmente WordPress/Tunnel.</p>
            <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
            <input type="hidden" name="action" value="site_create">

            <div class="mt-4 grid gap-3 md:grid-cols-4">
              <div class="md:col-span-2">
                <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Dominio</label>
                <input name="site_domain" placeholder="ex: meusite.com" required class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
              </div>
              <div>
                <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">PHP</label>
                <select name="php_version" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                  <option value="8.4">8.4</option>
                  <option value="8.3">8.3</option>
                  <option value="8.2">8.2</option>
                  <option value="8.1">8.1</option>
                </select>
              </div>
              <div class="flex items-end">
                <button type="submit" class="w-full rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700">Criar site</button>
              </div>
            </div>

            <div class="mt-3 flex flex-wrap gap-5 text-sm">
              <label class="inline-flex items-center gap-2 text-slate-700">
                <input type="checkbox" name="install_wp" value="1" class="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500">
                Instalar WordPress automaticamente
              </label>
              <label class="inline-flex items-center gap-2 text-slate-700">
                <input type="checkbox" name="create_tunnel" value="1" class="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500">
                Criar tunnel Cloudflare para o site
              </label>
            </div>
          </form>

          <form method="post" class="mb-5 rounded-xl border border-slate-200 bg-slate-50 p-4">
            <h4 class="font-display text-lg font-semibold text-slate-900">Clonar site</h4>
            <p class="mt-1 text-sm text-slate-600">Clona arquivos e banco principal para um novo domínio.</p>
            <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
            <input type="hidden" name="action" value="site_clone">

            <div class="mt-4 grid gap-3 md:grid-cols-4">
              <div>
                <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Origem</label>
                <select name="source_user" required class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                  <?php foreach ($fileSites as $site): ?>
                    <?php $user = (string) ($site['user'] ?? ''); ?>
                    <option value="<?= h($user) ?>"><?= h($user . ' (' . ((string) ($site['domain'] ?? '-')) . ')') ?></option>
                  <?php endforeach; ?>
                </select>
              </div>
              <div class="md:col-span-2">
                <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Domínio destino</label>
                <input name="target_domain" placeholder="ex: clone.meusite.com" required class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
              </div>
              <div>
                <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">PHP destino</label>
                <select name="php_version" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                  <option value="8.4">8.4</option>
                  <option value="8.3">8.3</option>
                  <option value="8.2">8.2</option>
                  <option value="8.1">8.1</option>
                </select>
              </div>
            </div>

            <div class="mt-3 flex items-center justify-between gap-4">
              <label class="inline-flex items-center gap-2 text-sm text-slate-700">
                <input type="checkbox" name="create_tunnel" value="1" class="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500">
                Criar tunnel Cloudflare no clone
              </label>
              <button type="submit" class="rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-indigo-700">Clonar site</button>
            </div>
          </form>

          <div class="overflow-x-auto rounded-xl border border-slate-200">
            <table class="min-w-full divide-y divide-slate-200 text-sm">
              <thead class="bg-slate-50 text-left text-xs uppercase tracking-[0.14em] text-slate-500">
                <tr>
                  <th class="px-4 py-3">Usuario</th>
                  <th class="px-4 py-3">Dominio</th>
                  <th class="px-4 py-3">Status</th>
                  <th class="px-4 py-3">Tunnel</th>
                  <th class="px-4 py-3">Acoes</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-200 bg-white">
                <?php foreach ($sites as $site): ?>
                  <?php
                  $user = (string) ($site['user'] ?? '');
                  $isSuspended = !empty($site['suspended']);
                  $tunnel = (string) ($site['tunnel'] ?? 'inativo');
                  $isInfra = (($site['kind'] ?? 'site') !== 'site');
                  ?>
                  <tr class="hover:bg-slate-50">
                    <td class="px-4 py-3 font-semibold text-slate-900"><?= h($user) ?></td>
                    <td class="px-4 py-3 text-slate-600"><?= h((string) ($site['domain'] ?? '-')) ?></td>
                    <td class="px-4 py-3">
                      <span class="rounded-full px-2.5 py-1 text-xs font-semibold <?= $isSuspended ? 'bg-amber-100 text-amber-700 ring-1 ring-amber-200' : 'bg-emerald-100 text-emerald-700 ring-1 ring-emerald-200' ?>"><?= $isSuspended ? 'Suspenso' : 'Ativo' ?></span>
                    </td>
                    <td class="px-4 py-3">
                      <span class="rounded-full px-2.5 py-1 text-xs font-semibold <?= $tunnel === 'ativo' ? 'bg-blue-100 text-blue-700 ring-1 ring-blue-200' : 'bg-slate-100 text-slate-700 ring-1 ring-slate-200' ?>"><?= h($tunnel) ?></span>
                    </td>
                    <td class="px-4 py-3">
                      <?php if (!$isInfra): ?>
                        <div class="flex flex-wrap gap-2">
                          <form method="post">
                            <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                            <input type="hidden" name="action" value="suspend_site">
                            <input type="hidden" name="site_user" value="<?= h($user) ?>">
                            <button type="submit" class="rounded-lg border border-rose-200 bg-rose-50 px-3 py-1.5 text-xs font-semibold text-rose-700 transition hover:bg-rose-100">Suspender</button>
                          </form>
                          <form method="post">
                            <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                            <input type="hidden" name="action" value="reactivate_site">
                            <input type="hidden" name="site_user" value="<?= h($user) ?>">
                            <button type="submit" class="rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-1.5 text-xs font-semibold text-emerald-700 transition hover:bg-emerald-100">Reativar</button>
                          </form>
                          <form method="post" onsubmit="return confirm('Remover site ' + <?= json_encode($user) ?> + '? Esta acao apaga arquivos, banco e vhost.');">
                            <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                            <input type="hidden" name="action" value="site_remove">
                            <input type="hidden" name="site_user" value="<?= h($user) ?>">
                            <input type="hidden" name="with_backup" value="1">
                            <button type="submit" class="rounded-lg border border-rose-300 bg-rose-100 px-3 py-1.5 text-xs font-semibold text-rose-700 transition hover:bg-rose-200">Remover</button>
                          </form>
                        </div>
                      <?php else: ?>
                        <span class="text-xs font-semibold uppercase tracking-[0.14em] text-slate-400">Infra</span>
                      <?php endif; ?>
                    </td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        </section>
      <?php endif; ?>

      <?php if ($tab === 'files'): ?>
        <section class="rounded-2xl border border-slate-200 bg-white p-5 shadow-panel">
          <?php
          $fileSiteDomain = '-';
          foreach ($fileSites as $site) {
              if ((string) ($site['user'] ?? '') === $fileSite) {
                  $fileSiteDomain = (string) ($site['domain'] ?? '-');
                  break;
              }
          }
          ?>

          <div class="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p class="text-xs font-semibold uppercase tracking-[0.2em] text-blue-600">Workspace</p>
              <h3 class="mt-1 font-display text-xl font-semibold text-slate-900">Gerenciador de arquivos</h3>
              <p class="mt-1 text-sm text-slate-500">Navegue pelos arquivos do site, edite rapidamente e mantenha a estrutura organizada.</p>
            </div>
            <?php if ($fileSite !== ''): ?>
              <div class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm">
                <p class="font-semibold text-slate-900"><?= h($fileSite) ?></p>
                <p class="text-slate-500"><?= h($fileSiteDomain) ?></p>
              </div>
            <?php endif; ?>
          </div>

          <form method="get" class="mt-5 grid gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4 sm:grid-cols-2 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,1.5fr)_auto]">
            <input type="hidden" name="tab" value="files">

            <div>
              <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Site</label>
              <select name="site" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                <?php foreach ($fileSites as $site): ?>
                  <?php $user = (string) ($site['user'] ?? ''); ?>
                  <option value="<?= h($user) ?>" <?= $user === $fileSite ? 'selected' : '' ?>><?= h($user . ' (' . ((string) ($site['domain'] ?? '-')) . ')') ?></option>
                <?php endforeach; ?>
              </select>
            </div>

            <div>
              <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Pasta relativa</label>
              <input name="path" value="<?= h($filePath) ?>" placeholder="ex: wp-content/themes" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
            </div>

            <div class="flex items-end">
              <button type="submit" class="w-full rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700">Abrir pasta</button>
            </div>
          </form>

          <?php if ($fileReadError !== ''): ?>
            <div class="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"><?= h($fileReadError) ?></div>
          <?php endif; ?>

          <?php if ($fileSite !== ''): ?>
            <div class="mt-5 grid gap-4 xl:grid-cols-4">
              <div class="rounded-2xl border border-slate-200 bg-gradient-to-br from-slate-900 to-slate-800 p-4 text-white xl:col-span-2">
                <p class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-300">Caminho atual</p>
                <div class="mt-3 flex flex-wrap items-center gap-2 text-sm">
                  <?php foreach ($fileBreadcrumbs as $index => $crumb): ?>
                    <?php $isLastCrumb = $index === array_key_last($fileBreadcrumbs); ?>
                    <a href="<?= h(baseUrl(['tab' => 'files', 'site' => $fileSite, 'path' => (string) $crumb['path']])) ?>" class="rounded-full px-3 py-1.5 <?= $isLastCrumb ? 'bg-white text-slate-900' : 'bg-white/10 text-slate-100 hover:bg-white/20' ?> transition">
                      <?= h((string) $crumb['label']) ?>
                    </a>
                    <?php if (!$isLastCrumb): ?>
                      <span class="text-slate-500">/</span>
                    <?php endif; ?>
                  <?php endforeach; ?>
                </div>
                <p class="mt-3 break-all text-sm text-slate-300">/home/<?= h($fileSite) ?>/public_html<?= $fileCurrentPath !== '' ? '/' . h($fileCurrentPath) : '' ?></p>
                <div class="mt-4 flex flex-wrap gap-2">
                  <a href="<?= h(baseUrl(['tab' => 'files', 'site' => $fileSite, 'path' => ''])) ?>" class="rounded-xl border border-white/15 bg-white/10 px-3 py-2 text-xs font-semibold text-white transition hover:bg-white/20">Raiz do site</a>
                  <?php if ($fileParentPath !== '' || $filePath !== ''): ?>
                    <a href="<?= h(baseUrl(['tab' => 'files', 'site' => $fileSite, 'path' => $fileParentPath])) ?>" class="rounded-xl border border-white/15 bg-white/10 px-3 py-2 text-xs font-semibold text-white transition hover:bg-white/20">Voltar um nivel</a>
                  <?php endif; ?>
                </div>
              </div>

              <div class="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <p class="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Itens na pasta</p>
                <p class="mt-2 font-display text-3xl font-semibold text-slate-900"><?= h((string) $fileEntryCount) ?></p>
                <p class="mt-1 text-sm text-slate-500"><?= h((string) $fileDirectoryCount) ?> pasta(s) e <?= h((string) ($fileEntryCount - $fileDirectoryCount)) ?> arquivo(s)</p>
              </div>

              <div class="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <p class="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Volume listado</p>
                <p class="mt-2 font-display text-3xl font-semibold text-slate-900"><?= h(formatBytesUi($fileTotalSize)) ?></p>
                <p class="mt-1 text-sm text-slate-500"><?= $fileEdit !== '' ? 'Editor aberto para um arquivo.' : 'Nenhum arquivo em edicao no momento.' ?></p>
              </div>
            </div>

            <div class="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1.85fr)_minmax(320px,0.95fr)]">
              <div class="min-w-0">
                <div class="rounded-2xl border border-slate-200 bg-white">
                  <div class="flex flex-col gap-3 border-b border-slate-200 px-4 py-4 lg:flex-row lg:items-center lg:justify-between">
                    <div>
                      <h4 class="font-display text-lg font-semibold text-slate-900">Conteudo da pasta</h4>
                      <p class="mt-1 text-sm text-slate-500">Visual profissional com leitura rapida de tipo, tamanho e ultima modificacao.</p>
                    </div>
                    <div class="w-full lg:max-w-xs">
                      <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Filtro rapido</label>
                      <input
                        type="search"
                        placeholder="Filtrar por nome"
                        class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
                        oninput="const q=this.value.toLowerCase(); document.querySelectorAll('[data-file-row]').forEach((row)=>{row.classList.toggle('hidden', !row.dataset.search.includes(q));});"
                      >
                    </div>
                  </div>

                  <?php if ($fileItems === []): ?>
                    <div class="px-6 py-12 text-center">
                      <div class="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 text-slate-500">
                        <svg viewBox="0 0 24 24" fill="none" class="h-7 w-7" stroke="currentColor" stroke-width="1.8"><path d="M3 6a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6Z"/></svg>
                      </div>
                      <h5 class="mt-4 font-display text-lg font-semibold text-slate-900">Pasta vazia</h5>
                      <p class="mt-1 text-sm text-slate-500">Use as acoes laterais para criar um diretorio ou enviar arquivos para este local.</p>
                    </div>
                  <?php else: ?>
                    <div class="overflow-x-auto">
                      <table class="min-w-full divide-y divide-slate-200 text-sm">
                        <thead class="bg-slate-50 text-left text-xs uppercase tracking-[0.14em] text-slate-500">
                          <tr>
                            <th class="px-4 py-3">Nome</th>
                            <th class="px-4 py-3">Tipo</th>
                            <th class="px-4 py-3">Tamanho</th>
                            <th class="px-4 py-3">Modificado</th>
                            <th class="px-4 py-3">Acoes</th>
                          </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-200 bg-white">
                          <?php foreach ($fileItems as $item): ?>
                            <?php
                            $name = (string) ($item['name'] ?? '');
                            $type = (string) ($item['type'] ?? 'file');
                            $rel = (string) ($item['relpath'] ?? '');
                            $size = (int) ($item['size'] ?? 0);
                            $mtime = (int) ($item['mtime'] ?? 0);
                            ?>
                            <tr data-file-row data-search="<?= h(strtolower($name . ' ' . $type)) ?>" class="hover:bg-slate-50">
                              <td class="px-4 py-3">
                                <div class="flex items-center gap-3">
                                  <div class="flex h-10 w-10 items-center justify-center rounded-xl bg-slate-100">
                                    <?= fileTypeIcon($type) ?>
                                  </div>
                                  <div class="min-w-0">
                                    <p class="truncate font-semibold text-slate-900"><?= h($name) ?></p>
                                    <p class="truncate text-xs text-slate-500"><?= h($rel) ?></p>
                                  </div>
                                </div>
                              </td>
                              <td class="px-4 py-3">
                                <span class="rounded-full px-2.5 py-1 text-xs font-semibold <?= h(fileTypeBadgeClass($type)) ?>"><?= h(fileTypeLabel($type)) ?></span>
                              </td>
                              <td class="px-4 py-3 text-slate-600"><?= h($type === 'dir' ? '--' : formatBytesUi($size)) ?></td>
                              <td class="px-4 py-3 text-slate-600"><?= h(formatUnixTimeUi($mtime)) ?></td>
                              <td class="px-4 py-3">
                                <div class="flex flex-wrap gap-2">
                                  <?php if ($type === 'dir'): ?>
                                    <a href="<?= h(baseUrl(['tab' => 'files', 'site' => $fileSite, 'path' => $rel])) ?>" class="rounded-lg border border-blue-200 bg-blue-50 px-3 py-1.5 text-xs font-semibold text-blue-700 transition hover:bg-blue-100">Abrir</a>
                                  <?php else: ?>
                                    <a href="<?= h(baseUrl(['tab' => 'files', 'site' => $fileSite, 'path' => $fileCurrentPath, 'edit' => $rel])) ?>" class="rounded-lg border border-indigo-200 bg-indigo-50 px-3 py-1.5 text-xs font-semibold text-indigo-700 transition hover:bg-indigo-100">Editar</a>
                                  <?php endif; ?>

                                  <form method="post" onsubmit="return confirm('Remover este item?');">
                                    <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                                    <input type="hidden" name="action" value="file_delete">
                                    <input type="hidden" name="site_user" value="<?= h($fileSite) ?>">
                                    <input type="hidden" name="target_path" value="<?= h($rel) ?>">
                                    <input type="hidden" name="current_path" value="<?= h($fileCurrentPath) ?>">
                                    <button type="submit" class="rounded-lg border border-rose-200 bg-rose-50 px-3 py-1.5 text-xs font-semibold text-rose-700 transition hover:bg-rose-100">Excluir</button>
                                  </form>
                                </div>
                              </td>
                            </tr>
                          <?php endforeach; ?>
                        </tbody>
                      </table>
                    </div>
                  <?php endif; ?>
                </div>

                <?php if ($fileEdit !== ''): ?>
                  <form method="post" class="mt-5 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
                    <div class="flex flex-col gap-3 border-b border-slate-200 pb-4 lg:flex-row lg:items-center lg:justify-between">
                      <div>
                        <p class="text-xs font-semibold uppercase tracking-[0.14em] text-indigo-600">Editor</p>
                        <h4 class="mt-1 font-display text-lg font-semibold text-slate-900"><?= h(basename($fileEdit)) ?></h4>
                        <p class="mt-1 break-all text-sm text-slate-500"><?= h($fileEdit) ?></p>
                      </div>
                      <div class="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                        <?php if (is_array($fileEditingItem)): ?>
                          <p><span class="font-semibold text-slate-900"><?= h(fileTypeLabel((string) ($fileEditingItem['type'] ?? 'file'))) ?></span> | <?= h(formatBytesUi((int) ($fileEditingItem['size'] ?? 0))) ?></p>
                          <p class="mt-1">Modificado em <?= h(formatUnixTimeUi((int) ($fileEditingItem['mtime'] ?? 0))) ?></p>
                        <?php else: ?>
                          <p>Arquivo carregado para edicao.</p>
                        <?php endif; ?>
                      </div>
                    </div>

                    <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                    <input type="hidden" name="action" value="file_save">
                    <input type="hidden" name="site_user" value="<?= h($fileSite) ?>">
                    <input type="hidden" name="file_path" value="<?= h($fileEdit) ?>">
                    <textarea name="file_content" spellcheck="false" class="mt-4 min-h-[420px] w-full rounded-2xl border border-slate-300 bg-slate-950 px-4 py-4 font-mono text-sm text-slate-100 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"><?= h($fileContent) ?></textarea>
                    <div class="mt-4 flex flex-wrap items-center justify-between gap-3">
                      <a href="<?= h(baseUrl(['tab' => 'files', 'site' => $fileSite, 'path' => $fileCurrentPath])) ?>" class="rounded-xl border border-slate-300 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 transition hover:bg-slate-100">Fechar editor</a>
                      <button type="submit" class="rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700">Salvar arquivo</button>
                    </div>
                  </form>
                <?php endif; ?>
              </div>

              <aside class="space-y-5">
                <div class="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                  <h4 class="font-display text-lg font-semibold text-slate-900">Acoes rapidas</h4>
                  <p class="mt-1 text-sm text-slate-500">Trabalhe na pasta atual sem perder o contexto da navegacao.</p>

                  <form method="post" class="mt-4 rounded-xl border border-slate-200 bg-white p-4">
                    <h5 class="font-semibold text-slate-900">Novo diretorio</h5>
                    <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                    <input type="hidden" name="action" value="file_mkdir">
                    <input type="hidden" name="site_user" value="<?= h($fileSite) ?>">
                    <input type="hidden" name="current_path" value="<?= h($fileCurrentPath) ?>">
                    <input name="new_dir" placeholder="ex: assets, backups, private" required class="mt-3 w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                    <button type="submit" class="mt-3 w-full rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700">Criar pasta</button>
                  </form>

                  <form method="post" enctype="multipart/form-data" class="mt-4 rounded-xl border border-slate-200 bg-white p-4">
                    <h5 class="font-semibold text-slate-900">Upload de arquivo</h5>
                    <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                    <input type="hidden" name="action" value="file_upload">
                    <input type="hidden" name="site_user" value="<?= h($fileSite) ?>">
                    <input type="hidden" name="current_path" value="<?= h($fileCurrentPath) ?>">
                    <input type="file" name="upload_file" required class="mt-3 block w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700 file:mr-3 file:rounded-lg file:border-0 file:bg-blue-50 file:px-3 file:py-1.5 file:text-xs file:font-semibold file:text-blue-700 hover:file:bg-blue-100">
                    <button type="submit" class="mt-3 w-full rounded-xl bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-emerald-700">Enviar arquivo</button>
                  </form>
                </div>

                <div class="rounded-2xl border border-slate-200 bg-white p-4">
                  <div class="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div>
                      <h4 class="font-display text-lg font-semibold text-slate-900">GitHub do site</h4>
                      <p class="mt-1 text-sm text-slate-500">Clone privado, sincronize alteracoes e envie commits sem SSH no usuario do site.</p>
                    </div>
                    <div class="flex flex-wrap gap-2">
                      <span class="rounded-full px-2.5 py-1 text-xs font-semibold <?= !empty($githubConfigStatus['configured']) ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-200 text-slate-700' ?>">
                        <?= !empty($githubConfigStatus['configured']) ? 'Acesso pronto' : 'Configurar no sistema' ?>
                      </span>
                      <?php if (!empty($githubSiteStatus['repo_exists'])): ?>
                        <span class="rounded-full px-2.5 py-1 text-xs font-semibold <?= !empty($githubSiteStatus['dirty']) ? 'bg-amber-100 text-amber-700' : 'bg-blue-100 text-blue-700' ?>">
                          <?= !empty($githubSiteStatus['dirty']) ? 'Com alteracoes locais' : 'Repositorio limpo' ?>
                        </span>
                      <?php endif; ?>
                    </div>
                  </div>

                  <?php if (($githubSiteStatus['error'] ?? '') !== ''): ?>
                    <div class="mt-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"><?= h((string) $githubSiteStatus['error']) ?></div>
                  <?php endif; ?>

                  <?php if (($githubCloneStatus['error'] ?? '') !== ''): ?>
                    <div class="mt-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"><?= h((string) $githubCloneStatus['error']) ?></div>
                  <?php endif; ?>

                  <?php if (!empty($githubCloneStatus['status_exists'])): ?>
                    <div class="mt-4 rounded-xl border <?= $githubCloneRunning ? 'border-blue-200 bg-blue-50/70' : (!empty($githubCloneStatus['finished']) && ($githubCloneStatus['state'] ?? '') === 'completed' ? 'border-emerald-200 bg-emerald-50/70' : 'border-amber-200 bg-amber-50/70') ?> p-4" data-github-clone-card="<?= $githubCloneRunning ? 'running' : 'idle' ?>">
                      <div class="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                        <div>
                          <p class="text-xs font-semibold uppercase tracking-[0.14em] <?= $githubCloneRunning ? 'text-blue-700' : 'text-slate-500' ?>">Progresso do clone</p>
                          <h5 class="mt-1 font-semibold text-slate-900"><?= h((string) (($githubCloneStatus['repo'] ?? '') !== '' ? $githubCloneStatus['repo'] : 'Repositorio em processamento')) ?></h5>
                          <p class="mt-1 text-sm text-slate-600"><?= h((string) ($githubCloneStatus['detail'] ?? ($githubCloneStatus['message'] ?? 'Aguardando informacoes do clone.'))) ?></p>
                        </div>
                        <div class="flex flex-wrap gap-2">
                          <span class="rounded-full px-2.5 py-1 text-xs font-semibold <?= $githubCloneRunning ? 'bg-blue-100 text-blue-700' : (($githubCloneStatus['state'] ?? '') === 'completed' ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700') ?>">
                            <?= $githubCloneRunning ? 'Em andamento' : (($githubCloneStatus['state'] ?? '') === 'completed' ? 'Concluido' : 'Interrompido') ?>
                          </span>
                          <span class="rounded-full bg-white px-2.5 py-1 text-xs font-semibold text-slate-700"><?= h((string) $githubClonePercent) ?>%</span>
                        </div>
                      </div>

                      <div class="mt-4 h-2.5 overflow-hidden rounded-full bg-white/90 ring-1 ring-slate-200">
                        <div class="h-full rounded-full <?= $githubCloneRunning ? 'bg-blue-600' : (($githubCloneStatus['state'] ?? '') === 'completed' ? 'bg-emerald-600' : 'bg-amber-500') ?>" style="width: <?= h((string) $githubClonePercent) ?>%"></div>
                      </div>

                      <div class="mt-4 grid gap-3 sm:grid-cols-3 text-sm">
                        <div class="rounded-xl bg-white/80 px-3 py-2.5">
                          <p class="text-slate-500">Etapa</p>
                          <p class="mt-1 font-semibold text-slate-900"><?= h((string) ($githubCloneStatus['phase'] ?? '-')) ?></p>
                        </div>
                        <div class="rounded-xl bg-white/80 px-3 py-2.5">
                          <p class="text-slate-500">Branch</p>
                          <p class="mt-1 font-semibold text-slate-900"><?= h((string) (($githubCloneStatus['branch'] ?? '') !== '' ? $githubCloneStatus['branch'] : '-')) ?></p>
                        </div>
                        <div class="rounded-xl bg-white/80 px-3 py-2.5">
                          <p class="text-slate-500">Atualizado</p>
                          <p class="mt-1 font-semibold text-slate-900"><?= h(formatUnixTimeUi((int) ($githubCloneStatus['updated_at'] ?? 0))) ?></p>
                        </div>
                      </div>

                      <?php if (($githubCloneStatus['log_tail'] ?? '') !== ''): ?>
                        <pre class="mt-4 max-h-56 overflow-auto rounded-xl bg-slate-950 p-3 font-mono text-xs text-slate-100"><?= h((string) $githubCloneStatus['log_tail']) ?></pre>
                      <?php endif; ?>

                      <?php if ($githubCloneRunning): ?>
                        <p class="mt-3 text-xs text-blue-700">Atualizando automaticamente esta aba a cada 4 segundos enquanto o clone estiver em andamento.</p>
                      <?php endif; ?>
                    </div>
                  <?php endif; ?>

                  <?php if (!empty($githubSiteStatus['repo_exists'])): ?>
                    <div class="mt-4 space-y-3 text-sm">
                      <div class="rounded-xl bg-slate-50 px-3 py-2.5">
                        <p class="text-slate-500">Remote</p>
                        <p class="mt-1 break-all font-semibold text-slate-900"><?= h((string) ($githubSiteStatus['remote'] ?? '-')) ?></p>
                      </div>
                      <div class="grid gap-3 sm:grid-cols-3">
                        <div class="rounded-xl bg-slate-50 px-3 py-2.5">
                          <p class="text-slate-500">Branch</p>
                          <p class="mt-1 font-semibold text-slate-900"><?= h((string) ($githubSiteStatus['branch'] ?? '-')) ?></p>
                        </div>
                        <div class="rounded-xl bg-slate-50 px-3 py-2.5">
                          <p class="text-slate-500">Ahead</p>
                          <p class="mt-1 font-semibold text-slate-900"><?= h((string) ($githubSiteStatus['ahead'] ?? '0')) ?></p>
                        </div>
                        <div class="rounded-xl bg-slate-50 px-3 py-2.5">
                          <p class="text-slate-500">Behind</p>
                          <p class="mt-1 font-semibold text-slate-900"><?= h((string) ($githubSiteStatus['behind'] ?? '0')) ?></p>
                        </div>
                      </div>
                      <div class="rounded-xl bg-slate-50 px-3 py-2.5">
                        <p class="text-slate-500">Ultimo commit</p>
                        <p class="mt-1 break-all font-semibold text-slate-900"><?= h((string) (($githubSiteStatus['last_commit'] ?? '') !== '' ? $githubSiteStatus['last_commit'] : '-')) ?></p>
                      </div>
                    </div>

                    <form method="post" class="mt-4">
                      <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                      <input type="hidden" name="action" value="github_site_pull">
                      <input type="hidden" name="return_tab" value="files">
                      <input type="hidden" name="site_user" value="<?= h($fileSite) ?>">
                      <button type="submit" class="w-full rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700">Atualizar com pull</button>
                    </form>

                    <form method="post" class="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-4">
                      <h5 class="font-semibold text-slate-900">Commit e push</h5>
                      <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                      <input type="hidden" name="action" value="github_site_commit_push">
                      <input type="hidden" name="return_tab" value="files">
                      <input type="hidden" name="site_user" value="<?= h($fileSite) ?>">
                      <label class="mb-1 mt-3 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Mensagem de commit</label>
                      <input type="text" name="github_commit_message" placeholder="ex: Atualiza layout da home" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                      <button type="submit" class="mt-3 w-full rounded-xl bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-700">Commitar e enviar</button>
                    </form>
                  <?php else: ?>
                    <div class="mt-4 rounded-xl border border-dashed border-slate-300 bg-slate-50 px-4 py-4 text-sm text-slate-600">
                      Esse site ainda nao tem um repositorio Git em `public_html`. Conecte sua conta na aba Sistema, escolha um repositorio da sua conta e acompanhe o clone aqui mesmo.
                    </div>

                    <form method="post" class="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-4">
                      <h5 class="font-semibold text-slate-900">Clonar repositorio privado</h5>
                      <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                      <input type="hidden" name="action" value="github_site_clone_start">
                      <input type="hidden" name="return_tab" value="files">
                      <input type="hidden" name="site_user" value="<?= h($fileSite) ?>">

                      <?php if (($githubRepoList['error'] ?? '') !== ''): ?>
                        <div class="mt-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-700"><?= h((string) $githubRepoList['error']) ?></div>
                      <?php endif; ?>

                      <?php if ($githubRepos !== []): ?>
                        <div class="mt-3">
                          <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Buscar repositorio</label>
                          <input type="text" placeholder="Filtrar por nome, owner ou branch" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20" data-github-repo-filter>
                          <p class="mt-2 text-xs text-slate-500">Repositorios carregados da conta conectada: <?= h((string) count($githubRepos)) ?></p>
                        </div>
                        <div class="mt-3">
                          <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Escolher repositorio</label>
                          <select name="github_repo_slug" size="8" required class="w-full rounded-2xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20" data-github-repo-select data-github-branch-target="github-branch-input" <?= $githubCloneRunning ? 'disabled' : '' ?>>
                            <?php foreach ($githubRepos as $repo): ?>
                              <?php
                              $repoSlug = (string) ($repo['slug'] ?? '');
                              $repoPrivate = !empty($repo['private']);
                              $repoArchived = !empty($repo['archived']);
                              $repoDefaultBranch = (string) ($repo['default_branch'] ?? '');
                              $repoUpdatedAt = formatIsoTimeUi((string) ($repo['updated_at'] ?? ''));
                              $repoLabel = $repoSlug;
                              $repoLabel .= $repoPrivate ? ' | privado' : ' | publico';
                              if ($repoArchived) {
                                  $repoLabel .= ' | arquivado';
                              }
                              if ($repoDefaultBranch !== '') {
                                  $repoLabel .= ' | branch: ' . $repoDefaultBranch;
                              }
                              if ($repoUpdatedAt !== '-') {
                                  $repoLabel .= ' | atualizado: ' . $repoUpdatedAt;
                              }
                              ?>
                              <option value="<?= h($repoSlug) ?>" data-default-branch="<?= h($repoDefaultBranch) ?>"><?= h($repoLabel) ?></option>
                            <?php endforeach; ?>
                          </select>
                        </div>
                      <?php else: ?>
                        <div class="mt-3">
                          <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Repositorio</label>
                          <input type="text" name="github_repo_slug" placeholder="owner/repositorio" required class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20" <?= $githubCloneRunning ? 'disabled' : '' ?>>
                        </div>
                      <?php endif; ?>

                      <div class="mt-3">
                        <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Branch inicial</label>
                        <input type="text" id="github-branch-input" name="github_branch" placeholder="main" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20" <?= $githubCloneRunning ? 'disabled' : '' ?>>
                      </div>
                      <label class="mt-3 flex items-center gap-2 text-sm text-slate-700">
                        <input type="checkbox" name="github_clean_target" value="1" class="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500" <?= $githubCloneRunning ? 'disabled' : '' ?>>
                        Limpar `public_html` antes do clone
                      </label>
                      <button type="submit" class="mt-4 w-full rounded-xl bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-700 <?= $githubCloneRunning ? 'opacity-60 cursor-not-allowed' : '' ?>" <?= $githubCloneRunning ? 'disabled' : '' ?>><?= $githubCloneRunning ? 'Clone em andamento' : 'Clonar no site' ?></button>
                    </form>
                  <?php endif; ?>
                </div>

                <div class="rounded-2xl border border-slate-200 bg-white p-4">
                  <h4 class="font-display text-lg font-semibold text-slate-900">Resumo da pasta</h4>
                  <div class="mt-4 space-y-3 text-sm">
                    <div class="flex items-center justify-between gap-3 rounded-xl bg-slate-50 px-3 py-2.5">
                      <span class="text-slate-500">Site selecionado</span>
                      <span class="font-semibold text-slate-900"><?= h($fileSite) ?></span>
                    </div>
                    <div class="flex items-center justify-between gap-3 rounded-xl bg-slate-50 px-3 py-2.5">
                      <span class="text-slate-500">Pasta atual</span>
                      <span class="max-w-[55%] truncate font-semibold text-slate-900"><?= h($fileCurrentPath !== '' ? $fileCurrentPath : 'public_html') ?></span>
                    </div>
                    <div class="flex items-center justify-between gap-3 rounded-xl bg-slate-50 px-3 py-2.5">
                      <span class="text-slate-500">Pastas</span>
                      <span class="font-semibold text-slate-900"><?= h((string) $fileDirectoryCount) ?></span>
                    </div>
                    <div class="flex items-center justify-between gap-3 rounded-xl bg-slate-50 px-3 py-2.5">
                      <span class="text-slate-500">Arquivos listados</span>
                      <span class="font-semibold text-slate-900"><?= h((string) ($fileEntryCount - $fileDirectoryCount)) ?></span>
                    </div>
                    <div class="flex items-center justify-between gap-3 rounded-xl bg-slate-50 px-3 py-2.5">
                      <span class="text-slate-500">Tamanho total</span>
                      <span class="font-semibold text-slate-900"><?= h(formatBytesUi($fileTotalSize)) ?></span>
                    </div>
                  </div>
                </div>

                <div class="rounded-2xl border border-slate-200 bg-white p-4">
                  <h4 class="font-display text-lg font-semibold text-slate-900">Boas praticas</h4>
                  <ul class="mt-3 space-y-3 text-sm text-slate-600">
                    <li class="rounded-xl bg-slate-50 px-3 py-2.5">Edite arquivos pequenos direto no painel e prefira versionar alteracoes maiores no Git.</li>
                    <li class="rounded-xl bg-slate-50 px-3 py-2.5">Antes de apagar uma pasta, confirme se ela nao guarda uploads ou backups do site.</li>
                    <li class="rounded-xl bg-slate-50 px-3 py-2.5">Use a navegacao por breadcrumbs para voltar rapidamente sem editar o caminho manualmente.</li>
                  </ul>
                </div>
              </aside>
            </div>
          <?php endif; ?>
        </section>
      <?php endif; ?>

      <?php if ($tab === 'database'): ?>
        <section class="rounded-2xl border border-slate-200 bg-white p-5 shadow-panel">
          <h3 class="font-display text-xl font-semibold text-slate-900">Acesso ao banco de dados</h3>
          <p class="mt-2 text-sm text-slate-600">Abra o phpMyAdmin, publique o dominio dele e gerencie credenciais dos bancos principais e adicionais.</p>

          <div class="mt-4 grid gap-4 xl:grid-cols-3">
            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <h4 class="font-display text-lg font-semibold text-slate-900">phpMyAdmin</h4>
              <p class="mt-1 text-sm text-slate-600">Acesso visual aos bancos do servidor.</p>
              <?php if ($phpmyadminDomain !== ''): ?>
                <a href="<?= h('https://' . $phpmyadminDomain) ?>" target="_blank" rel="noopener" class="mt-3 inline-flex items-center rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700">Abrir phpMyAdmin (<?= h($phpmyadminDomain) ?>)</a>
              <?php else: ?>
                <div class="mt-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">Dominio do phpMyAdmin nao encontrado.</div>
              <?php endif; ?>

              <form method="post" class="mt-4 rounded-xl border border-slate-200 bg-white p-4">
                <h5 class="font-semibold text-slate-900">Publicar dominio do phpMyAdmin</h5>
                <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                <input type="hidden" name="action" value="phpmyadmin_configure_domain">
                <input type="hidden" name="return_tab" value="database">

                <div class="mt-3">
                  <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Dominio</label>
                  <input name="phpmyadmin_domain" value="<?= h($phpmyadminDomain !== '' ? $phpmyadminDomain : 'db.i3lab.site') ?>" required class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                </div>

                <div class="mt-3 space-y-2 text-sm text-slate-700">
                  <label class="inline-flex items-center gap-2">
                    <input type="checkbox" name="phpmyadmin_remove_others" value="1" checked class="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500">
                    Remover /phpmyadmin dos demais sites
                  </label>
                  <label class="inline-flex items-center gap-2">
                    <input type="checkbox" name="phpmyadmin_create_tunnel" value="1" class="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500">
                    Criar tunnel Cloudflare
                  </label>
                </div>

                <button type="submit" class="mt-4 w-full rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700">Configurar phpMyAdmin</button>
              </form>
            </div>

            <form method="post" class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <h4 class="font-display text-lg font-semibold text-slate-900">Criar banco adicional</h4>
              <p class="mt-1 text-sm text-slate-600">Cria banco + usuario para um site existente.</p>
              <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
              <input type="hidden" name="action" value="db_create_additional">

              <div class="mt-3">
                <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Site</label>
                <select name="site_user" required class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                  <?php foreach ($fileSites as $site): ?>
                    <?php $user = (string) ($site['user'] ?? ''); ?>
                    <option value="<?= h($user) ?>"><?= h($user . ' (' . ((string) ($site['domain'] ?? '-')) . ')') ?></option>
                  <?php endforeach; ?>
                </select>
              </div>

              <div class="mt-3">
                <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Sufixo (opcional)</label>
                <input name="db_suffix" placeholder="ex: extra1" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
              </div>

              <button type="submit" class="mt-3 w-full rounded-xl bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-emerald-700">Criar banco adicional</button>
            </form>

            <form method="post" class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <h4 class="font-display text-lg font-semibold text-slate-900">Trocar senha do banco principal</h4>
              <p class="mt-1 text-sm text-slate-600">Gera uma nova senha para o banco principal do site e tenta atualizar o .env automaticamente.</p>
              <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
              <input type="hidden" name="action" value="db_rotate_password">
              <input type="hidden" name="return_tab" value="database">

              <div class="mt-3">
                <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Site</label>
                <select name="site_user" required class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                  <?php foreach ($fileSites as $site): ?>
                    <?php $user = (string) ($site['user'] ?? ''); ?>
                    <option value="<?= h($user) ?>"><?= h($user . ' (' . ((string) ($site['domain'] ?? '-')) . ')') ?></option>
                  <?php endforeach; ?>
                </select>
              </div>

              <button type="submit" class="mt-3 w-full rounded-xl bg-amber-500 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-amber-600">Gerar nova senha</button>
            </form>
          </div>
        </section>
      <?php endif; ?>

      <?php if ($tab === 'system'): ?>
        <section class="rounded-2xl border border-slate-200 bg-white p-5 shadow-panel">
          <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <h3 class="font-display text-xl font-semibold text-slate-900">Sistema</h3>
            <form method="post">
              <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
              <input type="hidden" name="action" value="restart_services">
              <button type="submit" class="rounded-xl bg-amber-500 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-amber-600">Reiniciar servicos principais</button>
            </form>
          </div>

          <div class="mt-4 overflow-x-auto rounded-xl border border-slate-200">
            <table class="min-w-full divide-y divide-slate-200 text-sm">
              <thead class="bg-slate-50 text-left text-xs uppercase tracking-[0.14em] text-slate-500">
                <tr>
                  <th class="px-4 py-3">Servico</th>
                  <th class="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-200 bg-white">
                <?php foreach ($serviceStatus as $svc): ?>
                  <?php
                  $svcName = (string) ($svc['service'] ?? '-');
                  $svcState = (string) ($svc['status'] ?? 'missing');
                  ?>
                  <tr class="hover:bg-slate-50">
                    <td class="px-4 py-3 font-semibold text-slate-900"><?= h($svcName) ?></td>
                    <td class="px-4 py-3">
                      <span class="rounded-full px-2.5 py-1 text-xs font-semibold <?= h(serviceStatusUiClass($svcState)) ?>"><?= h($svcState) ?></span>
                    </td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>

          <?php if (($serverMetrics['error'] ?? '') !== ''): ?>
            <div class="mt-5 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">Falha ao carregar metricas do servidor: <?= h((string) $serverMetrics['error']) ?></div>
          <?php endif; ?>

          <div class="mt-5 grid gap-4 xl:grid-cols-4">
            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <p class="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">CPU atual</p>
              <p class="mt-2 font-display text-3xl font-semibold text-slate-900"><?= h(formatPercentUi($cpuPercent)) ?></p>
              <div class="mt-3 h-2 rounded-full bg-white">
                <div class="h-2 rounded-full <?= h(metricBarClass($cpuPercent)) ?>" style="width: <?= h((string) max(2, min(100, $cpuPercent))) ?>%"></div>
              </div>
              <p class="mt-3 text-xs text-slate-500">Load: <?= h((string) (($serverMetrics['cpu']['load']['one'] ?? '0') . ' / ' . ($serverMetrics['cpu']['load']['five'] ?? '0') . ' / ' . ($serverMetrics['cpu']['load']['fifteen'] ?? '0'))) ?></p>
            </div>

            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <p class="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Memoria RAM</p>
              <p class="mt-2 font-display text-3xl font-semibold text-slate-900"><?= h(formatPercentUi($memoryPercent)) ?></p>
              <div class="mt-3 h-2 rounded-full bg-white">
                <div class="h-2 rounded-full <?= h(metricBarClass($memoryPercent)) ?>" style="width: <?= h((string) max(2, min(100, $memoryPercent))) ?>%"></div>
              </div>
              <p class="mt-3 text-xs text-slate-500"><?= h(formatBytesUi((int) ($serverMetrics['memory']['used'] ?? 0))) ?> / <?= h(formatBytesUi((int) ($serverMetrics['memory']['total'] ?? 0))) ?></p>
            </div>

            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <p class="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Disco raiz</p>
              <p class="mt-2 font-display text-3xl font-semibold text-slate-900"><?= h(formatPercentUi($diskRootPercent)) ?></p>
              <div class="mt-3 h-2 rounded-full bg-white">
                <div class="h-2 rounded-full <?= h(metricBarClass($diskRootPercent)) ?>" style="width: <?= h((string) max(2, min(100, $diskRootPercent))) ?>%"></div>
              </div>
              <p class="mt-3 text-xs text-slate-500"><?= h(formatBytesUi((int) ($serverMetrics['disk']['root']['available'] ?? 0))) ?> livres</p>
            </div>

            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <p class="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Uptime</p>
              <p class="mt-2 font-display text-3xl font-semibold text-slate-900"><?= h(formatUptimeUi($uptimeSeconds)) ?></p>
              <p class="mt-3 text-xs text-slate-500"><?= h((string) ($serverMetrics['cpu']['cores'] ?? '-')) ?> core(s) detectados</p>
            </div>
          </div>

          <div class="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,0.9fr)]">
            <div class="rounded-xl border border-slate-200 bg-white p-4">
              <h4 class="font-display text-lg font-semibold text-slate-900">Particoes monitoradas</h4>
              <div class="mt-4 overflow-x-auto rounded-xl border border-slate-200">
                <table class="min-w-full divide-y divide-slate-200 text-sm">
                  <thead class="bg-slate-50 text-left text-xs uppercase tracking-[0.14em] text-slate-500">
                    <tr>
                      <th class="px-4 py-3">Mount</th>
                      <th class="px-4 py-3">Uso</th>
                      <th class="px-4 py-3">Livre</th>
                      <th class="px-4 py-3">Percentual</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-slate-200 bg-white">
                    <?php foreach (($serverMetrics['disk']['mounts'] ?? []) as $mount): ?>
                      <?php $mountPercent = (float) ($mount['percent'] ?? 0); ?>
                      <tr class="hover:bg-slate-50">
                        <td class="px-4 py-3 font-semibold text-slate-900"><?= h((string) ($mount['mount'] ?? '-')) ?></td>
                        <td class="px-4 py-3 text-slate-600"><?= h(formatBytesUi((int) ($mount['used'] ?? 0))) ?></td>
                        <td class="px-4 py-3 text-slate-600"><?= h(formatBytesUi((int) ($mount['available'] ?? 0))) ?></td>
                        <td class="px-4 py-3">
                          <div class="flex min-w-[180px] items-center gap-3">
                            <div class="h-2 flex-1 rounded-full bg-slate-100">
                              <div class="h-2 rounded-full <?= h(metricBarClass($mountPercent)) ?>" style="width: <?= h((string) max(2, min(100, $mountPercent))) ?>%"></div>
                            </div>
                            <span class="w-14 text-right text-xs font-semibold text-slate-700"><?= h(formatPercentUi($mountPercent)) ?></span>
                          </div>
                        </td>
                      </tr>
                    <?php endforeach; ?>
                  </tbody>
                </table>
              </div>
            </div>

            <div class="rounded-xl border border-slate-200 bg-white p-4">
              <h4 class="font-display text-lg font-semibold text-slate-900">Processos mais ativos</h4>
              <div class="mt-4 space-y-3">
                <?php foreach (($serverMetrics['top_processes'] ?? []) as $process): ?>
                  <div class="rounded-xl border border-slate-200 bg-slate-50 px-3 py-3">
                    <div class="flex items-center justify-between gap-3">
                      <p class="font-semibold text-slate-900"><?= h((string) ($process['command'] ?? '-')) ?></p>
                      <span class="text-xs font-semibold text-slate-500">PID <?= h((string) ($process['pid'] ?? '-')) ?></span>
                    </div>
                    <div class="mt-2 flex items-center justify-between text-xs text-slate-600">
                      <span>CPU <?= h((string) ($process['cpu'] ?? '0')) ?>%</span>
                      <span>RAM <?= h((string) ($process['mem'] ?? '0')) ?>%</span>
                    </div>
                  </div>
                <?php endforeach; ?>
              </div>
            </div>
          </div>

          <div class="mt-5 grid gap-5 xl:grid-cols-2">
            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <h4 class="font-display text-lg font-semibold text-slate-900">Instalacao base</h4>
              <p class="mt-1 text-sm text-slate-600">Executa a rotina inicial para preparar os componentes principais do servidor.</p>
              <form method="post" class="mt-4">
                <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                <input type="hidden" name="action" value="stack_install_base">
                <input type="hidden" name="return_tab" value="system">
                <button type="submit" class="rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700">Instalar stack base</button>
              </form>
            </div>

            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <div class="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <h4 class="font-display text-lg font-semibold text-slate-900">Cloudflare Tunnel</h4>
                  <p class="mt-1 text-sm text-slate-600">Autentique a conta e acompanhe o status antes de publicar sites com tunnel.</p>
                </div>
                <div class="flex flex-wrap gap-2">
                  <span class="rounded-full px-2.5 py-1 text-xs font-semibold <?= !empty($cloudflareStatus['authenticated']) ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-200 text-slate-700' ?>">
                    <?= !empty($cloudflareStatus['authenticated']) ? 'Autenticado' : 'Nao autenticado' ?>
                  </span>
                  <?php if (!empty($cloudflareStatus['login_running'])): ?>
                    <span class="rounded-full bg-blue-100 px-2.5 py-1 text-xs font-semibold text-blue-700">Login em andamento</span>
                  <?php endif; ?>
                </div>
              </div>

              <?php if (($cloudflareStatus['error'] ?? '') !== ''): ?>
                <div class="mt-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"><?= h((string) $cloudflareStatus['error']) ?></div>
              <?php endif; ?>

              <div class="mt-4 flex flex-wrap gap-3">
                <form method="post">
                  <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                  <input type="hidden" name="action" value="cloudflare_login_start">
                  <input type="hidden" name="return_tab" value="system">
                  <button type="submit" class="rounded-xl bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-700">Iniciar login</button>
                </form>
                <?php if (($cloudflareStatus['login_url'] ?? '') !== ''): ?>
                  <a href="<?= h((string) $cloudflareStatus['login_url']) ?>" target="_blank" rel="noreferrer" class="rounded-xl border border-blue-200 bg-blue-50 px-4 py-2.5 text-sm font-semibold text-blue-700 transition hover:bg-blue-100">Abrir URL de autorizacao</a>
                <?php endif; ?>
              </div>

              <?php if (($cloudflareStatus['log_file'] ?? '') !== ''): ?>
                <p class="mt-3 text-xs text-slate-500">Log: <?= h((string) $cloudflareStatus['log_file']) ?></p>
              <?php endif; ?>

              <?php if (($cloudflareStatus['log_excerpt'] ?? '') !== ''): ?>
                <pre class="mt-3 overflow-x-auto rounded-xl border border-slate-200 bg-white p-3 font-mono text-xs text-slate-800"><?= h((string) $cloudflareStatus['log_excerpt']) ?></pre>
              <?php endif; ?>
            </div>

            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <h4 class="font-display text-lg font-semibold text-slate-900">Dominio do painel</h4>
              <p class="mt-1 text-sm text-slate-600">Publica o webpanel com dominio proprio e opcionalmente cria o tunnel.</p>
              <form method="post" class="mt-4 space-y-3">
                <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                <input type="hidden" name="action" value="panel_configure_domain">
                <input type="hidden" name="return_tab" value="system">
                <div>
                  <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Dominio</label>
                  <input type="text" name="panel_domain" value="<?= h($panelDomain !== '' ? $panelDomain : 'panel.i3lab.site') ?>" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20" placeholder="panel.seudominio.com">
                </div>
                <label class="flex items-center gap-2 text-sm text-slate-700">
                  <input type="checkbox" name="panel_create_tunnel" value="1" class="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500">
                  Criar tunnel Cloudflare para o painel
                </label>
                <button type="submit" class="rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700">Configurar painel</button>
              </form>
            </div>

            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <h4 class="font-display text-lg font-semibold text-slate-900">OpenLiteSpeed Admin</h4>
              <p class="mt-1 text-sm text-slate-600">Atualize o usuario e a senha do painel administrativo do OpenLiteSpeed.</p>
              <form method="post" class="mt-4 grid gap-3">
                <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                <input type="hidden" name="action" value="ols_set_admin_password">
                <input type="hidden" name="return_tab" value="system">
                <div>
                  <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Usuario</label>
                  <input type="text" name="ols_admin_user" value="admin" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                </div>
                <div>
                  <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Nova senha</label>
                  <input type="password" name="ols_admin_password" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                </div>
                <div>
                  <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Confirmar senha</label>
                  <input type="password" name="ols_admin_password_confirm" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                </div>
                <button type="submit" class="rounded-xl bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-700">Salvar credenciais</button>
              </form>
            </div>

            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4 xl:col-span-2">
              <div class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <h4 class="font-display text-lg font-semibold text-slate-900">GitHub privado</h4>
                  <p class="mt-1 text-sm text-slate-600">Conecte sua conta com autorizacao oficial do GitHub e mantenha uma credencial central no painel, sem chave SSH por site.</p>
                </div>
                <div class="flex flex-wrap gap-2">
                  <span class="rounded-full px-2.5 py-1 text-xs font-semibold <?= !empty($githubConfigStatus['oauth_app_configured']) ? 'bg-blue-100 text-blue-700' : 'bg-slate-200 text-slate-700' ?>">
                    <?= !empty($githubConfigStatus['oauth_app_configured']) ? 'OAuth pronto' : 'OAuth pendente' ?>
                  </span>
                  <span class="rounded-full px-2.5 py-1 text-xs font-semibold <?= !empty($githubConfigStatus['configured']) ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-200 text-slate-700' ?>">
                    <?= !empty($githubConfigStatus['configured']) ? 'Conta conectada' : 'Nao conectado' ?>
                  </span>
                  <?php if (!empty($githubConfigStatus['device_flow']['pending'])): ?>
                    <span class="rounded-full bg-amber-100 px-2.5 py-1 text-xs font-semibold text-amber-700">Autorizacao pendente</span>
                  <?php endif; ?>
                  <?php if (($githubConfigStatus['token_masked'] ?? '') !== ''): ?>
                    <span class="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-700"><?= h((string) $githubConfigStatus['token_masked']) ?></span>
                  <?php endif; ?>
                </div>
              </div>

              <?php if (($githubConfigStatus['error'] ?? '') !== ''): ?>
                <div class="mt-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"><?= h((string) $githubConfigStatus['error']) ?></div>
              <?php endif; ?>

              <div class="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1.3fr)_minmax(260px,0.7fr)]">
                <div class="space-y-4">
                  <form method="post" class="rounded-xl border border-slate-200 bg-white p-4">
                    <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                    <input type="hidden" name="action" value="github_oauth_app_save">
                    <input type="hidden" name="return_tab" value="system">

                    <div class="flex items-start justify-between gap-3">
                      <div>
                        <h5 class="font-semibold text-slate-900">App OAuth do painel</h5>
                        <p class="mt-1 text-sm text-slate-600">Cadastre o Client ID do seu GitHub OAuth App para liberar o botao de conexao oficial.</p>
                      </div>
                      <span class="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-600">Passo 1</span>
                    </div>

                    <div class="mt-4 grid gap-3 md:grid-cols-2">
                      <div>
                        <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Client ID</label>
                        <input type="text" name="github_client_id" value="<?= h((string) ($githubConfigStatus['oauth_client_id'] ?? '')) ?>" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20" placeholder="Iv1.0123456789abcdef">
                      </div>
                      <div>
                        <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Escopos</label>
                        <input type="text" name="github_scopes" value="<?= h((string) (($githubConfigStatus['oauth_scopes'] ?? '') !== '' ? $githubConfigStatus['oauth_scopes'] : 'repo read:user user:email')) ?>" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20" placeholder="repo read:user user:email">
                      </div>
                    </div>

                    <div class="mt-4 flex flex-wrap gap-3">
                      <button type="submit" class="rounded-xl bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-700">Salvar App OAuth</button>
                      <p class="self-center text-xs text-slate-500">Use o Client ID oficial do app que voce criou no GitHub para este painel.</p>
                    </div>
                  </form>

                  <div class="rounded-xl border border-slate-200 bg-white p-4">
                    <div class="flex items-start justify-between gap-3">
                      <div>
                        <h5 class="font-semibold text-slate-900">Conectar com GitHub</h5>
                        <p class="mt-1 text-sm text-slate-600">Depois de salvar o app, gere um codigo de autorizacao e aprove a conexao na sua conta GitHub.</p>
                      </div>
                      <span class="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-600">Passo 2</span>
                    </div>

                    <div class="mt-4 flex flex-wrap gap-3">
                      <form method="post">
                        <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                        <input type="hidden" name="action" value="github_device_start">
                        <input type="hidden" name="return_tab" value="system">
                        <button type="submit" class="rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700" <?= empty($githubConfigStatus['oauth_app_configured']) ? 'disabled' : '' ?>>Conectar com GitHub</button>
                      </form>
                      <?php if (!empty($githubConfigStatus['device_flow']['pending'])): ?>
                        <form method="post">
                          <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                          <input type="hidden" name="action" value="github_device_poll">
                          <input type="hidden" name="return_tab" value="system">
                          <button type="submit" class="rounded-xl border border-slate-300 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 transition hover:bg-slate-50">Verificar conexao</button>
                        </form>
                      <?php endif; ?>
                    </div>

                    <?php if (empty($githubConfigStatus['oauth_app_configured'])): ?>
                      <p class="mt-3 text-xs text-slate-500">Salve o Client ID do app antes de iniciar a conexao.</p>
                    <?php endif; ?>

                    <?php if (!empty($githubConfigStatus['device_flow']['pending'])): ?>
                      <div class="mt-4 grid gap-3 md:grid-cols-3">
                        <div class="rounded-xl bg-slate-50 px-3 py-3">
                          <p class="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Codigo</p>
                          <p class="mt-1 text-lg font-semibold tracking-[0.18em] text-slate-900"><?= h((string) ($githubConfigStatus['device_flow']['user_code'] ?? '-')) ?></p>
                        </div>
                        <div class="rounded-xl bg-slate-50 px-3 py-3 md:col-span-2">
                          <p class="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">URL de autorizacao</p>
                          <p class="mt-1 break-all text-sm font-semibold text-slate-900"><a href="<?= h((string) ($githubConfigStatus['device_flow']['verification_uri'] ?? '#')) ?>" target="_blank" rel="noreferrer" class="text-blue-700 underline decoration-blue-300 underline-offset-2"><?= h((string) ($githubConfigStatus['device_flow']['verification_uri'] ?? '-')) ?></a></p>
                          <p class="mt-2 text-xs text-slate-500">Tempo restante: <?= h((string) max(0, (int) ($githubConfigStatus['device_flow']['seconds_left'] ?? 0))) ?>s</p>
                        </div>
                      </div>
                    <?php endif; ?>
                  </div>

                  <form method="post" class="rounded-xl border border-slate-200 bg-white p-4">
                    <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                    <input type="hidden" name="action" value="github_config_save">
                    <input type="hidden" name="return_tab" value="system">

                    <div class="flex items-start justify-between gap-3">
                      <div>
                        <h5 class="font-semibold text-slate-900">Token manual</h5>
                        <p class="mt-1 text-sm text-slate-600">Fallback para quando voce preferir salvar usuario, token e identidade Git manualmente.</p>
                      </div>
                      <span class="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-600">Opcional</span>
                    </div>

                    <div class="mt-4 grid gap-3 md:grid-cols-2">
                      <div>
                        <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Usuario GitHub</label>
                        <input type="text" name="github_username" value="<?= h((string) ($githubConfigStatus['username'] ?? '')) ?>" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20" placeholder="seu-usuario">
                      </div>
                      <div>
                        <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Token pessoal</label>
                        <input type="password" name="github_token" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20" placeholder="ghp_... ou github_pat_...">
                      </div>
                      <div>
                        <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Nome do autor Git</label>
                        <input type="text" name="github_author_name" value="<?= h((string) ($githubConfigStatus['author_name'] ?? '')) ?>" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20" placeholder="Seu Nome">
                      </div>
                      <div>
                        <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Email do autor Git</label>
                        <input type="email" name="github_author_email" value="<?= h((string) ($githubConfigStatus['author_email'] ?? '')) ?>" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20" placeholder="dev@empresa.com">
                      </div>
                    </div>

                    <div class="mt-4 flex flex-wrap gap-3">
                      <button type="submit" class="rounded-xl border border-slate-300 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 transition hover:bg-slate-50">Salvar token manual</button>
                      <p class="self-center text-xs text-slate-500">O token fica salvo em arquivo root-only e o painel usa autenticacao temporaria por comando.</p>
                    </div>
                  </form>
                </div>

                <div class="rounded-xl border border-slate-200 bg-white p-4">
                  <h5 class="font-semibold text-slate-900">Estado atual</h5>
                  <div class="mt-3 space-y-3 text-sm">
                    <div class="rounded-xl bg-slate-50 px-3 py-2.5">
                      <p class="text-slate-500">Usuario autenticado</p>
                      <p class="mt-1 font-semibold text-slate-900"><?= h((string) (($githubConfigStatus['username'] ?? '') !== '' ? $githubConfigStatus['username'] : '-')) ?></p>
                    </div>
                    <div class="rounded-xl bg-slate-50 px-3 py-2.5">
                      <p class="text-slate-500">Autor Git padrao</p>
                      <p class="mt-1 font-semibold text-slate-900"><?= h(trim((string) (($githubConfigStatus['author_name'] ?? '') . ' <' . ($githubConfigStatus['author_email'] ?? '') . '>'), ' <>')) ?: '-' ?></p>
                    </div>
                    <div class="rounded-xl bg-slate-50 px-3 py-2.5">
                      <p class="text-slate-500">Client ID OAuth</p>
                      <p class="mt-1 break-all font-semibold text-slate-900"><?= h((string) (($githubConfigStatus['oauth_client_id'] ?? '') !== '' ? $githubConfigStatus['oauth_client_id'] : '-')) ?></p>
                    </div>
                    <div class="rounded-xl bg-slate-50 px-3 py-2.5">
                      <p class="text-slate-500">Escopos</p>
                      <p class="mt-1 break-all font-semibold text-slate-900"><?= h((string) (($githubConfigStatus['oauth_scopes'] ?? '') !== '' ? $githubConfigStatus['oauth_scopes'] : '-')) ?></p>
                    </div>
                    <div class="rounded-xl bg-slate-50 px-3 py-2.5">
                      <p class="text-slate-500">Arquivo de configuracao</p>
                      <p class="mt-1 break-all font-semibold text-slate-900"><?= h((string) (($githubConfigStatus['config_file'] ?? '') !== '' ? $githubConfigStatus['config_file'] : '-')) ?></p>
                    </div>
                  </div>

                  <form method="post" class="mt-4" onsubmit="return confirm('Remover a credencial central do GitHub do painel?');">
                    <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                    <input type="hidden" name="action" value="github_config_clear">
                    <input type="hidden" name="return_tab" value="system">
                    <button type="submit" class="w-full rounded-xl border border-rose-200 bg-rose-50 px-4 py-2.5 text-sm font-semibold text-rose-700 transition hover:bg-rose-100">Limpar credenciais</button>
                  </form>
                </div>
              </div>
            </div>
          </div>

          <div class="mt-5 grid gap-5 xl:grid-cols-2">
            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <h4 class="font-display text-lg font-semibold text-slate-900">Diagnostico de logs</h4>
              <p class="mt-1 text-sm text-slate-600">Leia o fim do `error.log` de um site para identificar falhas de PHP, permissao ou rewrite.</p>
              <form method="get" class="mt-4 grid gap-3 sm:grid-cols-[1fr_120px_auto]">
                <input type="hidden" name="tab" value="system">
                <input type="hidden" name="diag_action" value="log">
                <div>
                  <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Site</label>
                  <select name="diag_site" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                    <?php foreach ($fileSites as $site): ?>
                      <?php $user = (string) ($site['user'] ?? ''); ?>
                      <option value="<?= h($user) ?>" <?= $user === $diagnosticSite ? 'selected' : '' ?>><?= h($user . ' (' . ((string) ($site['domain'] ?? '-')) . ')') ?></option>
                    <?php endforeach; ?>
                  </select>
                </div>
                <div>
                  <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Linhas</label>
                  <input type="number" min="10" max="500" name="diag_lines" value="<?= h($diagnosticLines) ?>" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                </div>
                <div class="flex items-end">
                  <button type="submit" class="rounded-xl bg-slate-700 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-800">Ver log</button>
                </div>
              </form>

              <?php if ($diagnosticAction === 'log' && $diagnosticLog !== null): ?>
                <div class="mt-4 rounded-xl border border-slate-200 bg-white p-4">
                  <div class="flex flex-wrap items-center gap-2 text-sm">
                    <span class="font-semibold text-slate-900"><?= h((string) ($diagnosticLog['domain'] ?? $diagnosticSite)) ?></span>
                    <?php if (($diagnosticLog['file'] ?? '') !== ''): ?>
                      <span class="text-slate-500"><?= h((string) $diagnosticLog['file']) ?></span>
                    <?php endif; ?>
                  </div>
                  <pre class="mt-3 overflow-x-auto rounded-xl border border-slate-200 bg-slate-950 p-3 font-mono text-xs text-slate-100"><?= h((string) ($diagnosticLog['content'] ?? 'Sem conteudo retornado.')) ?></pre>
                </div>
              <?php endif; ?>
            </div>

            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <h4 class="font-display text-lg font-semibold text-slate-900">Verificacao de rewrite e .htaccess</h4>
              <p class="mt-1 text-sm text-slate-600">Confere o vhost, o autoload do `.htaccess` e mostra um relatorio rapido do site selecionado.</p>
              <form method="get" class="mt-4 grid gap-3 sm:grid-cols-[1fr_auto]">
                <input type="hidden" name="tab" value="system">
                <input type="hidden" name="diag_action" value="htaccess">
                <div>
                  <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Site</label>
                  <select name="diag_site" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                    <?php foreach ($fileSites as $site): ?>
                      <?php $user = (string) ($site['user'] ?? ''); ?>
                      <option value="<?= h($user) ?>" <?= $user === $diagnosticSite ? 'selected' : '' ?>><?= h($user . ' (' . ((string) ($site['domain'] ?? '-')) . ')') ?></option>
                    <?php endforeach; ?>
                  </select>
                </div>
                <div class="flex items-end">
                  <button type="submit" class="rounded-xl bg-slate-700 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-800">Verificar</button>
                </div>
              </form>

              <?php if ($diagnosticAction === 'htaccess' && $diagnosticHtaccess !== null): ?>
                <div class="mt-4 rounded-xl border border-slate-200 bg-white p-4">
                  <div class="flex flex-wrap items-center gap-2 text-sm">
                    <span class="font-semibold text-slate-900"><?= h((string) ($diagnosticHtaccess['domain'] ?? $diagnosticSite)) ?></span>
                    <span class="rounded-full px-2.5 py-1 text-xs font-semibold <?= !empty($diagnosticHtaccess['healthy']) ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700' ?>">
                      <?= !empty($diagnosticHtaccess['healthy']) ? 'Saudavel' : 'Revisar configuracao' ?>
                    </span>
                  </div>
                  <pre class="mt-3 overflow-x-auto rounded-xl border border-slate-200 bg-white p-3 font-mono text-xs text-slate-800"><?= h((string) ($diagnosticHtaccess['content'] ?? 'Sem relatorio retornado.')) ?></pre>
                </div>
              <?php endif; ?>
            </div>
          </div>

          <?php if ($diagnosticError !== ''): ?>
            <div class="mt-5 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"><?= h($diagnosticError) ?></div>
          <?php endif; ?>

          <div class="mt-5 grid gap-5 xl:grid-cols-2">
            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <h4 class="font-display text-lg font-semibold text-slate-900">Corrigir permalink WordPress</h4>
              <p class="mt-1 text-sm text-slate-600">Reaplica o bloco de rewrite do WordPress e reinicia o OpenLiteSpeed.</p>
              <form method="post" class="mt-4 grid gap-3 sm:grid-cols-[1fr_auto]">
                <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                <input type="hidden" name="action" value="wordpress_fix_permalink">
                <input type="hidden" name="return_tab" value="system">
                <div>
                  <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Site WordPress</label>
                  <select name="site_user" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                    <?php foreach ($fileSites as $site): ?>
                      <?php $user = (string) ($site['user'] ?? ''); ?>
                      <option value="<?= h($user) ?>"><?= h($user . ' (' . ((string) ($site['domain'] ?? '-')) . ')') ?></option>
                    <?php endforeach; ?>
                  </select>
                </div>
                <div class="flex items-end">
                  <button type="submit" class="rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700">Corrigir permalink</button>
                </div>
              </form>
            </div>

            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <h4 class="font-display text-lg font-semibold text-slate-900">Corrigir rewrite padrao</h4>
              <p class="mt-1 text-sm text-slate-600">Aplica um `.htaccess` generico para apps sem WordPress usando um front controller.</p>
              <form method="post" class="mt-4 grid gap-3">
                <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                <input type="hidden" name="action" value="site_fix_rewrite">
                <input type="hidden" name="return_tab" value="system">
                <div>
                  <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Site</label>
                  <select name="site_user" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                    <?php foreach ($fileSites as $site): ?>
                      <?php $user = (string) ($site['user'] ?? ''); ?>
                      <option value="<?= h($user) ?>"><?= h($user . ' (' . ((string) ($site['domain'] ?? '-')) . ')') ?></option>
                    <?php endforeach; ?>
                  </select>
                </div>
                <div>
                  <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Front controller</label>
                  <input type="text" name="front_controller" value="index.php" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20" placeholder="public/index.php">
                </div>
                <button type="submit" class="rounded-xl bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-700">Aplicar rewrite</button>
              </form>
            </div>
          </div>

          <div class="mt-5 rounded-xl border border-slate-200 bg-slate-50 p-4">
            <h4 class="font-display text-lg font-semibold text-slate-900">Cron por site</h4>
            <p class="mt-1 text-sm text-slate-600">Adicione, visualize e remova tarefas agendadas sem sair do painel.</p>

            <form method="get" class="mt-3 grid gap-3 sm:grid-cols-[1fr_auto]">
              <input type="hidden" name="tab" value="system">
              <div>
                <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Site do cron</label>
                <select name="cron_site" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                  <?php foreach ($fileSites as $site): ?>
                    <?php $user = (string) ($site['user'] ?? ''); ?>
                    <option value="<?= h($user) ?>" <?= $user === $cronSite ? 'selected' : '' ?>><?= h($user . ' (' . ((string) ($site['domain'] ?? '-')) . ')') ?></option>
                  <?php endforeach; ?>
                </select>
              </div>
              <div class="flex items-end">
                <button type="submit" class="rounded-xl bg-slate-700 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-800">Carregar cron</button>
              </div>
            </form>

            <?php if ($cronReadError !== ''): ?>
              <div class="mt-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"><?= h($cronReadError) ?></div>
            <?php endif; ?>

            <?php if ($cronSite !== ''): ?>
              <form method="post" class="mt-4 rounded-xl border border-slate-200 bg-white p-4">
                <h5 class="font-semibold text-slate-900">Nova entrada cron</h5>
                <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                <input type="hidden" name="action" value="cron_add">
                <input type="hidden" name="site_user" value="<?= h($cronSite) ?>">

                <div class="mt-3 grid gap-3 md:grid-cols-5">
                  <div class="md:col-span-2">
                    <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Expressao</label>
                    <input name="cron_expression" placeholder="*/5 * * * * ou @daily" required class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                  </div>
                  <div class="md:col-span-3">
                    <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Comando</label>
                    <input name="cron_command" placeholder="php artisan schedule:run" required class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                  </div>
                </div>

                <div class="mt-3 flex flex-wrap items-center justify-between gap-3">
                  <label class="inline-flex items-center gap-2 text-sm text-slate-700">
                    <input type="checkbox" name="run_in_public_html" value="1" checked class="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500">
                    Executar dentro de `public_html`
                  </label>
                  <button type="submit" class="rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700">Adicionar cron</button>
                </div>
              </form>

              <div class="mt-4 rounded-xl border border-slate-200 bg-white p-4">
                <h5 class="font-semibold text-slate-900">Entradas atuais</h5>
                <?php if ($cronItems === []): ?>
                  <p class="mt-2 text-sm text-slate-600">Nenhuma entrada cron encontrada para este site.</p>
                <?php else: ?>
                  <div class="mt-3 overflow-x-auto rounded-xl border border-slate-200">
                    <table class="min-w-full divide-y divide-slate-200 text-sm">
                      <thead class="bg-slate-50 text-left text-xs uppercase tracking-[0.14em] text-slate-500">
                        <tr>
                          <th class="px-4 py-3">Linha cron</th>
                          <th class="px-4 py-3">Ação</th>
                        </tr>
                      </thead>
                      <tbody class="divide-y divide-slate-200 bg-white">
                        <?php foreach ($cronItems as $line): ?>
                          <?php $line = (string) $line; ?>
                          <tr class="hover:bg-slate-50">
                            <td class="px-4 py-3 font-mono text-xs text-slate-700"><?= h($line) ?></td>
                            <td class="px-4 py-3">
                              <form method="post" onsubmit="return confirm('Remover esta entrada cron?');">
                                <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                                <input type="hidden" name="action" value="cron_remove">
                                <input type="hidden" name="site_user" value="<?= h($cronSite) ?>">
                                <input type="hidden" name="cron_line_token" value="<?= h(b64urlEncode($line)) ?>">
                                <button type="submit" class="rounded-lg border border-rose-200 bg-rose-50 px-3 py-1.5 text-xs font-semibold text-rose-700 transition hover:bg-rose-100">Remover</button>
                              </form>
                            </td>
                          </tr>
                        <?php endforeach; ?>
                      </tbody>
                    </table>
                  </div>
                <?php endif; ?>
              </div>
            <?php endif; ?>
          </div>
        </section>
      <?php endif; ?>
    </main>
  </div>
  <script>
    (function () {
      const repoFilter = document.querySelector('[data-github-repo-filter]');
      const repoSelect = document.querySelector('[data-github-repo-select]');
      const branchInput = document.getElementById('github-branch-input');

      if (repoFilter && repoSelect) {
        const allOptions = Array.from(repoSelect.options).map((option) => ({
          value: option.value,
          label: option.text,
          defaultBranch: option.dataset.defaultBranch || ''
        }));

        const renderOptions = (query) => {
          const normalized = query.trim().toLowerCase();
          const matches = allOptions.filter((item) => normalized === '' || item.label.toLowerCase().includes(normalized) || item.value.toLowerCase().includes(normalized));

          repoSelect.innerHTML = '';
          for (const item of matches) {
            const option = document.createElement('option');
            option.value = item.value;
            option.text = item.label;
            option.dataset.defaultBranch = item.defaultBranch;
            repoSelect.appendChild(option);
          }

          if (repoSelect.options.length > 0) {
            repoSelect.selectedIndex = 0;
            if (branchInput && branchInput.value.trim() === '') {
              branchInput.value = repoSelect.options[0].dataset.defaultBranch || '';
            }
          }
        };

        repoFilter.addEventListener('input', () => renderOptions(repoFilter.value));
        repoSelect.addEventListener('change', () => {
          if (!branchInput) {
            return;
          }
          const selected = repoSelect.options[repoSelect.selectedIndex];
          if (selected) {
            branchInput.value = selected.dataset.defaultBranch || '';
          }
        });

        renderOptions('');
      }

      const cloneCard = document.querySelector('[data-github-clone-card="running"]');
      if (cloneCard) {
        window.setTimeout(() => {
          window.location.reload();
        }, 4000);
      }
    })();
  </script>
</body>
</html>
