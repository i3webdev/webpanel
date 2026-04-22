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

$tab = (string) ($_GET['tab'] ?? 'dashboard');
$allowedTabs = ['dashboard', 'sites', 'files', 'database', 'system'];
if (!in_array($tab, $allowedTabs, true)) {
    $tab = 'dashboard';
}

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

      <?php if ($siteCode !== 0): ?>
        <div class="mb-5 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">Falha ao carregar sites: <?= h($siteErr) ?></div>
      <?php endif; ?>

      <?php if ($tab === 'dashboard'): ?>
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
          <h3 class="font-display text-xl font-semibold text-slate-900">Gerenciador de arquivos</h3>

          <form method="get" class="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <input type="hidden" name="tab" value="files">

            <div class="sm:col-span-2 lg:col-span-1">
              <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Site</label>
              <select name="site" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                <?php foreach ($fileSites as $site): ?>
                  <?php $user = (string) ($site['user'] ?? ''); ?>
                  <option value="<?= h($user) ?>" <?= $user === $fileSite ? 'selected' : '' ?>><?= h($user . ' (' . ((string) ($site['domain'] ?? '-')) . ')') ?></option>
                <?php endforeach; ?>
              </select>
            </div>

            <div class="sm:col-span-2 lg:col-span-2">
              <label class="mb-1 block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Pasta relativa</label>
              <input name="path" value="<?= h($filePath) ?>" placeholder="ex: wp-content/themes" class="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
            </div>

            <div class="flex items-end">
              <button type="submit" class="w-full rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700">Abrir</button>
            </div>
          </form>

          <?php if ($fileReadError !== ''): ?>
            <div class="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"><?= h($fileReadError) ?></div>
          <?php endif; ?>

          <?php if ($fileSite !== ''): ?>
            <div class="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
              <p class="text-sm text-slate-600">Raiz: <span class="font-semibold text-slate-800">/home/<?= h($fileSite) ?>/public_html<?= $fileList['current'] !== '' ? '/' . h((string) $fileList['current']) : '' ?></span></p>
              <?php if (($fileList['parent'] ?? '') !== '' || $filePath !== ''): ?>
                <a href="<?= h(baseUrl(['tab' => 'files', 'site' => $fileSite, 'path' => (string) ($fileList['parent'] ?? '')])) ?>" class="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 transition hover:bg-slate-100">Voltar pasta</a>
              <?php endif; ?>
            </div>

            <div class="mt-4 overflow-x-auto rounded-xl border border-slate-200">
              <table class="min-w-full divide-y divide-slate-200 text-sm">
                <thead class="bg-slate-50 text-left text-xs uppercase tracking-[0.14em] text-slate-500">
                  <tr>
                    <th class="px-4 py-3">Nome</th>
                    <th class="px-4 py-3">Tipo</th>
                    <th class="px-4 py-3">Tamanho</th>
                    <th class="px-4 py-3">Acoes</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-200 bg-white">
                  <?php foreach (($fileList['items'] ?? []) as $item): ?>
                    <?php
                    $name = (string) ($item['name'] ?? '');
                    $type = (string) ($item['type'] ?? 'file');
                    $rel = (string) ($item['relpath'] ?? '');
                    ?>
                    <tr class="hover:bg-slate-50">
                      <td class="px-4 py-3 font-medium text-slate-900"><?= h($name) ?></td>
                      <td class="px-4 py-3 text-slate-600"><?= h($type) ?></td>
                      <td class="px-4 py-3 text-slate-600"><?= h((string) ($item['size'] ?? 0)) ?></td>
                      <td class="px-4 py-3">
                        <div class="flex flex-wrap gap-2">
                          <?php if ($type === 'dir'): ?>
                            <a href="<?= h(baseUrl(['tab' => 'files', 'site' => $fileSite, 'path' => $rel])) ?>" class="rounded-lg border border-blue-200 bg-blue-50 px-3 py-1.5 text-xs font-semibold text-blue-700 transition hover:bg-blue-100">Abrir</a>
                          <?php else: ?>
                            <a href="<?= h(baseUrl(['tab' => 'files', 'site' => $fileSite, 'path' => $filePath, 'edit' => $rel])) ?>" class="rounded-lg border border-indigo-200 bg-indigo-50 px-3 py-1.5 text-xs font-semibold text-indigo-700 transition hover:bg-indigo-100">Editar</a>
                          <?php endif; ?>

                          <form method="post" onsubmit="return confirm('Remover este item?');">
                            <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                            <input type="hidden" name="action" value="file_delete">
                            <input type="hidden" name="site_user" value="<?= h($fileSite) ?>">
                            <input type="hidden" name="target_path" value="<?= h($rel) ?>">
                            <input type="hidden" name="current_path" value="<?= h($filePath) ?>">
                            <button type="submit" class="rounded-lg border border-rose-200 bg-rose-50 px-3 py-1.5 text-xs font-semibold text-rose-700 transition hover:bg-rose-100">Excluir</button>
                          </form>
                        </div>
                      </td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>

            <div class="mt-5 grid gap-4 lg:grid-cols-2">
              <form method="post" class="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <h4 class="font-display text-lg font-semibold text-slate-900">Novo diretorio</h4>
                <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                <input type="hidden" name="action" value="file_mkdir">
                <input type="hidden" name="site_user" value="<?= h($fileSite) ?>">
                <input type="hidden" name="current_path" value="<?= h($filePath) ?>">
                <input name="new_dir" placeholder="ex: nova-pasta" required class="mt-3 w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20">
                <button type="submit" class="mt-3 w-full rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700">Criar</button>
              </form>

              <form method="post" enctype="multipart/form-data" class="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <h4 class="font-display text-lg font-semibold text-slate-900">Upload de arquivo</h4>
                <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                <input type="hidden" name="action" value="file_upload">
                <input type="hidden" name="site_user" value="<?= h($fileSite) ?>">
                <input type="hidden" name="current_path" value="<?= h($filePath) ?>">
                <input type="file" name="upload_file" required class="mt-3 block w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700 file:mr-3 file:rounded-lg file:border-0 file:bg-blue-50 file:px-3 file:py-1.5 file:text-xs file:font-semibold file:text-blue-700 hover:file:bg-blue-100">
                <button type="submit" class="mt-3 w-full rounded-xl bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-emerald-700">Enviar</button>
              </form>
            </div>

            <?php if ($fileEdit !== ''): ?>
              <form method="post" class="mt-5 rounded-2xl border border-slate-200 bg-white p-4">
                <h4 class="font-display text-lg font-semibold text-slate-900">Editando: <?= h($fileEdit) ?></h4>
                <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                <input type="hidden" name="action" value="file_save">
                <input type="hidden" name="site_user" value="<?= h($fileSite) ?>">
                <input type="hidden" name="file_path" value="<?= h($fileEdit) ?>">
                <textarea name="file_content" class="mt-3 min-h-[360px] w-full rounded-xl border border-slate-300 bg-white px-3 py-3 font-mono text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"><?= h($fileContent) ?></textarea>
                <button type="submit" class="mt-3 rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700">Salvar arquivo</button>
              </form>
            <?php endif; ?>
          <?php endif; ?>
        </section>
      <?php endif; ?>

      <?php if ($tab === 'database'): ?>
        <section class="rounded-2xl border border-slate-200 bg-white p-5 shadow-panel">
          <h3 class="font-display text-xl font-semibold text-slate-900">Acesso ao banco de dados</h3>
          <p class="mt-2 text-sm text-slate-600">Gerencie bancos pelo phpMyAdmin e crie bancos adicionais por site direto aqui.</p>

          <div class="mt-4 grid gap-4 lg:grid-cols-2">
            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <h4 class="font-display text-lg font-semibold text-slate-900">phpMyAdmin</h4>
              <p class="mt-1 text-sm text-slate-600">Acesso visual aos bancos do servidor.</p>
              <?php if ($phpmyadminDomain !== ''): ?>
                <a href="<?= h('https://' . $phpmyadminDomain) ?>" target="_blank" rel="noopener" class="mt-3 inline-flex items-center rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700">Abrir phpMyAdmin (<?= h($phpmyadminDomain) ?>)</a>
              <?php else: ?>
                <div class="mt-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">Dominio do phpMyAdmin nao encontrado. Configure no instalador.</div>
              <?php endif; ?>
            </div>

            <form method="post" class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <h4 class="font-display text-lg font-semibold text-slate-900">Criar banco adicional</h4>
              <p class="mt-1 text-sm text-slate-600">Cria banco + usuário para um site existente.</p>
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
</body>
</html>
