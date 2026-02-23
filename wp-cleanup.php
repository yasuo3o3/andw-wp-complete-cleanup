<?php
// PHPバージョンチェック（7.4未満は非対応）
if (PHP_VERSION_ID < 70400) {
    http_response_code(500);
    exit('<!DOCTYPE html><html lang="ja"><head><meta charset="UTF-8"></head><body>'
        . '<h1>PHP 7.4 以上が必要です</h1>'
        . '<p>現在のPHPバージョン: ' . PHP_VERSION . '</p>'
        . '<p>サーバーのPHPバージョンをアップグレードしてください。</p>'
        . '</body></html>');
}

/**
 * WordPress Complete Cleanup Script
 *
 * FTPでWordPressルートに設置し、ブラウザからアクセスして使用。
 * 対象プレフィックスのDBテーブルとWP関連ファイルを安全に削除する。
 *
 * 使い方:
 *   1. 下記の PASSWORD_HASH を自分のパスワードハッシュに変更
 *      (生成: php -r "echo password_hash('your-password', PASSWORD_DEFAULT);")
 *   2. 必要に応じて EXPIRES_AT を変更
 *   3. FTPでWordPressルートにアップロード
 *   4. ブラウザでアクセスして実行
 */

// ============================================================
// 設定（設置時に変更してください）
// ============================================================

// パスワードハッシュ（php -r "echo password_hash('your-password', PASSWORD_DEFAULT);" で生成）
define('PASSWORD_HASH', '$2y$10$CHANGE_THIS_TO_YOUR_HASH');

// 有効期限（UNIXタイムスタンプ。デフォルト: このファイルの設置から24時間後を想定）
// 例: strtotime('2026-03-01 00:00:00') → 1740787200
define('EXPIRES_AT', 0); // 0 = 無制限（非推奨）

// ============================================================
// 定数
// ============================================================
define('SCRIPT_VERSION', '1.0.0');
define('MAX_LOGIN_ATTEMPTS', 3);
define('LOCKOUT_DURATION', 3600); // 1時間
define('WP_ROOT', __DIR__);

// WordPress既知のファイル・ディレクトリ（ホワイトリスト）
define('WP_KNOWN_DIRS', [
    'wp-admin',
    'wp-includes',
    'wp-content',
]);

define('WP_KNOWN_FILES', [
    'index.php',
    'license.txt',
    'readme.html',
    'xmlrpc.php',
    '.htaccess',
    '.htpasswd',
    '.user.ini',
]);

// wp-*.php パターンでマッチするファイルも削除対象
define('WP_FILE_PATTERN', '/^wp-.*\.php$/');

// ============================================================
// HTMLエスケープヘルパー（PHP 7.4互換）
// ============================================================
function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// ============================================================
// セッション開始（セキュリティ属性付き）
// ============================================================
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', '1');
}
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ============================================================
// 有効期限チェック
// ============================================================
function checkExpiry(): void
{
    if (EXPIRES_AT > 0 && time() > EXPIRES_AT) {
        @unlink(__FILE__);
        http_response_code(410);
        exit('<!DOCTYPE html><html><body><h1>有効期限切れ</h1><p>このスクリプトは有効期限が切れたため、自動削除されました。</p></body></html>');
    }
}

// ============================================================
// IPベース認証ロック
// ============================================================
function getLockFilePath(): string
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    // PASSWORD_HASHを含めて他ユーザーのロックファイルとの衝突を防止
    return sys_get_temp_dir() . '/wp_cleanup_lock_' . md5($ip . __FILE__ . PASSWORD_HASH);
}

function isLockedOut(): bool
{
    $lockFile = getLockFilePath();
    if (!file_exists($lockFile)) {
        return false;
    }
    $data = json_decode(file_get_contents($lockFile), true);
    if ($data === null) {
        return false;
    }
    if ($data['count'] >= MAX_LOGIN_ATTEMPTS && (time() - $data['time']) < LOCKOUT_DURATION) {
        return true;
    }
    if ((time() - $data['time']) >= LOCKOUT_DURATION) {
        @unlink($lockFile);
        return false;
    }
    return false;
}

function recordFailedAttempt(): void
{
    $lockFile = getLockFilePath();
    $data = ['count' => 1, 'time' => time()];
    if (file_exists($lockFile)) {
        $existing = json_decode(file_get_contents($lockFile), true);
        if ($existing !== null) {
            $data['count'] = $existing['count'] + 1;
        }
    }
    file_put_contents($lockFile, json_encode($data));
}

function clearLockout(): void
{
    @unlink(getLockFilePath());
}

// ============================================================
// パスワード認証
// ============================================================
function authenticate(string $password): bool
{
    if (PASSWORD_HASH === '$2y$10$CHANGE_THIS_TO_YOUR_HASH') {
        return false;
    }
    return password_verify($password, PASSWORD_HASH);
}

function isAuthenticated(): bool
{
    return !empty($_SESSION['wp_cleanup_auth']);
}

// ============================================================
// CSRFトークン
// ============================================================
function generateCsrfToken(): string
{
    $token = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $token;
    return $token;
}

function verifyCsrfToken(string $token): bool
{
    if (!empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token)) {
        unset($_SESSION['csrf_token']); // 使い捨て（リプレイ攻撃防止）
        return true;
    }
    return false;
}

// ============================================================
// wp-config.php 解析
// ============================================================
function findWpConfig(): ?string
{
    // 1. カレントディレクトリを優先
    $current = WP_ROOT . '/wp-config.php';
    if (file_exists($current) && is_readable($current)) {
        return $current;
    }

    // 2. 1つ上のディレクトリ（WordPressの仕様: wp-settings.phpが親に存在しない場合のみ有効）
    $parent = dirname(WP_ROOT) . '/wp-config.php';
    $parentSettings = dirname(WP_ROOT) . '/wp-settings.php';
    if (file_exists($parent) && is_readable($parent) && !file_exists($parentSettings)) {
        return $parent;
    }

    return null;
}

function parseWpConfig(string $path): array
{
    $content = file_get_contents($path);
    if ($content === false) {
        throw new RuntimeException('wp-config.php を読み取れません');
    }

    $config = [];

    // define() の値を取得（エスケープ済みクォート・複数行対応）
    $defines = ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_CHARSET'];
    foreach ($defines as $key) {
        $quotedKey = preg_quote($key, '/');
        // シングルクォート値: エスケープされた \' を含む文字列に対応
        $patternSingle = '/define\s*\(\s*[\'"]' . $quotedKey . '[\'"]\s*,\s*\'((?:[^\'\\\\]|\\\\.)*)\'\s*\)/s';
        // ダブルクォート値
        $patternDouble = '/define\s*\(\s*[\'"]' . $quotedKey . '[\'"]\s*,\s*"((?:[^"\\\\]|\\\\.)*)"\s*\)/s';
        if (preg_match($patternSingle, $content, $m)) {
            $config[$key] = stripslashes($m[1]);
        } elseif (preg_match($patternDouble, $content, $m)) {
            $config[$key] = stripslashes($m[1]);
        } elseif ($key !== 'DB_CHARSET') {
            throw new RuntimeException("wp-config.php から {$key} を検出できません");
        }
    }

    if (!isset($config['DB_CHARSET'])) {
        $config['DB_CHARSET'] = 'utf8mb4';
    }

    // $table_prefix を取得（行コメント・ブロックコメントを除外）
    $prefix = null;
    $lines = explode("\n", $content);
    $inBlockComment = false;
    foreach ($lines as $line) {
        $trimmed = ltrim($line);

        // ブロックコメント内の処理
        if ($inBlockComment) {
            if (strpos($trimmed, '*/') !== false) {
                $inBlockComment = false;
                $trimmed = ltrim(substr($trimmed, strpos($trimmed, '*/') + 2));
                if ($trimmed === '') {
                    continue;
                }
            } else {
                continue;
            }
        }

        // ブロックコメント開始
        $openPos = strpos($trimmed, '/*');
        if ($openPos !== false) {
            $closePos = strpos($trimmed, '*/', $openPos + 2);
            // 同一行で閉じる場合: /* ... */
            if ($closePos !== false) {
                // コメント部分を除去して残りを検査
                $trimmed = preg_replace('/\/\*.*?\*\//', '', $trimmed);
            } else {
                $inBlockComment = true;
                continue;
            }
        }

        // 行コメントを除外
        if (strpos($trimmed, '//') === 0 || strpos($trimmed, '#') === 0) {
            continue;
        }

        if (preg_match('/\$table_prefix\s*=\s*[\'"]([a-zA-Z0-9_]+)[\'"]\s*;/', $trimmed, $m)) {
            $prefix = $m[1];
            break;
        }
    }

    if ($prefix === null) {
        throw new RuntimeException('$table_prefix を検出できません');
    }
    $config['table_prefix'] = $prefix;

    return $config;
}

// ============================================================
// DB_HOST パース（ポート/ソケット対応）
// ============================================================
function parseDbHost(string $host): array
{
    $port = 3306;
    $socket = '';

    // ソケットパス: localhost:/tmp/mysql.sock
    if (strpos($host, ':/') !== false) {
        list($host, $socket) = explode(':', $host, 2);
        return ['host' => $host, 'port' => $port, 'socket' => $socket];
    }

    // IPv6ブラケット表記: [::1] or [::1]:3306
    if (strpos($host, '[') === 0) {
        $closeBracket = strpos($host, ']');
        if ($closeBracket !== false) {
            $ipv6Host = substr($host, 1, $closeBracket - 1);
            $rest = substr($host, $closeBracket + 1);
            $host = $ipv6Host;
            if (strpos($rest, ':') === 0 && strlen($rest) > 1) {
                $port = (int)substr($rest, 1);
            }
        }
        return ['host' => $host, 'port' => $port, 'socket' => $socket];
    }

    // 標準: hostname:port（コロンが1つだけの場合）
    if (strpos($host, ':') !== false && substr_count($host, ':') === 1) {
        list($host, $portStr) = explode(':', $host, 2);
        if (is_numeric($portStr)) {
            $port = (int)$portStr;
        }
    }
    // コロンが複数 = ブラケットなしIPv6（例: ::1）→ そのまま使用

    return ['host' => $host, 'port' => $port, 'socket' => $socket];
}

// ============================================================
// DB接続
// ============================================================
function connectDatabase(array $config): mysqli
{
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    $hostInfo = parseDbHost($config['DB_HOST']);

    try {
        $conn = new mysqli(
            $hostInfo['host'],
            $config['DB_USER'],
            $config['DB_PASSWORD'],
            $config['DB_NAME'],
            $hostInfo['port'],
            $hostInfo['socket'] ?: null
        );
    } catch (mysqli_sql_exception $e) {
        throw new RuntimeException('データベース接続に失敗しました。wp-config.php の接続設定を確認してください。');
    }

    $conn->set_charset($config['DB_CHARSET']);
    return $conn;
}

// ============================================================
// 対象テーブル取得（LIKEエスケープ済み）
// ============================================================
function getTargetTables(mysqli $conn, string $dbName, string $prefix): array
{
    // _ と % はLIKEのワイルドカードなのでエスケープ必須
    // プレフィックスは [a-zA-Z0-9_]+ で検証済みなのでSQLインジェクションリスクなし
    $escaped = str_replace(['%', '_'], ['\\%', '\\_'], $prefix);
    $sql = "SHOW TABLES FROM `" . $conn->real_escape_string($dbName) . "` LIKE '" . $escaped . "%'";

    $result = $conn->query($sql);
    if ($result === false) {
        throw new RuntimeException('テーブル一覧の取得に失敗しました');
    }

    $tables = [];
    while ($row = $result->fetch_row()) {
        $tables[] = $row[0];
    }
    return $tables;
}

// ============================================================
// テーブルの行数取得
// ============================================================
function getTableRowCounts(mysqli $conn, array $tables): array
{
    $counts = [];
    foreach ($tables as $table) {
        $quoted = '`' . str_replace('`', '``', $table) . '`';
        try {
            $result = $conn->query("SELECT COUNT(*) FROM {$quoted}");
            $row = $result->fetch_row();
            $counts[$table] = (int)$row[0];
        } catch (Exception $e) {
            $counts[$table] = '取得不可';
        }
    }
    return $counts;
}

// ============================================================
// DB内の全プレフィックス一覧を取得（比較用）
// ============================================================
function getAllPrefixes(mysqli $conn, string $dbName): array
{
    $result = $conn->query("SHOW TABLES FROM `" . $conn->real_escape_string($dbName) . "`");
    $tables = [];
    while ($row = $result->fetch_row()) {
        $tables[] = $row[0];
    }

    // WordPressのコアテーブル名パターンからプレフィックスを推定
    $wpCoreTables = ['posts', 'postmeta', 'options', 'users', 'usermeta', 'terms',
                     'term_taxonomy', 'term_relationships', 'comments', 'commentmeta', 'links'];
    $prefixes = [];
    foreach ($tables as $table) {
        foreach ($wpCoreTables as $core) {
            if (substr($table, -strlen('_' . $core)) === '_' . $core || substr($table, -strlen($core)) === $core) {
                $prefix = substr($table, 0, strlen($table) - strlen($core));
                if ($prefix !== '' && !in_array($prefix, $prefixes)) {
                    $prefixes[] = $prefix;
                }
            }
        }
    }
    return array_unique($prefixes);
}

// ============================================================
// 入れ子WordPress検出
// ============================================================
function detectNestedWP(string $rootDir): array
{
    $nested = [];
    try {
        $iterator = new RecursiveDirectoryIterator($rootDir, FilesystemIterator::SKIP_DOTS);
        $files = new RecursiveIteratorIterator($iterator, RecursiveIteratorIterator::SELF_FIRST);
        $files->setMaxDepth(3); // 深さ3まで

        foreach ($files as $file) {
            if ($file->getFilename() === 'wp-config.php' && $file->getPath() !== $rootDir) {
                $nested[] = $file->getPath();
            }
        }
    } catch (Exception $e) {
        // アクセスできないディレクトリはスキップ
    }
    return $nested;
}

// ============================================================
// サイトURLをDBから取得（ドメイン確認用）
// ============================================================
function getSiteUrl(mysqli $conn, string $prefix): ?string
{
    $tableName = $prefix . 'options';
    $quoted = '`' . str_replace('`', '``', $tableName) . '`';
    try {
        $result = $conn->query("SELECT option_value FROM {$quoted} WHERE option_name = 'siteurl' LIMIT 1");
        if ($result && $row = $result->fetch_row()) {
            return $row[0];
        }
    } catch (Exception $e) {
        // テーブルが存在しない場合等
    }
    return null;
}

// ============================================================
// マルチサイト検出
// ============================================================
function detectMultisite(string $wpConfigContent): bool
{
    // MULTISITE, WP_ALLOW_MULTISITE, SUBDOMAIN_INSTALL などを検出
    if (preg_match('/define\s*\(\s*[\'"](?:MULTISITE|WP_ALLOW_MULTISITE|SUBDOMAIN_INSTALL)[\'"]\s*,\s*true\s*\)/i', $wpConfigContent)) {
        return true;
    }
    return false;
}

// ============================================================
// テーブル削除
// ============================================================
function dropTables(mysqli $conn, array $tables): array
{
    $errors = [];
    $conn->query('SET FOREIGN_KEY_CHECKS = 0');

    foreach ($tables as $table) {
        $quoted = '`' . str_replace('`', '``', $table) . '`';
        try {
            $conn->query("DROP TABLE IF EXISTS {$quoted}");
        } catch (Exception $e) {
            $errors[] = "{$table}: {$e->getMessage()}";
        }
    }

    $conn->query('SET FOREIGN_KEY_CHECKS = 1');
    return $errors;
}

// ============================================================
// ホワイトリスト方式のファイル削除
// ============================================================
function deleteWpFiles(string $rootDir, string $selfPath = ''): array
{
    $results = ['deleted_dirs' => [], 'deleted_files' => [], 'errors' => [], 'skipped' => []];
    $count = 0;

    // 1. ホワイトリストのディレクトリを再帰削除
    foreach (WP_KNOWN_DIRS as $dir) {
        $dirPath = $rootDir . DIRECTORY_SEPARATOR . $dir;
        if (is_dir($dirPath)) {
            $errs = deleteDirectoryRecursive($dirPath, $selfPath, $count);
            if (empty($errs)) {
                $results['deleted_dirs'][] = $dir . '/';
            } else {
                $results['errors'] = array_merge($results['errors'], $errs);
            }
        }
    }

    // 2. ホワイトリストのファイルを削除
    foreach (WP_KNOWN_FILES as $file) {
        $filePath = $rootDir . DIRECTORY_SEPARATOR . $file;
        if (file_exists($filePath) && !is_dir($filePath)) {
            $realFile = realpath($filePath);
            if ($selfPath !== '' && $realFile !== false && $realFile === $selfPath) {
                continue; // 自分自身はスキップ（後で消す）
            }
            if (@unlink($filePath)) {
                $results['deleted_files'][] = $file;
            } else {
                $results['errors'][] = "削除失敗: {$file}";
            }
        }
    }

    // 3. wp-*.php パターンのファイルを削除
    $items = @scandir($rootDir);
    if ($items) {
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            $itemPath = $rootDir . DIRECTORY_SEPARATOR . $item;
            if (!is_dir($itemPath) && preg_match(WP_FILE_PATTERN, $item)) {
                $realItem = realpath($itemPath);
                if ($selfPath !== '' && $realItem !== false && $realItem === $selfPath) continue;
                if (@unlink($itemPath)) {
                    $results['deleted_files'][] = $item;
                } else {
                    $results['errors'][] = "削除失敗: {$item}";
                }
            }
        }
    }

    // 残存ファイル一覧（削除済みファイルを除外して再走査）
    $items = @scandir($rootDir);
    if ($items) {
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            $realItem = realpath($rootDir . DIRECTORY_SEPARATOR . $item);
            if ($selfPath !== '' && $realItem !== false && $realItem === $selfPath) continue;
            $results['skipped'][] = $item;
        }
    }

    return $results;
}

function deleteDirectoryRecursive(string $dir, string $excludePath, int &$count): array
{
    $errors = [];

    // シンボリックリンクは追従しない。リンク自体を削除
    if (is_link($dir)) {
        if (!@unlink($dir)) {
            $errors[] = "シンボリックリンク削除失敗: {$dir}";
        }
        return $errors;
    }

    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO),
            RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $item) {
            $path = $item->getPathname();

            // 自分自身は除外
            $realItemPath = realpath($path);
            if ($excludePath !== '' && $realItemPath !== false && $realItemPath === $excludePath) continue;

            // 1000ファイルごとにタイムアウトリセット
            if (++$count % 1000 === 0) {
                @set_time_limit(60);
            }

            // シンボリックリンクは追従しない
            if (is_link($path)) {
                if (!@unlink($path)) {
                    $errors[] = "リンク削除失敗: {$path}";
                }
                continue;
            }

            if ($item->isDir()) {
                if (!@rmdir($path)) {
                    @chmod($path, 0755);
                    if (!@rmdir($path)) {
                        $errors[] = "ディレクトリ削除失敗: {$path}";
                    }
                }
            } else {
                if (!@unlink($path)) {
                    @chmod($path, 0644);
                    if (!@unlink($path)) {
                        $errors[] = "ファイル削除失敗: {$path}";
                    }
                }
            }
        }
    } catch (Exception $e) {
        $errors[] = "ディレクトリ走査エラー: {$dir} - {$e->getMessage()}";
    }

    // ディレクトリ自体を削除
    if (!@rmdir($dir)) {
        @chmod($dir, 0755);
        if (!@rmdir($dir)) {
            $errors[] = "ルートディレクトリ削除失敗: {$dir}";
        }
    }

    return $errors;
}

// ============================================================
// DROP権限チェック
// ============================================================
function checkDropPrivilege(mysqli $conn): bool
{
    try {
        $result = $conn->query("SHOW GRANTS");
        while ($row = $result->fetch_row()) {
            $grant = strtoupper($row[0]);
            if (strpos($grant, 'ALL PRIVILEGES') !== false || strpos($grant, 'DROP') !== false) {
                return true;
            }
        }
        return false;
    } catch (Exception $e) {
        return false; // 権限確認失敗=安全側に倒す
    }
}

// ============================================================
// HTML出力
// ============================================================
function renderPage(string $title, string $body): void
{
    echo '<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>' . h($title) . '</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #1a1a2e; color: #e0e0e0; padding: 2rem; min-height: 100vh; }
  .container { max-width: 720px; margin: 0 auto; }
  h1 { color: #ff6b6b; margin-bottom: 1.5rem; font-size: 1.5rem; }
  h2 { color: #ffa502; margin: 1.5rem 0 0.8rem; font-size: 1.1rem; }
  .card { background: #16213e; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; border: 1px solid #2a2a4a; }
  .warning { background: #3d1f1f; border-color: #ff6b6b; }
  .info { background: #1f2d3d; border-color: #4ecdc4; }
  .success { background: #1f3d2d; border-color: #4ecdc4; }
  input[type="text"], input[type="password"] { width: 100%; padding: 0.7rem; border: 1px solid #4a4a6a; border-radius: 4px; background: #0f3460; color: #e0e0e0; font-size: 1rem; margin-top: 0.3rem; }
  button, input[type="submit"] { padding: 0.7rem 1.5rem; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; margin-top: 0.5rem; }
  .btn-danger { background: #ff4757; color: #fff; }
  .btn-danger:hover { background: #ff6b81; }
  .btn-primary { background: #4ecdc4; color: #1a1a2e; font-weight: bold; }
  .btn-primary:hover { background: #7bed9f; }
  table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
  th, td { padding: 0.4rem 0.6rem; text-align: left; border-bottom: 1px solid #2a2a4a; font-size: 0.9rem; }
  th { color: #a0a0c0; }
  .highlight { color: #ff6b6b; font-weight: bold; font-size: 1.1rem; }
  .tag { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.8rem; margin: 0.1rem; }
  .tag-red { background: #5c2020; color: #ff6b6b; }
  .tag-green { background: #205c2d; color: #7bed9f; }
  .tag-yellow { background: #5c5c20; color: #ffa502; }
  ul { padding-left: 1.2rem; }
  li { margin: 0.2rem 0; font-size: 0.9rem; }
  .footer { margin-top: 2rem; text-align: center; color: #666; font-size: 0.8rem; }
  .mono { font-family: monospace; background: #0f3460; padding: 0.1rem 0.4rem; border-radius: 3px; }
</style>
</head>
<body>
<div class="container">
<h1>' . h($title) . '</h1>
' . $body . '
<div class="footer">WordPress Cleanup Script v' . SCRIPT_VERSION . '</div>
</div>
</body>
</html>';
}

// ============================================================
// メインロジック
// ============================================================

// セキュリティ・レスポンスヘッダー
header('Content-Type: text/html; charset=UTF-8');
header('X-Robots-Tag: noindex, nofollow');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store, no-cache, must-revalidate');

// 1. 有効期限チェック
checkExpiry();

// 2. パスワード未設定チェック
if (PASSWORD_HASH === '$2y$10$CHANGE_THIS_TO_YOUR_HASH') {
    renderPage('設定エラー', '
        <div class="card warning">
            <p>パスワードハッシュが設定されていません。</p>
            <p style="margin-top:0.8rem;">以下のコマンドでハッシュを生成し、スクリプト冒頭の <span class="mono">PASSWORD_HASH</span> を書き換えてください:</p>
            <p class="mono" style="margin-top:0.5rem;">php -r "echo password_hash(\'your-password\', PASSWORD_DEFAULT);"</p>
        </div>
    ');
    exit;
}

// ロックアウトチェック
if (isLockedOut()) {
    renderPage('アクセス制限', '
        <div class="card warning">
            <p>パスワードの入力回数が上限を超えました。</p>
            <p style="margin-top:0.5rem;">しばらく待ってから再試行してください。</p>
        </div>
    ');
    exit;
}

// ============================================================
// ステップ判定
// ============================================================
$action = $_POST['action'] ?? $_GET['action'] ?? 'login';

// --- ログイン処理 ---
if ($action === 'login') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        if (authenticate($_POST['password'])) {
            session_regenerate_id(true); // セッション固定攻撃対策
            $_SESSION['wp_cleanup_auth'] = true;
            clearLockout();
            header('Location: ' . $_SERVER['SCRIPT_NAME'] . '?action=confirm');
            exit;
        } else {
            recordFailedAttempt();
            if (isLockedOut()) {
                renderPage('アクセス制限', '<div class="card warning"><p>パスワードの入力回数が上限を超えました。しばらく待ってください。</p></div>');
                exit;
            }
            $error = 'パスワードが正しくありません。';
        }
    }

    $errorHtml = '';
    if (isset($error)) {
        $errorHtml = '<div class="card warning"><p>' . h($error) . '</p></div>';
    }

    $expiryInfo = '';
    if (EXPIRES_AT > 0) {
        $expiryInfo = '<p style="margin-top:0.8rem;color:#a0a0c0;font-size:0.85rem;">有効期限: ' . date('Y-m-d H:i:s', EXPIRES_AT) . '</p>';
    }

    renderPage('WordPress Cleanup - 認証', '
        ' . $errorHtml . '
        <div class="card">
            <form method="post">
                <input type="hidden" name="action" value="login">
                <label>パスワード:</label>
                <input type="password" name="password" autofocus required>
                <div style="margin-top:1rem;">
                    <input type="submit" value="ログイン" class="btn-primary">
                </div>
            </form>
            ' . $expiryInfo . '
        </div>
    ');
    exit;
}

// --- 以降は認証必須 ---
if (!isAuthenticated()) {
    header('Location: ' . $_SERVER['SCRIPT_NAME']);
    exit;
}

// --- 確認画面 ---
if ($action === 'confirm') {
    try {
        $configPath = findWpConfig();
        if (!$configPath) {
            throw new RuntimeException('wp-config.php が見つかりません（カレントおよび1つ上のディレクトリを検索しました）');
        }

        $config = parseWpConfig($configPath);
        $conn = connectDatabase($config);

        // 対象テーブル取得
        $tables = getTargetTables($conn, $config['DB_NAME'], $config['table_prefix']);
        $rowCounts = getTableRowCounts($conn, $tables);

        // DB内の他プレフィックス検出
        $allPrefixes = getAllPrefixes($conn, $config['DB_NAME']);
        $otherPrefixes = array_filter($allPrefixes, fn($p) => $p !== $config['table_prefix']);

        // DROP権限チェック
        $hasDropPrivilege = checkDropPrivilege($conn);

        // サイトURL取得（ドメイン確認用、HTTP_HOSTより信頼性が高い）
        $siteUrl = getSiteUrl($conn, $config['table_prefix']);
        $confirmDomainSource = 'db'; // ドメインの取得元
        if ($siteUrl !== null) {
            $parsed = parse_url($siteUrl);
            $confirmDomain = isset($parsed['host']) ? $parsed['host'] : $_SERVER['HTTP_HOST'];
        } else {
            $confirmDomain = $_SERVER['SERVER_NAME'] ?? $_SERVER['HTTP_HOST'];
            $confirmDomainSource = 'server';
        }

        // マルチサイト検出
        $wpConfigContent = file_get_contents($configPath);
        $isMultisite = ($wpConfigContent !== false) ? detectMultisite($wpConfigContent) : false;

        // 入れ子WordPress検出
        $nestedWP = detectNestedWP(WP_ROOT);

        // ドキュメントルートチェック
        $realWpRoot = realpath(WP_ROOT);
        $realDocRoot = realpath($_SERVER['DOCUMENT_ROOT'] ?? '');
        $isDocRoot = ($realWpRoot !== false && $realDocRoot !== false && $realWpRoot === $realDocRoot);

        $conn->close();

        // CSRFトークン生成
        $csrf = generateCsrfToken();

        // セッションにDB情報を保存（実行時に使う）
        $_SESSION['wp_cleanup_config'] = $config;
        $_SESSION['wp_cleanup_tables'] = $tables;
        $_SESSION['wp_cleanup_confirm_domain'] = $confirmDomain;
        $_SESSION['wp_cleanup_config_path'] = $configPath;

        // --- HTML組み立て ---
        // h() グローバル関数を使用
        $body = '';

        // 基本情報
        $displayPath = ($realWpRoot !== false) ? $realWpRoot : WP_ROOT;
        $body .= '<div class="card info">';
        $body .= '<h2>対象サイト情報</h2>';
        $body .= '<table>';
        $body .= '<tr><th>サイトドメイン</th><td class="highlight">' . h($confirmDomain) . '</td></tr>';
        if ($siteUrl !== null) {
            $body .= '<tr><th>サイトURL (DB)</th><td class="mono">' . h($siteUrl) . '</td></tr>';
        }
        $body .= '<tr><th>削除パス</th><td class="mono">' . h($displayPath) . '</td></tr>';
        $body .= '<tr><th>データベース</th><td class="mono">' . h($config['DB_NAME']) . '</td></tr>';
        $body .= '<tr><th>テーブルプレフィックス</th><td class="mono">' . h($config['table_prefix']) . '</td></tr>';
        $body .= '<tr><th>wp-config.php</th><td class="mono">' . h($configPath) . '</td></tr>';
        $body .= '</table>';
        $body .= '</div>';

        // 警告表示
        if ($isDocRoot) {
            $body .= '<div class="card warning">';
            $body .= '<h2>注意: ドキュメントルート直下</h2>';
            $body .= '<p>このWordPressはドキュメントルート直下にインストールされています。WordPress関連ファイルのみ削除しますが、慎重に確認してください。</p>';
            $body .= '</div>';
        }

        if ($isMultisite) {
            $body .= '<div class="card warning">';
            $body .= '<h2>注意: マルチサイト構成</h2>';
            $body .= '<p>このWordPressはマルチサイト構成です。全サブサイトのデータも削除対象に含まれます。個別サブサイトのみの削除はこのスクリプトでは対応していません。</p>';
            $body .= '</div>';
        }

        if (!empty($nestedWP)) {
            $body .= '<div class="card warning">';
            $body .= '<h2>注意: サブディレクトリにWordPressが存在</h2>';
            $body .= '<p>以下のディレクトリにも別のWordPressがインストールされています。これらも削除対象に含まれます。</p><ul>';
            foreach ($nestedWP as $nwp) {
                $body .= '<li class="mono">' . h($nwp) . '</li>';
            }
            $body .= '</ul></div>';
        }

        if (!$hasDropPrivilege) {
            $body .= '<div class="card warning">';
            $body .= '<h2>注意: DROP権限なし</h2>';
            $body .= '<p>このDBユーザーにはDROP TABLE権限がない可能性があります。テーブル削除はphpMyAdminから手動で行ってください。ファイル削除のみ実行できます。</p>';
            $body .= '</div>';
        }

        // 他プレフィックス情報
        if (!empty($otherPrefixes)) {
            $body .= '<div class="card info">';
            $body .= '<h2>同一DB内の他WordPressプレフィックス</h2>';
            $body .= '<p>以下のプレフィックスは削除されません:</p><p>';
            foreach ($otherPrefixes as $op) {
                $body .= '<span class="tag tag-green">' . h($op) . '</span> ';
            }
            $body .= '</p></div>';
        }

        // 対象テーブル一覧
        $body .= '<div class="card">';
        $body .= '<h2>削除対象テーブル (' . count($tables) . '件)</h2>';
        if (empty($tables)) {
            $body .= '<p>対象テーブルが見つかりません。</p>';
        } else {
            $body .= '<table><tr><th>テーブル名</th><th>行数</th></tr>';
            foreach ($rowCounts as $tbl => $cnt) {
                $body .= '<tr><td class="mono">' . h($tbl) . '</td><td>' . h((string)$cnt) . '</td></tr>';
            }
            $body .= '</table>';
        }
        $body .= '</div>';

        // 削除対象ファイル/ディレクトリ
        $body .= '<div class="card">';
        $body .= '<h2>削除対象ファイル/ディレクトリ</h2>';
        $body .= '<p>以下のWordPress関連ファイル・ディレクトリのみ削除します:</p><ul>';
        foreach (WP_KNOWN_DIRS as $d) {
            $path = WP_ROOT . DIRECTORY_SEPARATOR . $d;
            if (is_dir($path)) {
                $body .= '<li><span class="tag tag-red">DIR</span> <span class="mono">' . h($d) . '/</span></li>';
            }
        }
        foreach (WP_KNOWN_FILES as $f) {
            $path = WP_ROOT . DIRECTORY_SEPARATOR . $f;
            if (file_exists($path)) {
                $body .= '<li><span class="tag tag-yellow">FILE</span> <span class="mono">' . h($f) . '</span></li>';
            }
        }
        // wp-*.php
        $items = @scandir(WP_ROOT);
        if ($items) {
            foreach ($items as $item) {
                if (preg_match(WP_FILE_PATTERN, $item) && !in_array($item, WP_KNOWN_FILES)) {
                    $body .= '<li><span class="tag tag-yellow">FILE</span> <span class="mono">' . h($item) . '</span></li>';
                }
            }
        }
        $body .= '</ul></div>';

        // 最終確認フォーム
        $body .= '<div class="card warning">';
        $body .= '<h2>最終確認</h2>';
        $body .= '<p>この操作は<strong>元に戻せません</strong>。本当に削除するには、以下に対象ドメイン名を正確に入力してください。</p>';
        $body .= '<form method="post">';
        $body .= '<input type="hidden" name="action" value="execute">';
        $body .= '<input type="hidden" name="csrf_token" value="' . h($csrf) . '">';
        $body .= '<input type="hidden" name="skip_db" value="' . ($hasDropPrivilege ? '0' : '1') . '">';
        $body .= '<label>ドメイン名を入力: <span class="highlight">' . h($confirmDomain) . '</span></label>';
        $body .= '<input type="text" name="confirm_domain" placeholder="' . h($confirmDomain) . '" required autocomplete="off">';
        $body .= '<div style="margin-top:1rem;">';
        $body .= '<button type="submit" class="btn-danger" onclick="return confirm(\'本当に実行しますか？この操作は元に戻せません。\')">削除を実行する</button>';
        $body .= '</div></form></div>';

    } catch (Exception $e) {
        $body = '<div class="card warning"><h2>エラー</h2><p>' . h($e->getMessage()) . '</p></div>';
    }

    renderPage('WordPress Cleanup - 確認', $body);
    exit;
}

// --- 削除実行 ---
if ($action === 'execute') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        header('Location: ' . $_SERVER['SCRIPT_NAME'] . '?action=confirm');
        exit;
    }

    // CSRFチェック
    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        renderPage('エラー', '<div class="card warning"><p>不正なリクエストです。<a href="' . h($_SERVER['SCRIPT_NAME']) . '?action=confirm" style="color:#4ecdc4;">確認画面に戻る</a></p></div>');
        exit;
    }

    // セッションからDB情報を取得
    $config = $_SESSION['wp_cleanup_config'] ?? null;
    $tables = $_SESSION['wp_cleanup_tables'] ?? null;
    $expectedDomain = $_SESSION['wp_cleanup_confirm_domain'] ?? null;
    $storedConfigPath = $_SESSION['wp_cleanup_config_path'] ?? null;
    if (!$config || !$tables || !$expectedDomain) {
        renderPage('エラー', '<div class="card warning"><p>セッションが切れました。<a href="' . h($_SERVER['SCRIPT_NAME']) . '" style="color:#4ecdc4;">最初からやり直す</a></p></div>');
        exit;
    }

    // ドメイン名一致チェック（セッションに保存されたDB由来のドメインと比較）
    $confirmDomain = trim($_POST['confirm_domain'] ?? '');
    if ($confirmDomain !== $expectedDomain) {
        renderPage('エラー', '<div class="card warning"><p>ドメイン名が一致しません。<a href="' . h($_SERVER['SCRIPT_NAME']) . '?action=confirm" style="color:#4ecdc4;">確認画面に戻る</a></p></div>');
        exit;
    }

    // 実行時間制限を延長
    @set_time_limit(300);
    @ini_set('memory_limit', '256M');

    // h() グローバル関数を使用
    $body = '';
    $dbErrors = [];
    $fileResults = [];

    // 自分のパスを先に記録（unlink後はrealpathが使えない）
    $selfRealPath = realpath(__FILE__);
    if ($selfRealPath === false) {
        $selfRealPath = __FILE__; // フォールバック
    }

    // 1. DBテーブル削除（最初に実行。失敗してもリトライ可能）
    $skipDb = ($_POST['skip_db'] ?? '0') === '1';
    if (!$skipDb && !empty($tables)) {
        try {
            $conn = connectDatabase($config);
            $dbErrors = dropTables($conn, $tables);
            $conn->close();
        } catch (Exception $e) {
            $dbErrors[] = 'DB接続エラー: ' . $e->getMessage();
        }
    }

    // 2. wp-config.php を削除（WP_ROOT内のもののみ。親ディレクトリのものは他サイトが使用する可能性があるため削除しない）
    $configPath = $storedConfigPath ?: findWpConfig();
    $configDeleted = false;
    $configInParent = false;
    if ($configPath) {
        $configDir = dirname(realpath($configPath) ?: $configPath);
        $wpRootReal = realpath(WP_ROOT) ?: WP_ROOT;
        if ($configDir === $wpRootReal) {
            $configDeleted = @unlink($configPath);
        } else {
            $configInParent = true; // 親ディレクトリにある → 削除しない
        }
    }

    // 3. ファイル削除（自己パスを渡して除外判定に使う）
    $fileResults = deleteWpFiles(WP_ROOT, $selfRealPath);

    // 4. スクリプト自身を最後に削除（メモリ上で実行継続）
    $selfDeleted = @unlink($selfRealPath);

    // --- 結果画面 ---
    $body .= '<div class="card success">';
    $body .= '<h2>削除完了</h2>';

    // DB結果
    if ($skipDb) {
        $body .= '<p><span class="tag tag-yellow">DB</span> DROP権限なし - スキップしました。phpMyAdminから手動で削除してください。</p>';
    } elseif (empty($dbErrors)) {
        $body .= '<p><span class="tag tag-green">DB</span> ' . count($tables) . ' テーブルを削除しました。</p>';
    } else {
        $body .= '<p><span class="tag tag-red">DB</span> 一部エラーがありました:</p><ul>';
        foreach ($dbErrors as $err) {
            $body .= '<li>' . h($err) . '</li>';
        }
        $body .= '</ul>';
    }

    // wp-config.php
    if ($configInParent) {
        $body .= '<p><span class="tag tag-yellow">wp-config.php</span> 親ディレクトリにあるため削除をスキップしました（他サイトが使用している可能性があります）</p>';
    } else {
        $body .= '<p><span class="tag ' . ($configDeleted ? 'tag-green' : 'tag-red') . '">wp-config.php</span> ' . ($configDeleted ? '削除済み' : '削除失敗（手動で削除してください）') . '</p>';
    }

    // ファイル結果
    if (!empty($fileResults['deleted_dirs'])) {
        $body .= '<p><span class="tag tag-green">DIR</span> 削除済みディレクトリ: ' . h(implode(', ', $fileResults['deleted_dirs'])) . '</p>';
    }
    if (!empty($fileResults['deleted_files'])) {
        $body .= '<p><span class="tag tag-green">FILE</span> 削除済みファイル: ' . count($fileResults['deleted_files']) . ' 件</p>';
    }

    // エラー
    if (!empty($fileResults['errors'])) {
        $body .= '<h2>削除できなかったファイル</h2><ul>';
        foreach ($fileResults['errors'] as $err) {
            $body .= '<li class="mono" style="color:#ff6b6b;">' . h($err) . '</li>';
        }
        $body .= '</ul><p>FTPで手動削除してください。</p>';
    }

    // 残存ファイル
    if (!empty($fileResults['skipped'])) {
        $body .= '<h2>WordPress以外の残存ファイル</h2><ul>';
        foreach ($fileResults['skipped'] as $s) {
            $body .= '<li class="mono">' . h($s) . '</li>';
        }
        $body .= '</ul>';
    }

    // スクリプト自身
    $body .= '<p style="margin-top:1rem;"><span class="tag ' . ($selfDeleted ? 'tag-green' : 'tag-red') . '">このスクリプト</span> ' . ($selfDeleted ? '削除済み' : '削除失敗（手動で削除してください）') . '</p>';

    $body .= '</div>';

    renderPage('WordPress Cleanup - 完了', $body);

    // セッション破棄
    session_destroy();
    exit;
}

// 不明なアクション
header('Location: ' . $_SERVER['SCRIPT_NAME']);
exit;
