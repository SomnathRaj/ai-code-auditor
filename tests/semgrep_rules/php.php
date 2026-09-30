<?php
// Semgrep rule tests. Lines after a "rule id" annotation must match; lines after an "ok" annotation must not.

function sqli($conn, $pdo, $id, $name) {
    // ruleid: aca-php-sqli-string-built-query
    mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
    // ruleid: aca-php-sqli-string-built-query
    $pdo->query("SELECT * FROM users WHERE name = '$name'");
    // ruleid: aca-php-sqli-string-built-query
    DB::select("SELECT * FROM orders WHERE id = " . $id);
    $sql = "DELETE FROM users WHERE id = " . $id;
    // ruleid: aca-php-sqli-string-built-query
    $pdo->exec($sql);
    // ok: aca-php-sqli-string-built-query
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    // ok: aca-php-sqli-string-built-query
    DB::select("SELECT * FROM orders WHERE id = ?", [$id]);
}

function commands($host) {
    // ruleid: aca-php-command-injection
    exec("ping -c 1 " . $host);
    // ruleid: aca-php-command-injection
    shell_exec($host);
    // ok: aca-php-command-injection
    exec("ping -c 1 " . escapeshellarg($host));
    // ok: aca-php-command-injection
    system("uptime");
}

function code($expr) {
    // ruleid: aca-php-code-injection
    eval($expr);
    // ruleid: aca-php-code-injection
    $f = create_function('$a', $expr);
    // ok: aca-php-code-injection
    eval("return 1;");
}

function xss() {
    // ruleid: aca-php-reflected-xss
    echo "Hello " . $_GET['name'];
    // ok: aca-php-reflected-xss
    echo "Hello " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
}

function inclusion($page) {
    // ruleid: aca-php-file-inclusion
    include $_GET['page'] . ".php";
    // ruleid: aca-php-file-inclusion
    require_once $page;
    // ok: aca-php-file-inclusion
    require_once __DIR__ . "/config.php";
    // ok: aca-php-file-inclusion
    include "header.php";
    // ok: aca-php-file-inclusion
    require_once APP_ROOT . 'includes/page.inc.php';
    // ruleid: aca-php-file-inclusion
    require_once APP_ROOT . "pages/{$page}.php";
}

function traversal() {
    $file = $_GET['file'];
    // ruleid: aca-php-path-traversal
    readfile("/var/www/uploads/" . $file);
    // ok: aca-php-path-traversal
    readfile("/var/www/uploads/" . basename($_GET['file']));
}

function ssrf() {
    $ch = curl_init();
    // ruleid: aca-php-ssrf
    curl_setopt($ch, CURLOPT_URL, $_GET['url']);
    // ok: aca-php-ssrf
    curl_setopt($ch, CURLOPT_URL, "https://api.example.com/status");
    // ruleid: aca-php-tls-verification-disabled
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    // ok: aca-php-tls-verification-disabled
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
}

function deser($data) {
    // ruleid: aca-php-unsafe-deserialization
    $obj = unserialize($data);
    // ok: aca-php-unsafe-deserialization
    $safe = unserialize($data, ['allowed_classes' => false]);
}

function passwords($password, $name) {
    // ruleid: aca-php-weak-password-hash
    $h = md5($password);
    // ruleid: aca-php-weak-password-hash
    $h2 = sha1($user_pass);
    // ok: aca-php-weak-password-hash
    $h3 = password_hash($password, PASSWORD_DEFAULT);
    // ok: aca-php-weak-password-hash
    $etag = md5($name);
}

class User extends Model {
    // ruleid: aca-php-laravel-mass-assignment
    protected $guarded = [];
}

class Post extends Model {
    // ok: aca-php-laravel-mass-assignment
    protected $fillable = ['title', 'body'];
}

function logs($user, $password) {
    // ruleid: aca-php-sensitive-data-logged
    Log::info("login attempt", ['user' => $user, 'password' => $password]);
    // ok: aca-php-sensitive-data-logged
    Log::info("login attempt", ['user' => $user]);
    // ok: aca-php-sensitive-data-logged
    $stmt->bindParam(':password', $password, PDO::PARAM_STR);
    // ruleid: aca-php-sensitive-data-logged
    $this->logger->warning("reset", [$password]);
}

// ruleid: aca-php-hardcoded-credential
$db_password = "S3cr3t-Passw0rd!";
// ruleid: aca-php-hardcoded-credential
define("API_KEY", "sk_live_51Hx9kd8F3kslP0qZm");
// ok: aca-php-hardcoded-credential
$password = env('DB_PASSWORD');
// ok: aca-php-hardcoded-credential
$secret = "changeme";

// ruleid: aca-php-display-errors-enabled
ini_set('display_errors', 1);
// ok: aca-php-display-errors-enabled
ini_set('display_errors', 0);
