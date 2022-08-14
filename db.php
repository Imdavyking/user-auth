<?php
$servername = "127.0.0.1";
$username = "root";
$password = "";
$dbname = "user";
$GLOBALS['playerRecordsTable'] = "userRecords";
$GLOBALS['server_url'] = "http://{$_SERVER['HTTP_HOST']}";
$GLOBALS['company_domain'] = "ecla.network";
$GLOBALS['email_sender'] = "info@ecla.network";
$GLOBALS['access_token_minutes'] = 10;
$GLOBALS['refresh_token_minutes'] = 60 * 24;// 1 day
$GLOBALS['jwt_secret'] = "d35cf52185ab27508b65151bce439342555e2141d68872a8250c09f81d5a8d7990f39d344b578fa901ac305ed32e1f32f4d930ee3f81158de72f9f9352f555c5";
$GLOBALS['refresh_secret'] = "6b7a00cadf94aa9ece7b1bf778d722b3a77787fb2ab631c85708ec20506a912d890628cd64f5c772a11d669ef04461ca41bf2f9994f50798c0d2313a0bd82601";

date_default_timezone_set("Africa/Lagos");
if (!defined('root')) define('root', $_SERVER['DOCUMENT_ROOT']);
if (!defined('debug')) define('debug', true);
if (!session_id()) session_start();
$_SESSION['nonce'] = sha1(random_bytes(64));
if (!isset($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = sha1(random_bytes(64));
header("X-CSRF-TOKEN: {$_SESSION['csrf_token']}");
header("Content-Security-Policy:default-src 'self';script-src 'self' 'nonce-{$_SESSION['nonce']}';form-action 'self';block-all-mixed-content;style-src 'self' 'nonce-{$_SESSION['nonce']}';");

try {
  $GLOBALS['conn'] = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
  $GLOBALS['conn']->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
  die( "Connection failed: " . $e->getMessage());
}