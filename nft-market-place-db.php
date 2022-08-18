<?php
$servername = "127.0.0.1";
$username = "root";
$password = "";
$dbname = "nft-marketplace";
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