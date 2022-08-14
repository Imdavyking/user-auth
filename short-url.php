<?php
require_once "./db.php";
require_once "./helpers.php";
header('Content-Type:application/json');
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
  http_response_code(405);
  die(json_encode([
    'success' => false,
    'msg' => 'access this page with method get'
  ]));
}

$shortLinkRewriteFromHtacess = "{$_SERVER['SERVER_NAME']}/r/";

if (isset($_GET['url']) && filter_var($_GET['url'], FILTER_VALIDATE_URL)) {
  $stmt = $GLOBALS['conn']->prepare('SELECT shortLink FROM linkshortener WHERE actualLink = ? LIMIT 1');
  $stmt->execute([trim($_GET['url'])]);
  if ($stmt->rowCount() === 0) {
    $unique = random_str(8);
    $stmt = $GLOBALS['conn']->prepare('INSERT INTO linkshortener(actualLink,shortLink) VALUES (?,?)');
    $stmt->execute([$_GET['url'], $unique]);
    die(json_encode([
      'msg' => "https://{$shortLinkRewriteFromHtacess}{$unique}",
      'success' => true
    ]));
  } else {
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    die(json_encode([
      'msg' => "https://{$shortLinkRewriteFromHtacess}{$result['shortLink']}",
      'success' => true
    ]));
  }
} else {
  http_response_code(400);
  die(json_encode([
    'msg' => "Invalid url or url not provided",
    'success' => false
  ]));
}

