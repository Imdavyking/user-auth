<?php
require_once "../nft-market-place-db.php";

header('content-type: application/json');
header('Access-Control-Allow-Origin: *');

$page = 1;
// get all listing form itemListed table 10 per page pdo
$stmt = $GLOBALS['conn']->prepare("SELECT * FROM itemListed ORDER BY id DESC LIMIT 10 OFFSET " . ($page - 1) * 10);
$stmt->execute();

$result = $stmt->fetchAll();
// send json response
die(json_encode($result));
?>


