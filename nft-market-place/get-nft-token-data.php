<?php
require_once "../nft-market-place-db.php";
header('Content-Type:application/json');
header('Access-Control-Allow-Origin: *');
// must be get request
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    die(json_encode([
        'success' => false,
        'msg' => 'request method must be get'
    ]));
}

if(!isset($_GET['token_id']) || !filter_var($_GET['token_id'],FILTER_VALIDATE_INT)){
    // 400 bad request
    http_response_code(400);
    die(json_encode([
        'success' => false,
        'msg' => 'token_id not given or invalid'
    ]));
}

die(json_encode([
    'image' => '',
    'name' => "{$_GET['token_id']} name",
    'description' => "{$_GET['token_id']} description",
]));