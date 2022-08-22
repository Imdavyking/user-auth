<?php
require_once "./db.php";
require_once "./helpers.php";
// must be get request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // 400 bad request
    http_response_code(400);
    die(json_encode([
        'success' => false,
        'msg' => 'request method must be post'
    ]));
}

if(!isset($_GET['verify_code']) ){
    http_response_code(400);
    die(json_encode([
        'msg' => 'verification code not given',
        'success' => false,
    ]));
}

if(!isset($_GET['email']) ){
    http_response_code(400);
    die(json_encode([
        'success' => false,
        'msg' => 'email not given'
    ]));
}

die(json_encode(verify_email($_POST['verify_code'],$_POST['verify_code'])));

?>