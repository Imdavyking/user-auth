<?php
require_once './db.php';
require_once './helpers.php';
header('Content-Type:application/json');
// must be post request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // 400 bad request
    http_response_code(400);
    die(json_encode([
        'success' => false,
        'msg' => 'request method must be post'
    ]));
}

if(!isset($_POST['email']) || !filter_var($_POST['email'],FILTER_VALIDATE_EMAIL)){
    // 400 bad request
    http_response_code(400);
    die(json_encode([
        'success' => false,
        'msg' => 'email not given or invalid'
    ]));
}

$sendEmailVerificationResult = sendEmailVerification($_POST['email']);

die(json_encode([
    'success' => $sendEmailVerificationResult['success'],
    'msg' => $sendEmailVerificationResult['msg'],
    'expiration' => $GLOBALS['email_code_minutes']
]));

