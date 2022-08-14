<?php
require_once "./db.php";
require_once "./helpers.php";
header('Content-Type:application/json');
// check if request method is post
if($_SERVER['REQUEST_METHOD'] !== 'POST'){
    // 400 bad request
    http_response_code(400);
    die(json_encode([
        'success' => false,
        'msg' => 'request method must be post'
    ]));
}


if(!isset($_POST['refresh_token'])){
    // 400 bad request
    http_response_code(400);
    die(json_encode([
        'success' => false,
        'msg' => 'refresh token not given'
    ]));
}

// validate refresh token 
$refresh_token_result = verifyJWT($_POST['refresh_token'],$GLOBALS['refresh_secret']);

if(!$refresh_token_result['success']){
    // 401 unauthorized
    http_response_code(401);
    die(json_encode([
        'success' => false,
        'msg' => $refresh_token_result['msg']
    ]));
}

// decode refresh token
$json_payload = decodeJWTpayload($_POST['refresh_token']);

// make new access token
$access_token = createJWT($json_payload,$GLOBALS['access_token_minutes'],$GLOBALS['jwt_secret']);

die(json_encode([
    'success' => true,
    'msg' => [
        'access_token' => $access_token,
        'refresh_token' => $_POST['refresh_token']
    ]
]));