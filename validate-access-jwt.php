<?php
// validate jwt payload
require_once './db.php';
require_once './helpers.php';
header('Content-Type:application/json');
// must be get request
if($_SERVER['REQUEST_METHOD'] !== 'GET'){
    // 400 bad request
    http_response_code(400);
    die(json_encode([
        'success' => false,
        'msg' => 'request method must be get'
    ]));
}
$headers = array_change_key_case(apache_request_headers(),CASE_LOWER);
// get auth header from client in order to get the token
$bearerHeader = $headers['authorization'];

// check if header is empty
if(empty($bearerHeader)){
    // 400 bad request
    http_response_code(400);
    die (json_encode(['success' => false,'msg' => 'no bearer header']));
}
// remove bearer
$bearer = str_replace('Bearer ', '', $bearerHeader);
// check if token is empty
if(empty($bearer)){
    // 400 bad request
    http_response_code(400);
    die (json_encode(['success' => false,'msg' => 'no bearer token']));
}

$verifyJWTResponse = verifyJWT($bearer,$GLOBALS['jwt_secret']);

if(!$verifyJWTResponse['success']){
    // 401 unauthorized
    http_response_code(401);
    die(json_encode([
        'success' => false,
        'msg' => $verifyJWTResponse['msg']
    ]));
}


die(json_encode([
    'success' => $verifyJWTResponse['success'],
    'msg' => $verifyJWTResponse['msg']
]));

