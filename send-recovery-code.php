<?php
require_once "./db.php";
require_once "./helpers.php";
header('content-type: application/json');
// must be post request
if($_SERVER['REQUEST_METHOD'] !== 'POST'){
    // 400 bad request
    http_response_code(400);
    die(json_encode([
        'success' => false,
        'msg' => 'request method must be post'
    ]));
}
// call send mail forget password
$result = sendForgetPasswordEmailWithRandomCode($_POST['email']);

if($result['success']){
    die (json_encode(['success' => true,'msg' => 'email sent']));
}else{
    die (json_encode(['success' => false,'msg' => $result['msg']]));
}
