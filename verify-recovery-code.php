<?php
require_once "./db.php";
require_once "./helpers.php";
header('content-type: application/json');

// must be post request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    die(json_encode([
        'success' => false,
        'msg' => 'request method must be post'
    ]));
}
// delete forgot password greater than 5 minutues in player records table
$stmt = $GLOBALS['conn']->prepare("DELETE FROM {$GLOBALS['playerRecordsTable']} WHERE passwordResetCode != '' AND TIMESTAMPDIFF(MINUTE,passwordResetCodeTimestamp,NOW()) > 5");
$stmt->execute();

if(!isset($_POST['email']) || !filter_var($_POST['email'],FILTER_VALIDATE_EMAIL)){
    // 400 bad request
    http_response_code(400);
    die(json_encode([
        'success' => false,
        'msg' => 'email not given or invalid'
    ]));
}
if(!isset($_POST['new-password'])){
    // 400 bad request
    http_response_code(400);
    die(json_encode([
        'success' => false,
        'msg' => 'new password not given'
    ]));
}

if(!isset($_POST['code'])){
    // 400 bad request
    http_response_code(400);
    die(json_encode([
        'success' => false,
        'msg' => 'code not given'
    ]));
}

// call forgot password
$result = resetPassword($_POST['email'],$_POST['new-password'],$_POST['code']);

if($result['success']){
    die (json_encode(['success' => true,'msg' => 'password reset']));
}else{
    
    die( json_encode(['success' => false,'msg' => $result['msg']]));
}


