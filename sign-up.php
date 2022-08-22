<?php
require_once "./db.php";
require_once "./helpers.php";
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

if(!isset($_POST['email']) || !filter_var($_POST['email'],FILTER_VALIDATE_EMAIL)
){
    // 400 bad request
    http_response_code(400);
    die(json_encode([
        'success' => false,
        'msg' => 'email not given or invalid'
    ]));
}
if(!isset($_POST['password'])){
    // 400 bad request
    http_response_code(400);
    die(json_encode([
        'success' => false,
        'msg' => 'password not given'
    ]));
}
if(!isset($_POST['username'])){
    // 400 bad request
    http_response_code(400);
    die(json_encode([
        'success' => false,
        'msg' => 'username not given'
    ]));
}

if(!isset($_FILES['image'])){
    // 400 bad request
    http_response_code(400);
    die(json_encode([
        'success' => false,
        'msg' => 'image not given'
    ]));
}


die(json_encode(createUserWithEmailAndPassword($_POST['email'],$_POST['username'],$_POST['password'])));



