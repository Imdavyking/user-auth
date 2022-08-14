<?php
if (!session_id()) session_start();
if (!defined('root')) define('root', $_SERVER['DOCUMENT_ROOT']);
$constantVar = function ($name) {
  return constant($name);
};
require_once "../db.php";
require_once "../helpers.php";
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
  http_response_code(405);
  die(json_encode([
    'success' => false,
    'msg' => 'access this page with method get'
  ]));
}
if (!isset($_GET['r'])) {
  die('Please an redirection url needed');
}
$redirectUrl = $_GET['r'];


$actualLink = getActualLink($_GET['r']);
if ($actualLink['success']){
  if($_SERVER['REQUEST_URI'][strlen($_SERVER['REQUEST_URI']) - 1] === '+'){
    die($actualLink['msg']);
  }else {
    header('Location: ' . $actualLink['msg']);
  }
}else {
  http_response_code(404);
  die($actualLink['msg']);
}