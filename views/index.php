<?php
require_once "./common-data.php";
// minify
ob_start('minifier');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style  nonce="<?= $_SESSION['nonce'] ?>">
        body{
            background-color: blue;
        }
    </style>
    <title>Document</title>
</head>
<body>
    <script nonce="<?= $_SESSION['nonce'] ?>">console.log('hello')</script>
</body>
</html>