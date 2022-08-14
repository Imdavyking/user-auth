<?php
require_once "./db.php";
require_once "./helpers.php";
// must be get request
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    // 400 bad request
    http_response_code(400);
    die("
        <!DOCTYPE html>
        <html lang='en'>
        <head>
            <meta charset='UTF-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
            <meta http-equiv='X-UA-Compatible' content='ie=edge'>
            <style  nonce='{$_SESSION['nonce']}'>
                body{
                    text-align: center;
                    font-family: sans-serif;
                }
                
            </style>
            <title>400 - Bad Request</title>
        </head>
        <body>
            <h1>400 - Bad Request</h1>
            <p>Request method must be get</p>
        </body>
        </html>
    ");
}

if(!isset($_GET['verify_code']) ){
    // 400 bad request
    http_response_code(400);
    die("
        <!DOCTYPE html>
        <html lang='en'>
        <head>
            <meta charset='UTF-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
            <meta http-equiv='X-UA-Compatible' content='ie=edge'>
            <style nonce='{$_SESSION['nonce']}'>
                body{
                    text-align: center;
                    font-family: sans-serif;
                }
                
            </style>
            <title>400 - Bad Request</title>
        </head>
        <body>
            <h1>400 - Bad Request</h1>
            <p>verify_code not given</p>
        </body>
        </html>
    ");
}

$verify_email_result = verify_email($_GET['verify_code']);

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <style   nonce="<?= $_SESSION['nonce'] ?>">
        body{
            text-align: center;
            font-family: sans-serif;
        }
        
    </style>

    <title>Verify Email</title>
</head>
<body>
    <?php if($verify_email_result['success']): ?>
        <h1>Email verified</h1>
        <p>You can now login.</p>
    <?php else: ?>
        <h1>Email not verified, <?= $verify_email_result['msg'] ?></h1>
        <p>Please try again.</p>
    <?php endif; ?>
</body>
</html>