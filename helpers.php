<?php
date_default_timezone_set("Africa/Lagos");
require_once $_SERVER['DOCUMENT_ROOT']."/ecla/user-auth/db.php";
error_reporting(0);  // hide notices
function requestIsHttps(){
    return isset($_SERVER['HTTPS']) &&
     ($_SERVER['HTTPS'] == 'on' || $_SERVER['HTTPS'] == 1) ||
     isset($_SERVER['HTTP_X_FORWARDED_PROTO']) &&
     $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https';
}

   
$requestScheme = requestIsHttps() ? 'https': 'http';
$GLOBALS['server_url'] = "{$requestScheme}://{$_SERVER['HTTP_HOST']}";

function checkIfEmailExists($email){
    $stmt = $GLOBALS['conn']->prepare("SELECT * FROM {$GLOBALS['playerRecordsTable']} WHERE email = ? LIMIT 1");
    $stmt->execute([$email]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    return $result;
}

function checkIfUsernameExists($username){
    $stmt = $GLOBALS['conn']->prepare("SELECT * FROM {$GLOBALS['playerRecordsTable']} WHERE username = ? LIMIT 1");
    $stmt->execute([$username]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    return $result;
}

function checkIfVerified($email){
    $stmt = $GLOBALS['conn']->prepare("SELECT * FROM {$GLOBALS['playerRecordsTable']} WHERE email = ? AND verified = 1 LIMIT 1");
    $stmt->execute([$email]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    return $result;
}

function getRandomCode(){
    // bin2hex(random_bytes(4)) former hex code
    $digits = 4;
    return str_pad(rand(0, pow(10, $digits)-1), $digits, '0', STR_PAD_LEFT);
}



function compressImage($source, $destination, $quality = 80) {
    try {
        $info = getimagesize($source);

        if ($info['mime'] == 'image/jpeg') 
            $image = imagecreatefromjpeg($source);
    
        elseif ($info['mime'] == 'image/gif') 
            $image = imagecreatefromgif($source);
    
        elseif ($info['mime'] == 'image/png') 
            $image = imagecreatefrompng($source);
            
        $exif = exif_read_data($source);
        if ($exif['Orientation']==3 OR $exif['Orientation']==6 OR $exif['Orientation']==8) {
            switch ($exif['Orientation']) { 
                case 3:
                $image = imagerotate($image, 180, 0);
                break;
                case 6:
                $image = imagerotate($image, -90, 0);
                break;
                case 8:
                $image = imagerotate($image, 90, 0);
                break;
            }
        }
    
        return imagejpeg($image, $destination, $quality);
    } catch (\Throwable $th) {
        return false;
    }
}


function createUserWithEmailAndPassword($email,$username,$password) {
    // get image from $_Files
    $image = $_FILES['image'];
    // compress image and get size
    $imageName = $image['name'];


    $imageTmpName = $image['tmp_name'];
    $imageSize = $image['size'];
    $imageError = $image['error'];
    $imageType = $image['type'];
    $imageExt = explode('.',$imageName);
    $imageActualExt = strtolower(end($imageExt));
    $allowed = array('jpg','jpeg','png');
    $emailExists = checkIfEmailExists($email);
    $usernameExists = checkIfUsernameExists($username);
    if($emailExists){
        return [
            'success' => false,
            'msg' => 'email already exists'
        ];
    }else if($usernameExists){
        return [
            'success' => false,
            'msg' => 'username already exists'
        ];
    }

   
    if(in_array($imageActualExt,$allowed)){
        if($imageError === 0){
           
                $imageNameNew = uniqid('',true).".".$imageActualExt;
                $imageDestination = __DIR__.'/images/'.$imageNameNew;
                // check dir or creater
                if(!file_exists('./images')){
                    $oldmask = umask(0);
                    // read and write everybody to allow user to upload images
                    mkdir('./images',0777);
                    umask($oldmask);
                }
                // compress image and get size
                if(!compressImage($imageTmpName,$imageDestination)) {
                    return [
                        'success' => false,
                        'msg' => 'error compressing image'
                    ];
                }
                // password should be at least 4 characters long
                if(strlen($password) < 4){
                    return [
                        'success' => false,
                        'msg' => 'password should be at least 4 characters long'
                    ];
                }
                $stmt = $GLOBALS['conn']->prepare("INSERT INTO {$GLOBALS['playerRecordsTable']} (email,username,password,image) VALUES (?,?,?,?)");
                $stmt->execute([$email, $username,password_hash($password,PASSWORD_BCRYPT),$imageNameNew]);
                if(sendEmailVerification($email)['success']){
                    return [
                        'success' => true,
                        'msg' => 'user created, check your email to verify'
                    ];
                }
                return [
                    'success' => true,
                    'msg' => 'user created'
                ];
        }else {
            return [
                'success' => false,
                'msg' => 'image error'
            ];
        }
    }else {
        return [
            'success' => false,
            'msg' => 'image type not allowed'
        ];
    }
}

function loginUserWithEmailAndPassword($email,$password){
    // issue jwt if password is correct
    
  

    $user = checkIfEmailExists($email);
    $verified = checkIfVerified($email);

    
 
    if($user){
        if(password_verify($password,$user['password'])){
            unset($user['password']);
            unset($user['verify-code']);
            unset($user['verifyCodeExpiryDate']);
            unset($user['passwordResetCode']);
            unset($user['passwordResetCodeTimestamp']);
            if($verified){
                return [
                    'success' => true,
                    'msg' =>[
                        'access_token'=> 
                        createJWT($user,$GLOBALS['access_token_minutes'] ,$GLOBALS['jwt_secret']),
    
                        'refresh_token'=> createJWT($user,$GLOBALS['refresh_token_minutes'],$GLOBALS['refresh_secret'])
                    ]
                ];
            }

            if(!$verified && sendEmailVerification($email)['success']){
                return [
                    'success' => false,
                    'msg' => 'check your email to verify'
                ];
            }

            return [
                'success' => false,
                'msg' => 'email not verified and we could not resend verification email',
            ];
           
        }else {
            return [
                'success' => false,
                'msg' => 'wrong password'
            ];
        }
    }else {
        return [
            'success' => false,
            'msg' => 'user not found'
        ];
    }
}

function sendForgetPasswordEmailWithRandomCode($email){

    $randomCode = getRandomCode();
    $result = checkIfEmailExists($email);
    if(!$result){
        return ['success' => false,'msg' => 'email given is invalid'];
    }
    $email = $result['email'];
    $subject = "Password Reset";
    $tenMinutesFromNow = date('Y-m-d H:i:s',strtotime('+10 minutes'));

    $message = "Your Password Reset Code is $randomCode<br><b>This code will expire in 10 minutes</b>";
    $headers  = "From: {$GLOBALS['company_domain']}\r\n"; // sender.co
    $headers .= "Reply-To: {$GLOBALS['email_sender']}\r\n"; // info@sender.co
    $headers .= "CC: {$GLOBALS['email_sender']}\r\n"; // info@sender.co
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";

    if(mail($email,$subject,$message,$headers)){
        // save code to database
        $stmt = $GLOBALS['conn']->prepare("UPDATE {$GLOBALS['playerRecordsTable']} SET passwordResetCode = ?, passwordResetCodeTimestamp = ? WHERE email = ?");
        $stmt->execute([$randomCode,$tenMinutesFromNow,$email]);
        return ['success' => true,'msg' => 'email sent'];
    }
    return ['success' => false,'msg' => 'email not sent'];

}


function resetPassword($email,$newPassword,$code){
    $result = checkIfEmailExists($email);
    if(!$result){
        return ['success' => false,'msg' => 'email does not exist'];
    }
    if($result['passwordResetCode'] != $code){
        return ['success' => false,'msg' => 'code is incorrect'];
    }
        
        // check if code is expired
    $expiryDate = $result['passwordResetCodeTimestamp'];
    $expiryDate = date('Y-m-d H:i:s',strtotime($expiryDate));
    $currentDate = date('Y-m-d H:i:s');
    if($currentDate > $expiryDate){
        // delete code from database
        $stmt = $GLOBALS['conn']->prepare("UPDATE {$GLOBALS['playerRecordsTable']} SET passwordResetCode = NULL, passwordResetCodeTimestamp = now() WHERE email = ?");
        $stmt->execute([$email]);
        return ['success' => false,'msg' => 'code has expired'];
    }
    // password should be at least 4 characters long
    if(strlen($newPassword) < 4){
        return ['success' => false,'msg' => 'password should be at least 4 characters long'];
    }
    // remove code from database and update password
    $stmt = $GLOBALS['conn']->prepare("UPDATE {$GLOBALS['playerRecordsTable']} SET passwordResetCode = NULL, passwordResetCodeTimestamp = now(), password = ? WHERE email = ?");
    $stmt->execute([password_hash($newPassword,PASSWORD_BCRYPT),$email]);
    return ['success' => true,'msg' => 'password reset'];
};




function sendEmailVerification($email){

    // check if email exist
    $result = checkIfEmailExists($email);
    if(!$result){
        return ['success' => false,'msg' => 'email does not exist'];
    }
    // check if already verified
    $stmt = $GLOBALS['conn']->prepare("SELECT * FROM {$GLOBALS['playerRecordsTable']} WHERE email = ?");
    $stmt->execute([$email]);
    $result = $stmt->fetch();
    if($result['verified'] == 1){
        return ['success' => false,'msg' => 'email already verified'];
    }
    
    $tenMinutesFromNow = date('Y-m-d H:i:s',strtotime('+10 minutes'));
    $verifyCode = getRandomCode();
    $stmt = $GLOBALS['conn']->prepare("UPDATE {$GLOBALS['playerRecordsTable']} SET `verify-code` = ?, `verifyCodeExpiryDate` = ? WHERE email = ?");
   
    $stmt->execute([$verifyCode,$tenMinutesFromNow,$email]);
    
    $subject = 'Email Verification';
    $message = "<p>Your verification code is <b>{$verifyCode}</b><br />Please click the link below to verify your email address, the code will expire in ten minutes.</p>";
    $message .= '<a href="'.$GLOBALS['server_url'].'/ecla/user-auth/verify-email.php?verify_code='.$verifyCode.'">Verify Email</a>';
    $headers  = "From: {$GLOBALS['company_domain']}\r\n"; // sender.co
    $headers .= "Reply-To: {$GLOBALS['email_sender']}\r\n"; // info@sender.co
    $headers .= "CC: {$GLOBALS['email_sender']}\r\n"; // info@sender.co
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
    if(mail($email,$subject,$message,$headers)){
        return ['success' => true,'msg' => 'email sent'];
    }
    return ['success' => false,'msg' => 'email not sent'];

}

function verify_email($verify_code){
    $stmt = $GLOBALS['conn']->prepare("SELECT * FROM {$GLOBALS['playerRecordsTable']} WHERE `verify-code` = ?");
    $stmt->execute([$verify_code]);
    $result = $stmt->fetch();

    if(!$result){
        return ['success' => false,'msg' => 'code is incorrect or expired'];
    }

    // check if already verified
    if($result['verified'] == 1){
        return ['success' => false,'msg' => 'email already verified'];
    }
    // check if verify code is expired
    if(strtotime($result['verifyCodeExpiryDate']) < strtotime(date('Y-m-d H:i:s'))){
        $stmt = $GLOBALS['conn']->prepare("UPDATE {$GLOBALS['playerRecordsTable']} SET `verify-code` = NULL, `verifyCodeExpiryDate` = now() WHERE email = ?");
        $stmt->execute([$result['email']]);
        return ['success' => false,'msg' => 'verify code expired'];
    }
    $stmt = $GLOBALS['conn']->prepare("UPDATE {$GLOBALS['playerRecordsTable']} SET verified = 1,`verify-code` = NULL, `verifyCodeExpiryDate` = now() WHERE `verify-code` = ?");
    $stmt->execute([$verify_code]);

    return [
        'success' => true,
        'msg' => 'email verified'
    ];
}


function urlsafeB64Decode(string $input)
{
    $remainder = \strlen($input) % 4;
    if ($remainder) {
        $padlen = 4 - $remainder;
        $input .= \str_repeat('=', $padlen);
    }
    return \base64_decode(\strtr($input, '-_', '+/'));
}

    
function urlsafeB64Encode(string $input)
{
    return \str_replace('=', '', \strtr(\base64_encode($input), '+/', '-_'));
}


function createJWT($json_payload,$minutes_to_expire,$secret_key){
 
    $json_payload['iat'] = time();
    $json_payload['exp'] = time() + ($minutes_to_expire * 60); 
    $json_payload['iss'] = $GLOBALS['server_url'];
    // base64 encode the payload
    
    $base64_json_payload = urlsafeB64Encode(json_encode($json_payload, JSON_UNESCAPED_SLASHES));
    // headers
    $headers = [
        'alg' => 'HS256',
        'typ' => 'JWT'
    ];
    // convert headers to base64
    $base64_headers = urlsafeB64Encode(json_encode($headers, JSON_UNESCAPED_SLASHES));
    // create the signature
    $signature = urlsafeB64Encode(hash_hmac('sha256', $base64_headers.'.'.$base64_json_payload, $secret_key,true));
    // return the jwt
    return $base64_headers.'.'.$base64_json_payload.'.'.$signature;
}

function verifyJWT($jwt_payload,$secret_key){
   
    // get the payload
    $payload = explode('.',$jwt_payload);
    // check number of .
    if(count($payload) != 3){
        return ['success' => false,'msg' => 'invalid jwt'];
    }
    $base64_headers = $payload[0];
    // get the headers with unescape slashes
    $headers = json_decode(urlsafeB64Decode($base64_headers));
 
    // get the signature
    $signature = $payload[2];
    // get the payload
    $base64_json_payload = $payload[1];

    // check signature alg
    if($headers->alg != 'HS256' || $headers->typ != 'JWT'){
        return ['success' => false,'msg' => 'invalid algorithm or type'];
    }
    // json decode payload
    $json_decoded_payload = json_decode(urlsafeB64Decode($base64_json_payload));
   


    // check expiry date
    if(!isset($json_decoded_payload->exp)){
        return ['success' => false,'msg' => 'expiry time not set'];
    }


    // check if exp timestamp in milliseconds is expired

    if($json_decoded_payload->exp < time()){
        return ['success' => false,'msg' => 'jwt expired'];
    }

    // check if the signature is valid
    if(urlsafeB64Encode(hash_hmac('sha256', $base64_headers.'.'.$base64_json_payload, $secret_key,true)) == $signature){
        // return the payload
        return 
        [
            'success' => true,
            'msg' => 'jwt verified',
        ];
        
    }
    return [
        'success' => false,
        'msg' => 'jwt not verified'
    ];
    
}

function decodeJWTpayload($jwt_payload){
    $payload = explode('.',$jwt_payload);
    $base64_json_payload = $payload[1];
    return json_decode(urlsafeB64Decode($base64_json_payload),true);
}

function random_str($length = 24, $numbers_only = false, $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
{
  if ($numbers_only) $keyspace = '0123456789';
  if ($length < 1) throw new \RangeException("Length must be a positive integer");
  $pieces = [];
  $max = mb_strlen($keyspace, '8bit') - 1;
  for ($i = 0; $i < $length; ++$i) $pieces[] = $keyspace[random_int(0, $max)];
  return implode('', $pieces);
}

function getActualLink( $shortLink ) {
    $stmt = $GLOBALS['conn']->prepare('SELECT actualLink FROM linkshortener WHERE BINARY shortLink = ? LIMIT 1');
    $stmt->execute([trim($shortLink)]);
    $fetchResult = $stmt->fetch(PDO::FETCH_ASSOC);

    if(!$fetchResult){
        return ['success' => false,'msg' => 'link not found'];
    }
    $actualLink = $fetchResult['actualLink'];
    if ($stmt->rowCount() === 0) {
      http_response_code(404);
      return [
        'success' => false,
        'msg' => 'Invalid link'
      ];
    }
    else return[
      'success' => true,
      'msg' => $actualLink
    ];
  }
  

  