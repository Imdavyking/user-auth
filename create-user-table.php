
<?php
require_once "./db.php";

$stmt = $GLOBALS['conn']->prepare("CREATE TABLE IF NOT EXISTS {$GLOBALS['playerRecordsTable']} (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` text NOT NULL,
  `email` text NOT NULL,
  `password` text NOT NULL,
  `image` text NOT NULL,
  `verify-code` text,
  `verified` int(1) NOT NULL DEFAULT '0',
  `verifyCodeExpiryDate` timestamp,
  `passwordResetCode` text,
  `passwordResetCodeTimestamp` timestamp,
  `date` timestamp NOT NULL DEFAULT current_timestamp(),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
$stmt->execute();

