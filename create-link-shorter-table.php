<?php
require_once "./db.php";

$stmt = $GLOBALS['conn']->prepare("CREATE TABLE IF NOT EXISTS linkshortener (
      id INT NOT NULL AUTO_INCREMENT,
      shortLink TEXT NOT NULL,
      actualLink TEXT NOT NULL,
      PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
$stmt->execute();

