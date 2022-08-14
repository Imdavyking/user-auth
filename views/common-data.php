<?php
require_once "../db.php";
date_default_timezone_set('Africa/lagos');
function minifier($buffer)
{
  $search = [
    '/\>[^\S ]+/s',
    '/[^\S ]+\</s',
    '/(\s)+/s',
    '/<!--(.|\s)*?-->/'
  ];

  $replace = [
    '>',
    '<',
    '\\1',
    ''
  ];
  $blocks = preg_split('/(<\/?pre[^>]*>)/', $buffer, 0, PREG_SPLIT_DELIM_CAPTURE);

  $buffer = '';

  foreach ($blocks as $i => $block) ($i % 4 === 2) ? ($buffer .= $block) : ($buffer .= preg_replace($search, $replace, $block));
  return $buffer;
}