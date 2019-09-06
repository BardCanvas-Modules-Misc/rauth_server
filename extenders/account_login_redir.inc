<?php
/**
 * Account login extender: after successful login, before final output
 * Overrides login extender with 
 *
 * @package    BardCanvas
 * @subpackage rauth_server
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 *
 * @var account $user_account
 */

use hng2_base\account;
use hng2_modules\rauth_server\toolbox;

global $goto, $account;

if( empty($_REQUEST["wsh"]) ) return;

try
{
    $toolbox = new toolbox();
    $wsdata  = $toolbox->init_website($_REQUEST["wsh"], false);
}
catch(\Exception $e)
{
    die( $e->getMessage() );
}

$exp   = time() + (60 * 5);
$key1  = $wsdata["encryption_key1"];
$key2  = $wsdata["encryption_key2"];
$key3  = $wsdata["encryption_key3"];

$value = "{$account->id_account},{$exp}";
$token = urlencode(three_layer_encrypt($value, $key1, $key2, $key3));
$uhash = urlencode(three_layer_encrypt($account->user_name, $key1, $key2, $key3));
$phash = urlencode(three_layer_encrypt($account->password, $key1, $key2, $key3));

$goto = sprintf(
    "%s/rauth_client/scripts/login.php?token=%s&uhash=%s&phash=%s&redirect_to=%s",
    rtrim($wsdata["url"], "/"),
    $token,
    $uhash,
    $phash,
    urlencode($goto)
);
