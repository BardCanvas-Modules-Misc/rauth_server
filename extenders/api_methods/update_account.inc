<?php
/**
 * Update account API method.
 * Called by the document handler.
 * Payload: account record.
 *
 * @package    BardCanvas
 * @subpackage rauth_server
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 *
 * @var toolbox $toolbox
 * @var config  $config
 */

use hng2_base\account;
use hng2_base\config;
use hng2_modules\rauth_server\toolbox;

global $config, $modules, $database;

try
{
    $xaccount = $toolbox->get_incoming_account($wsdata);
}
catch( Exception $e )
{
    die(json_encode(array("message" => $e->getMessage())));
}

$origin_account = new account($xaccount->id_account);

if(
    $xaccount->email != $origin_account->email
    && $xaccount->level < config::MODERATOR_USER_LEVEL
) {
    $res = $database->query("
        select * from account
        where id_account <> '$xaccount->id_account'
        and (
            email     = '$xaccount->email' or
            alt_email = '$xaccount->email'
        )
    ");
    
    if( $database->num_rows($res) > 0 )
        die(json_encode(array(
            "message" => trim($modules["accounts"]->language->errors->registration->invalid->main_email_exists)
        )));
}

if(
    $xaccount->alt_email != "" && $xaccount->alt_email != $origin_account->alt_email
    && $xaccount->level < config::MODERATOR_USER_LEVEL
) {
    $query = "
        select * from account
        where id_account <> '$xaccount->id_account'
        and (
            email     = '$xaccount->alt_email' or 
            alt_email = '$xaccount->alt_email'
        )
    ";
    $res = $database->query($query);
    if( $database->num_rows($res) > 0 )
        die(json_encode(array(
            "message" => trim($modules["accounts"]->language->errors->registration->invalid->alt_email_exists)
        )));
}

$xaccount->_exists = true;
$xaccount->save();

die(json_encode(array("message" => "OK")));
