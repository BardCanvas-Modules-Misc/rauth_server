<?php
/**
 * Create account API method.
 * Called by the document handler.
 * Payload: account record.
 *
 * @package    BardCanvas
 * @subpackage rauth_server
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 *
 * @var toolbox $toolbox
 */

use hng2_base\account;
use hng2_base\accounts_repository;
use hng2_modules\rauth_server\toolbox;

try
{
    $xaccount = $toolbox->get_incoming_account($wsdata);
}
catch( Exception $e )
{
    die(json_encode(array("message" => $e->getMessage())));
}
# die(json_encode(array("message" => print_r($xaccount, true))));

list($creation_ip, $creation_host) = explode("; ", $xaccount->creation_host);
$_SERVER['REMOTE_ADDR'] = $creation_ip;

$repository = new accounts_repository();

$alts   = empty($xaccount->alt_email) ? "" : " or email = '" . addslashes($xaccount->alt_email) . "' or alt_email = '" . addslashes($xaccount->alt_email) . "'";
$filter = array("(
    user_name    = '" . addslashes($xaccount->user_name)    . "' or 
    display_name = '" . addslashes($xaccount->display_name) . "' or
    email        = '" . addslashes($xaccount->email)        . "' or
    alt_email    = '" . addslashes($xaccount->email)        . "'
    $alts
)");
# die(json_encode(array("message" => print_r($filter, true))));

$rows = $repository->find($filter, 1, 0, "creation_date asc");
if( count($rows) > 0 )
{
    /** @var account $yaccount */
    $yaccount = current($rows);
    
    switch($yaccount->state)
    {
        case "new":
            $yaccount->send_new_account_confirmation_email();
            die(json_encode(array(
                "message" => replace_escaped_objects(
                    $current_module->language->messages->new_account_mail_sent,
                    array('{$email}' => $yaccount->email)
                )
            )));
            
        case "enabled":
            die(json_encode(array(
                "message" => trim($current_module->language->messages->new_account_exists)
            )));
            
        case "disabled":
            die(json_encode(array(
                "message" => trim($current_module->language->messages->new_account_disabled)
            )));
    }
}
else
{
    if( $settings->get("modules:accounts.register_enabled") != "true" ) die(json_encode(array(
        "message" => trim($current_module->language->messages->registration_disabled)
    )));
    
    try
    {
        $toolbox->validate_new_account($xaccount);
    }
    catch( Exception $e )
    {
        die(json_encode(array("message" => $e->getMessage())));
    }
    
    $xaccount->password   = md5($xaccount->_raw_password);
    $xaccount->id_account = make_unique_id(empty($wsdata["user_id_prefix"]) ? "10" : $wsdata["user_id_prefix"]);
    
    $xaccount->save();
    $xaccount->set_engine_pref("@rauth_server:post_confirmation_wsdata", $wsdata);
    
    $current_module = $modules["accounts"];
    $xaccount->send_new_account_confirmation_email();
    # die(json_encode(array("message" => print_r($xaccount, true))));
    
    $return = three_layer_encrypt(serialize($xaccount), $wsdata["encryption_key1"], $wsdata["encryption_key2"], $wsdata["encryption_key3"]);
    die(json_encode(array("message" => "OK", "data" => $return)));
}
