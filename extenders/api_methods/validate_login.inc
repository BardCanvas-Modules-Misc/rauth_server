<?php
/**
 * Validate Email API Method.
 * Called by the document handler.
 * Payload: [user_name:string, password_hash:string]
 * Response in format compatible with the JS login script.
 *
 * @package    BardCanvas
 * @subpackage rauth_server
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 * 
 * @var toolbox $toolbox
 */

use hng2_base\account;
use hng2_modules\rauth_server\toolbox;

try
{
    $data = $toolbox->get_incoming_data($wsdata);
}
catch(\Exception $e)
{
    die(json_encode(array("message" => $e->getMessage())));
}

if( empty($data["user_name"]) )
    die(json_encode(array("message" => trim($current_module->language->messages->validating_missing_params))));

$xaccount = new account($data["user_name"]);

if( ! $xaccount->_exists )
    die(json_encode(array("message" => trim($current_module->language->messages->validating_account_not_found))));

if( $settings->get("engine.enabled") != "true" && ! $account->_is_admin )
    die(json_encode(array("message" => trim($current_module->language->messages->validating_engine_disabled))));

if( $xaccount->state != "enabled" )
    die(json_encode(array("message" => trim($current_module->language->messages->validating_account_disabled))));

if( $xaccount->password != $data["password_hash"])
    die(json_encode(array("message" => trim($current_module->language->messages->validating_wrong_passowd))));

die(json_encode(array("message" => "OK")));
