<?php
/**
 * Send Confirmation Email API Method.
 * Called by the document handler.
 * Payload: [id_account:int, ip:string]
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

if( empty($data->id_account) )
    die(json_encode(array("message" => sprintf(
        $current_module->language->messages->missing_account_id,
        $wsdata["title"]
    ))));

if( ! is_numeric($data->id_account) )
    die(json_encode(array("message" => sprintf(
        $current_module->language->messages->invalid_account_id,
        $wsdata["title"]
    ))));

if( ! empty($data->ip) ) $_SERVER["REMOTE_ADDR"] = $data->ip;

$xaccount = new account($data->id_account);
if( ! $xaccount->_exists )
    die(json_encode(array("message" => trim($current_module->language->messages->account_not_found))));

$xaccount->set_engine_pref("@rauth_server:post_confirmation_wsdata", $wsdata);

$current_module = $modules["accounts"];
$xaccount->send_new_account_confirmation_email();

die(json_encode(array("message" => "OK")));
