<?php
/**
 * Account confirmation extender: after confirmation, broadcast change to origin creator
 * 
 * @package    BardCanvas
 * @subpackage rauth_server
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 * 
 * @var account $xaccount
 */

use hng2_base\account;
use hng2_modules\rauth_server\client;

global $xaccount, $errors;

$wsdata = $xaccount->get_engine_pref("@rauth_server:post_confirmation_wsdata");
# echo "wsdata - " . nl2br(print_r($wsdata, true));

if( empty($wsdata) ) return;

$client = new client($wsdata);
# echo "client := " . nl2br(print_r($client, true));

if( ! $client->enabled ) return;

try
{
    $client->activate_account($xaccount->id_account);
}
catch(\Exception $e)
{
    $errors[] = sprintf(
        $this_module->language->messages->cannot_confirm_account,
        $xaccount->id_account,
        $xaccount->user_name,
        $wsdata["title"],
        $e->getMessage()
    );
}
