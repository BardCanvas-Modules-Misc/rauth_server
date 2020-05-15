<?php
/**
 * Map Client Account API method.
 * Called by the document handler.
 * Payload: account record.
 * 
 * @package    BardCanvas
 * @subpackage rauth_server
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 * 
 * @var toolbox $toolbox
 * @var array   $wsdata
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

$xaccount->user_name    = "{$wsdata["handle"]}.{$xaccount->user_name}";
$xaccount->display_name = "{$wsdata["title"]} {$xaccount->display_name}";

$filter = array("(
    user_name    = '" . addslashes($xaccount->user_name)    . "' or 
    display_name = '" . addslashes($xaccount->display_name) . "'
)");
# die(json_encode(array("message" => print_r($filter, true))));

$rows = $repository->find($filter, 1, 0, "creation_date asc");
if( count($rows) > 0 )
{
    /** @var account $yaccount */
    $yaccount = current($rows);
    
    if( $yaccount->state == "new" )
    {
        die(json_encode(array(
            "message" => $current_module->language->messages->account_already_in_creation
        )));
    }
    
    if( $yaccount->state == "disabled" )
    {
        die(json_encode(array(
            "message" => $current_module->language->messages->account_exists_and_disabled
        )));
    }
    
    $return = three_layer_encrypt(serialize($xaccount), $wsdata["encryption_key1"], $wsdata["encryption_key2"], $wsdata["encryption_key3"]);
    die(json_encode(array("message" => "OK", "data" => $return)));
}
else
{
    $xaccount->id_account = make_unique_id(empty($wsdata["user_id_prefix"]) ? "10" : $wsdata["user_id_prefix"]);
    $xaccount->_exists    = false;
    $xaccount->save();
    
    if( ! empty($xaccount->engine_prefs) )
    {
        $prefs = $xaccount->engine_prefs;
        foreach($prefs as $key => $val) $xaccount->set_engine_pref($key, $val);
    }
    
    $return = three_layer_encrypt(serialize($xaccount), $wsdata["encryption_key1"], $wsdata["encryption_key2"], $wsdata["encryption_key3"]);
    die(json_encode(array("message" => "OK", "data" => $return)));
}
