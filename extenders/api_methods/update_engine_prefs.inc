<?php
/**
 * Update account prefs API method.
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
use hng2_modules\rauth_server\client;
use hng2_modules\rauth_server\toolbox;

global $config, $modules, $database;

try
{
    $data = $toolbox->get_incoming_data($wsdata);
}
catch( Exception $e )
{
    die(json_encode(array("message" => $e->getMessage())));
}

if( ! is_numeric($data->id_account) )
    die(json_encode(array("message" => trim($current_module->language->messages->invalid_account_id))));

if( ! is_array($data->prefs) )
    die(json_encode(array("message" => sprintf($current_module->language->messages->invalid_prefs, $wsdata["title"]))));

$xaccount = new account($data->id_account);
if( ! $xaccount->_exists )
    die(json_encode(array("message" => trim($current_module->language->messages->account_not_found))));

$existing_prefs = $xaccount->engine_prefs;
foreach($existing_prefs as $key => $val)
{
    $val = empty($data->prefs[$key]) ? "" : $data->prefs[$key];
    $xaccount->set_engine_pref($key, $val);
}

#
# Broadcasting
#

$now   = date("Y-m-d H:i:s");
$ldate = date("Ymd");
$log   = "{$config->logfiles_location}/rauth_server_prefs_pushing-$ldate.log";

$raw = $settings->get("modules:rauth_server.allowed_clients");
if( empty($raw) ) die(json_encode(array("message" => "OK")));

$ini = parse_ini_string($raw, true);

if( ! $ini )
{
    $message = "[$now] Allowed clients setting cannot be parsed. Cannot broadcast prefs.\n";
    @file_put_contents($log, $message, FILE_APPEND);
    
    return;
}

$message = "[$now] Locally saved prefs for $xaccount->display_name coming from {$wsdata["title"]}.\n";
@file_put_contents($log, $message, FILE_APPEND);

$xaccount = new account($xaccount->id_account);
$prefs = $xaccount->engine_prefs;
unset($prefs["@rauth_server:post_confirmation_wsdata"]);

foreach($ini as $wshandle => $pwsdata)
{
    if( $wshandle == $wsdata["handle"] ) continue;
    
    $pwsdata["handle"] = $wshandle;
    
    $client = new client($pwsdata);
    if( ! $client->enabled ) continue;
    
    try
    {
        $res = $client->save_engine_prefs($xaccount->id_account, $prefs);
    }
    catch(\Exception $e)
    {
        $message = "[$now] Cannot broadcast preferences for $xaccount->display_name to {$client->title}: {$e->getMessage()}.\n";
        @file_put_contents($log, $message, FILE_APPEND);
        
        continue;
    }
    
    if( $res != "OK" )
    {
        $message = "[$now] Error broadcast engine prefs for $xaccount->display_name to {$client->title}: {$res}.\n";
        @file_put_contents($log, $message, FILE_APPEND);
        
        continue;
    }
    
    $message = "[$now] Broadcasted engine prefs for $xaccount->display_name to {$client->title}.\n";
    @file_put_contents($log, $message, FILE_APPEND);
}

send_notification($xaccount->id_account, "info", replace_escaped_objects(
    unindent($current_module->language->messages->received_prefs),
    array('{$server}' => $client->title)
));

die(json_encode(array("message" => "OK")));
