<?php
/**
 * Account preferences saving extender: push prefs to client websites
 *
 * @package    BardCanvas
 * @subpackage rauth_server
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 * 
 * @var account $xaccount
 */

use hng2_base\account;
use hng2_modules\rauth_server\client;

global $xaccount, $settings;

$locals = $settings->get("modules:rauth_server.local_accounts");
if( ! empty($locals) )
{
    foreach(explode("\n", $locals) as $line)
    {
        $line = trim($line);
        
        if( empty($line) ) continue;
        if( substr($line, 0, 1) == "#" ) continue;
        
        if( $line == $xaccount->user_name ) return;
    }
}

$now   = date("Y-m-d H:i:s");
$ldate = date("Ymd");
$log   = "{$config->logfiles_location}/rauth_server_prefs_pushing-$ldate.log";

$raw = $settings->get("modules:rauth_server.allowed_clients");
if( empty($raw) ) return;

$ini = parse_ini_string($raw, true);

if( ! $ini )
{
    $message = "[$now] Allowed clients setting cannot be parsed.\n";
    @file_put_contents($log, $message, FILE_APPEND);
    
    return;
}

$zaccount = new account($xaccount->id_account);
$prefs    = $zaccount->engine_prefs;
unset($prefs["@rauth_server:post_confirmation_wsdata"]);

$message = "[$now] Locally saved prefs for $zaccount->display_name.\n";
@file_put_contents($log, $message, FILE_APPEND);

foreach($ini as $wshandle => $wsdata)
{
    $wsdata["handle"] = $wshandle;
    
    $client = new client($wsdata);
    if( ! $client->enabled ) continue;
    
    try
    {
        $res = $client->save_engine_prefs($zaccount->id_account, $prefs);
    }
    catch(\Exception $e)
    {
        $message = "[$now] Cannot push preferences for $zaccount->display_name to {$client->title}: {$e->getMessage()}.\n";
        @file_put_contents($log, $message, FILE_APPEND);
        
        continue;
    }
    
    if( $res != "OK" )
    {
        $message = "[$now] Error pushing engine prefs for $zaccount->display_name to {$client->title}: {$res}.\n";
        @file_put_contents($log, $message, FILE_APPEND);
        
        continue;
    }
    
    $message = "[$now] Pushed engine prefs for $zaccount->display_name to {$client->title}.\n";
    @file_put_contents($log, $message, FILE_APPEND);
}
