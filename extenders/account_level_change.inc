<?php
/**
 * Account toolbox extender: after level changed
 * Broadcasts the user level to all client websites. 
 *
 * @package    BardCanvas
 * @subpackage rauth_server
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 * 
 * @var account $user_account
 */

use hng2_base\account;
use hng2_modules\rauth_server\client;

global $account, $user_account, $settings;

$raw = $settings->get("modules:rauth_server.allowed_clients");
if( empty($raw) ) return;

$ini = parse_ini_string($raw, true);

if( ! $ini )
    die( $this_module->language->messages->invalid_allowed_clients_format );

foreach($ini as $wshandle => $wsdata)
{
    $wsdata["handle"] = $wshandle;
    
    $client = new client($wsdata);
    if( ! $client->enabled ) continue;
    
    try
    {
        $client->change_account_level($user_account->id_account, $user_account->level);
    }
    catch(\Exception $e)
    {
        send_notification($account->id_account, "warning", replace_escaped_objects(
            $this_module->language->messages->level_changed_ko,
            array( '{$client}' => $client->title, '{$error}' => $e->getMessage() )
        ));
    }
    
    send_notification($account->id_account, "success", replace_escaped_objects(
        $this_module->language->messages->level_changed_ok,
        array( '{$client}' => $client->title )
    ));
}
