<?php
/**
 * Accounts extender: set engine pref to properly handle redirection after account confirmation
 *
 * @package    BardCanvas
 * @subpackage rauth_server
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 */

use hng2_modules\rauth_server\toolbox;

global $xaccount;

if( empty($_POST["rauth_client_handle"]) ) return;

$wshandle = stripslashes($_POST["rauth_client_handle"]);

try
{
    $toolbox = new toolbox();
    $wsdata  = $toolbox->init_website($wshandle, false);
}
catch(\Exception $e)
{
    return;
}

$xaccount->set_engine_pref("@rauth_server:post_confirmation_wsdata", $wsdata);
$xaccount->set_engine_pref("@rauth_server:no_before_state_check", "true");
$xaccount->set_engine_pref("@rauth_server:send_user_and_pass_for_login", "true");
