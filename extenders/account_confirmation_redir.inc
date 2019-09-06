<?php
/**
 * Account confirmation extender: after successful confirmation
 *
 * @package    BardCanvas
 * @subpackage rauth_server
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 * 
 * @var account $xaccount
 */

use hng2_base\account;
use hng2_modules\rauth_server\client;

global $xaccount;

$wsdata = $xaccount->get_engine_pref("@rauth_server:post_confirmation_wsdata");
if( empty($wsdata) ) return;

$client = new client($wsdata);
$url    = $client->forge_login_token($xaccount->id_account);

if( $xaccount->get_engine_pref("@rauth_server:send_user_and_pass_for_login") == "true" )
{
    $key1  = $client->encryption_key1;
    $key2  = $client->encryption_key2;
    $key3  = $client->encryption_key3;
    $url  .= "&uhash=" . urlencode(three_layer_encrypt($xaccount->user_name, $key1, $key2, $key3));
    $url  .= "&phash=" . urlencode(three_layer_encrypt($xaccount->password,  $key1, $key2, $key3));
}

$msg = unindent(replace_escaped_objects(
    $this_module->language->login_to_origin, array('{$url}' => $url, '{$origin}' => $client->title)
));
?>

<p class="alternate">
    <?= $msg ?>
</p>
