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
$msg    = unindent(replace_escaped_objects(
    $this_module->language->login_to_origin, array('{$url}' => $url, '{$origin}' => $wsdata["title"])
));
?>

<p class="alternate">
    <?= $msg ?>
</p>
