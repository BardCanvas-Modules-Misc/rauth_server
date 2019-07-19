<?php
/**
 * Document handler for Remothe Auth Server JSON RPC API. Methods:
 * api/create_account?wsh=<website_handle>
 * api/get_account?wsh=<website_handle>
 * api/send_confirmation_email?wsh=<website_handle>
 * api/validate_login?wsh=<website_handle>
 * api/update_account?wsh=<website_handle>
 *
 * @package    BardCanvas
 * @subpackage rauth_server
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 *
 * $_GET params:
 * @param "handle"
 * 
 * $_POST params:
 * @param string "data"
 * 
 * @return string {message:string, data:mixed}
 */

use hng2_modules\rauth_server\toolbox;

if( empty($_GET["handle"]) ) return;

$handle = trim(stripslashes($_GET["handle"]));
if( substr($handle, 0, 4) !== "api/" ) return;

$method = preg_replace('#^api/#i', '', $handle);
$method = trim($method, "/");
if( empty($method) ) return;
if( ! preg_match("/^[a-z_]+$/", $method) ) return;
if( ! file_exists(__DIR__ . "/api_methods/$method.inc") ) return;

header("Content-Type: application/json; charset=utf-8");

try
{
    $toolbox = new toolbox();
    $wsdata  = $toolbox->init_website($_GET["wsh"]);
}
catch(\Exception $e)
{
    die(json_encode(array("message" => $e->getMessage())));
}

include __DIR__ . "/api_methods/$method.inc";

die(json_encode(array("message" => "Method not implemented")));
