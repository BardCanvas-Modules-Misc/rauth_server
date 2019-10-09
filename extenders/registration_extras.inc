<?php
/**
 * Accounts extender: additional fields for "always remote" registration
 *
 * @package    BardCanvas
 * @subpackage rauth_server
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 *
 */

if( $modules["single_signon"]->enabled )
    $_GET["redir_url"] = "{$this_module->get_url()}/scripts/login_redirect.php?wsh={$_REQUEST["rauth_client_handle"]}";
?>

<!-- [+] Remote Auth Server incoming fields --> 
<input type="hidden" name="rauth_client_handle" value="<?= $_REQUEST["rauth_client_handle"] ?>">
<!-- [-] Remote Auth Server incoming fields --> 
