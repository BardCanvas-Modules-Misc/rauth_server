<?php
/**
 * Remote authentication login page
 *
 * @package    BardCanvas
 * @subpackage rauth_server
 * @author     Alejandro Caballero - lava.caballero@gmail.com
 * 
 * @var string $error_message
 * @var array  $wsdata
 */

$accounts_module = $modules["accounts"];
?>

<h1><?= $template->get_page_title(false) ?></h1>

<?= $settings->get("modules:rauth_server.login_page_top_markup") ?>

<? if( ! empty($error_message) ): ?>
    
    <div class="framed_content state_ko">
        <i class="fa fa-warning"></i>
        <?= $error_message ?>
    </div>
    <? return; ?>
    
<? endif; ?>

<div class="multicol cols-2">
    <div class="col intro">
        <?= $settings->get("modules:rauth_server.login_page_left_markup") ?>
    </div>
    <div class="col login_form" id="rauthpage_login">
        
        <p class="principal_data">
            <?= replace_escaped_objects($current_module->language->login_page->info, array(
                '{$server_name}' => $settings->get("engine.website_name"),
                '{$client_name}' => $wsdata["title"],
            )) ?>
        </p>
        
        <div id="rauthpage_login_targetarea" style="display: none;"></div>
        
        <form name="rauthpage_login_form" id="rauthpage_login_form" method="post"
              action="<?=$config->full_root_path?>/accounts/scripts/login.php">
            <input type="hidden" name="wsh"  value="<?= $wsdata["handle"] ?>">
            <input type="hidden" name="goto" value="<?= rtrim($wsdata["url"], "/") . $_REQUEST["return_to"] ?>">
            
            <div class="field standard_user_name">
                <div class="caption"><?= $accounts_module->language->user_name ?></div>
                <div class="input"><input type="text" name="user_name"></div>
            </div>
            
            <div class="field standard_password">
                <div class="caption"><?= $accounts_module->language->password ?></div>
                <div class="input"><input type="password" name="password"></div>
            </div>
            
            <div class="field standard_password_reset">
                <span class="pseudo_link" onclick="$('#login_dialog').dialog('close'); reset_password();">
                    <span class="fa fa-key"></span>
                    <?= $accounts_module->language->reset_password ?>
                </span>
            </div>
            
            <div class="field submit_button_container alignright">
                <button type="submit">
                    <span class="fa fa-sign-in"></span>
                    <?= $accounts_module->language->login ?>
                </button>
            </div>
        </form>
        
        <? if( $settings->get("modules:accounts.register_enabled") != "false" ):
            $registration_page = "{$config->full_root_path}/accounts/register.php"; ?>
            <p class="aligncenter">
                <span class="principal_data"><?= $current_module->language->login_page->belong ?></span><br><br>
                <a class="framed_content registration_link state_highlight"
                   style="display: block; font-size: 1.4em;"
                   href="<?= $registration_page?> ">
                    <?= $current_module->language->login_page->register_now ?>
                </a>
            </p>
        <? endif; ?>
        
    </div>
</div>

<script type="text/javascript">
    
    var $login_form = $('#rauthpage_login_form');

    $login_form.ajaxForm({
        target:        '#rauthpage_login_targetarea',
        beforeSubmit:  validate_rauthpage_login_form,
        success:       process_rauthpage_login_result
    });
    
    function validate_rauthpage_login_form(formData, $form)
    {
        $form.block(blockUI_medium_params);
        
        if( $login_form.find('input[name="user_name"]').val().trim() === "" ||
            $login_form.find('input[name="user_name"]').val().trim() === "" ) {
            alert( $('#login_errors').find('.invalid_login_info').text().replace(/\n\s+/g, ' ') );
            return false;
        }
        
        return true;
    }
    
    function process_rauthpage_login_result(result, statusText, xhr, $form)
    {
        $form.unblock();
        
        if( result.indexOf('ERROR') < 0 )
        {
            // result > username > device_message > redirect
            parts = result.split('\t');
            
            // Let's show the info and logout button
            $('.login').hide();
            $('#loggedin_username').text(parts[1]);
            $('.logout').show();
            
            // Let's check if we need to alert about the new device
            if( parts[2] !== "OK" )
            {
                $('#loggedin_icon').hide();
                $('#loggedin_icon_locked').show();
                alert( $('#device_messages .' + parts[2]).text().replace(/\n\s+/g, ' ') );
                
                return;
            }
            
            if( parts[3] !== '' ) location.href = parts[3];
            
            return;
        }
        
        var $msgelement = $('#login_errors').find('.' + result);
        var message     = $msgelement.length > 0 ? $msgelement.text() : result;
        alert( message );
    }
</script>
