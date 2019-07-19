<?php
namespace hng2_modules\rauth_server;

use hng2_base\account;
use hng2_base\accounts_repository;

class toolbox
{
    /**
     * @param string $website_handle
     * @param bool   $check_ips_and_hosts
     *
     * @return array
     * @throws \Exception
     */
    public function init_website($website_handle, $check_ips_and_hosts = true)
    {
        global $settings, $modules;
        
        $current_module = $modules["rauth_server"];
        
        if( empty($website_handle) )
            throw new \Exception(
                trim($current_module->language->messages->missing_wsh)
            );
        
        $raw = $settings->get("modules:rauth_server.allowed_clients");
        if( empty($raw) )
            throw new \Exception(
                trim($current_module->language->messages->no_allowed_clients_found)
            );
        
        $ini = parse_ini_string($raw, true);
        
        if( ! $ini )
            throw new \Exception(
                trim($current_module->language->messages->invalid_allowed_clients_format)
            );
        
        if( ! isset($ini[$website_handle]) )
            throw new \Exception(
                sprintf($current_module->language->messages->wsh_not_found, $website_handle)
            );
        
        $wsdata = $ini[$website_handle];
        
        $wsdata["handle"] = $website_handle;
        
        if( empty($wsdata["title"]) )
            throw new \Exception(
                sprintf($current_module->language->messages->missing_details, $website_handle)
            );
        
        if( ! $wsdata["enabled"] )
            throw new \Exception(
                sprintf(
                    $current_module->language->messages->website_disabled,
                    $wsdata["title"],
                    $settings->get("engine.website_name")
                )
            );
        
        if( empty($wsdata["url"]) )
            throw new \Exception(
                sprintf($current_module->language->messages->missing_details, $website_handle)
            );
        
        if( empty($wsdata["encryption_key1"]) )
            throw new \Exception(
                sprintf($current_module->language->messages->missing_details, $website_handle)
            );
        
        if( empty($wsdata["encryption_key2"]) )
            throw new \Exception(
                sprintf($current_module->language->messages->missing_details, $website_handle)
            );
        
        if( empty($wsdata["encryption_key3"]) )
            throw new \Exception(
                sprintf($current_module->language->messages->missing_details, $website_handle)
            );
        
        if( ! $check_ips_and_hosts ) return $wsdata;
        
        if( ! empty($wsdata["valid_ips"]) )
        {
            $remote_ip = get_remote_address();
            if( ! filter_var($remote_ip, FILTER_VALIDATE_IP) )
                throw new \Exception(
                    sprintf($current_module->language->messages->invalid_ip, $remote_ip, $wsdata["title"])
                );
            
            $valid_ips = preg_split('/\s+/', trim($wsdata["valid_ips"]));
            if( ! in_array($remote_ip, $valid_ips) )
                throw new \Exception(
                    sprintf($current_module->language->messages->ip_not_allowed, $remote_ip, $wsdata["title"])
                );
        }
        
        if( ! empty($wsdata["valid_hostnames"]) )
        {
            $remote_ip   = get_remote_address();
            $remote_host = @gethostbyaddr($remote_ip);
            
            if( empty($remote_host) )
                throw new \Exception(
                    sprintf($current_module->language->messages->invalid_host, $remote_ip)
                );
            
            $valid_hosts = preg_split('/\s+/', trim($wsdata["valid_hostnames"]));
            if( ! in_array($remote_host, $valid_hosts) )
                throw new \Exception(
                    sprintf($current_module->language->messages->host_not_allowed, $remote_host, $wsdata["title"])
                );
        }
        
        return $wsdata;
    }
    
    /**
     * @param array $wsdata
     *
     * @return account
     * @throws \Exception
     */
    public function get_incoming_account($wsdata)
    {
        global $modules;
        $current_module = $modules["rauth_server"];
        
        if( ! is_array($_POST) )
            throw new \Exception(
                sprintf($current_module->language->messages->missing_data, $wsdata["title"])
            );
        
        $data    = $this->decrypt_data($_POST["data"], $wsdata);
        $account = new account($data);
        
        $account->_exists       = false;
        $account->_raw_password = $data->_raw_password;
        
        return $account;
    }
    
    public function get_incoming_data($wsdata)
    {
        global $modules;
        $current_module = $modules["rauth_server"];
        
        if( ! is_array($_POST) )
            throw new \Exception(
                sprintf($current_module->language->messages->missing_data, $wsdata["title"])
            );
        
        return $this->decrypt_data($_POST["data"], $wsdata);
    }
    
    private function decrypt_data($data, $wsdata)
    {
        global $modules;
        $current_module = $modules["rauth_server"];
        
        if( empty($data) )
            throw new \Exception(
                sprintf($current_module->language->messages->missing_data, $wsdata["title"])
            );
        
        $item = unserialize(three_layer_decrypt(
            $data, $wsdata["encryption_key1"], $wsdata["encryption_key2"], $wsdata["encryption_key3"]
        ));
        
        if( ! (is_object($item) || is_array($item)) )
            throw new \Exception(
                sprintf($current_module->language->messages->invalid_data, $wsdata["title"])
            );
        
        return $item;
    }
    
    /**
     * @param account $xaccount
     *
     * @throws \Exception
     */
    public function validate_new_account($xaccount)
    {
        global $settings, $modules;
        
        $module     = $modules["accounts"];
        $repository = new accounts_repository();
        
        $blacklist = trim($settings->get("modules:accounts.usernames_blacklist"));
        if( ! empty($blacklist) )
        {
            foreach(explode("\n", $blacklist) as $line)
            {
                $line = trim($line);
                if( empty($line) ) continue;
                if( substr($line, 0, 1) == "#" ) continue;
            
                $pattern = "@^" . str_replace(array("*", "?"), array(".+", ".?"), trim($line)) . "@i";
                if( preg_match($pattern, $xaccount->user_name) )
                {
                    throw new \Exception(
                        trim($module->language->errors->registration->invalid->user_name_blacklisted)
                    );
                }
            }
        }
        
        $blacklist = trim($settings->get("modules:accounts.displaynames_blacklist"));
        if( ! empty($blacklist) )
        {
            foreach(explode("\n", $blacklist) as $line)
            {
                $line = trim($line);
                if( empty($line) ) continue;
                if( substr($line, 0, 1) == "#" ) continue;
            
                $pattern = "@^" . str_replace(array("*", "?"), array(".+", ".?"), trim($line)) . "@i";
                if( preg_match($pattern, $xaccount->display_name) )
                {
                    throw new \Exception(
                        trim($module->language->errors->registration->invalid->display_name_blacklisted)
                    );
                }
            }
        }
        
        $blacklist = trim($settings->get("modules:accounts.email_domains_blacklist"));
        if( ! empty($blacklist) )
        {
            $main_domain = end(explode("@", $xaccount->email));
            $alt_domain  = end(explode("@", $xaccount->alt_email));
            foreach(explode("\n", $blacklist) as $line)
            {
                $line = trim($line);
                if( empty($line) ) continue;
                if( substr($line, 0, 1) == "#" ) continue;
            
                if( $line == $main_domain )
                {
                    throw new \Exception(
                        trim($module->language->errors->registration->invalid->mail_domain)
                    );
                }
            
                if( $line == $alt_domain )
                {
                    throw new \Exception(
                        trim($module->language->errors->registration->invalid->alt_mail_domain)
                    );
                }
            }
        }
    
        $count = $repository->get_record_count(array("display_name" => $_POST["display_name"]) );
        if( $count > 0 )
            throw new \Exception(
                trim($module->language->errors->registration->invalid->display_name_taken)
            );
        
        $yaccount = new account($xaccount->user_name);
        if( $yaccount->_exists )
            throw new \Exception(
                trim($module->language->errors->registration->invalid->user_name_taken)
            );
        
        $rows = $repository->find(array("email = '$xaccount->email' or alt_email = '$xaccount->email'"), 0, 0, "creation_date asc");
        if( count($rows) > 0 )
            throw new \Exception(
                trim($module->language->errors->registration->invalid->main_email_exists)
            );
        
        if( ! empty($xaccount->alt_email) )
        {
            $rows = $repository->find(array("alt_email = '$xaccount->alt_email' or alt_email = '$xaccount->alt_email'"), 0, 0, "creation_date asc");
            if( count($rows) > 0 )
                throw new \Exception(
                    trim($module->language->errors->registration->invalid->alt_email_exists)
                );
        }
    }
}
