<?php
namespace hng2_modules\rauth_server;

class client
{
    public $handle;
    public $title;
    public $url;
    public $user_id_prefix;
    public $encryption_key1;
    public $encryption_key2;
    public $encryption_key3;
    
    /**
     * @var boolean
     */
    public $enabled;
    
    public $valid_hostnames = array();
    public $valid_ips       = array();
    
    /**
     * client constructor.
     *
     * @param array|object $wsdata
     */
    public function __construct($wsdata)
    {
        if( is_object($wsdata) ) $wsdata = (array) $wsdata;
        
        $this->handle          = $wsdata["handle"];
        $this->title           = $wsdata["title"];
        $this->url             = rtrim($wsdata["url"], "/");
        $this->user_id_prefix  = $wsdata["user_id_prefix"];
        $this->encryption_key1 = $wsdata["encryption_key1"];
        $this->encryption_key2 = $wsdata["encryption_key2"];
        $this->encryption_key3 = $wsdata["encryption_key3"];
        $this->valid_hostnames = $wsdata["valid_hostnames"];
        $this->valid_ips       = $wsdata["valid_ips"];
        $this->enabled         = $wsdata["enabled"];
    }
    
    /**
     * @param int $id_account
     * 
     * @return string
     */
    public function forge_login_token($id_account)
    {
        $exp = time() + 3600;
        $tkn = urlencode(three_layer_encrypt(
            "$id_account,$exp", $this->encryption_key1, $this->encryption_key2, $this->encryption_key3
        ));
        
        return sprintf("%s/rauth_client/scripts/login.php?token=%s", $this->url, $tkn);
    }
    
    /**
     * @param $id_account
     *
     * @return string
     * @throws \Exception
     */
    public function activate_account($id_account)
    {
        return $this->send_request("activate_account.php", array("id_account" => $id_account));
    }
    
    public function change_account_level($id_account, $new_level)
    {
        return $this->send_request(
            "change_account_level.php", array("id_account" => $id_account, "level" => $new_level)
        );
    }
    
    public function save_engine_prefs($id_account, $prefs)
    {
        return $this->post_data(
            "save_engine_prefs.php", array("id_account" => $id_account, "prefs" => $prefs)
        );
    }
    
    /**
     * @param string $script
     * @param mixed  $params
     * 
     * @return string
     * @throws \Exception
     */
    private function send_request($script, $params)
    {
        global $modules;
        
        $current_module = $modules["rauth_server"];
        
        $url = "{$this->url}/rauth_client/scripts/{$script}?";
        
        foreach( $params as $key => $val )
            $params[$key] = three_layer_encrypt(
                $val, $this->encryption_key1, $this->encryption_key2, $this->encryption_key3
            );
        
        $url .= http_build_query($params);
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL,            $url );
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 20);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_FRESH_CONNECT,  TRUE);
        
        usleep(100000);
        $res = curl_exec($ch);
        # echo "res := $res<br>";
        
        if( curl_error($ch) )
            throw new \Exception(sprintf(
                $current_module->language->messages->client_api_error, $url, curl_error($ch)
            ));
        
        curl_close($ch);
        
        if( empty($res) )
            throw new \Exception(sprintf(
                $current_module->language->messages->client_api_empty, $url
            ));
        
        if( $res != "OK" )
            throw new \Exception(sprintf(
                $current_module->language->messages->client_api_error2, $res
            ));
        
        return $res;
    }
    
    /**
     * @param string $script
     * @param mixed  $params
     * 
     * @return string
     * @throws \Exception
     */
    private function post_data($script, $params)
    {
        global $modules;
        
        $current_module = $modules["rauth_server"];
        
        $url = "{$this->url}/rauth_client/scripts/{$script}";
        
        foreach( $params as $key => $val )
            $params[$key] = three_layer_encrypt(
                serialize($val), $this->encryption_key1, $this->encryption_key2, $this->encryption_key3
            );
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL,            $url );
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 20);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_FRESH_CONNECT,  TRUE);
        curl_setopt($ch, CURLOPT_POST,           1);
        curl_setopt($ch, CURLOPT_POSTFIELDS,     http_build_query($params));
        
        usleep(100000);
        $res = curl_exec($ch);
        # echo "res := $res<br>";
        
        if( curl_error($ch) )
            throw new \Exception(sprintf(
                $current_module->language->messages->client_api_error, $url, curl_error($ch)
            ));
        
        curl_close($ch);
        
        if( empty($res) )
            throw new \Exception(sprintf(
                $current_module->language->messages->client_api_empty, $url
            ));
        
        if( $res != "OK" )
            throw new \Exception(sprintf(
                $current_module->language->messages->client_api_error2, $res
            ));
        
        return $res;
    }
}
