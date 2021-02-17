<?php
namespace App\SecureApi;
use Exceptio;
class SecureApi{
    public static Array $client  = [];
    public static string $user_file = "";
    public static string $user_key = "Appid";
    public static string $pass_key = "Apppass";
    public static function enable_host_protection(){
        $ip = $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['HTTP_CLIENT_IP'] ?? $_SERVER['HTTP_CLIENT_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_FORWARDED'] ?? $_SERVER['HTTP_FORWARDED_FOR'] ?? $_SERVER['HTTP_FORWARDED'] ?? $_SERVER['REMOTE_ADDR'] ?? false;
        $host = $_SERVER['HTTP_HOST'] ?? false;
        if(!(self::check_host($ip) || self::check_host($host))){
            http_response_code(403);
            exit;
        }
    }
    public static function enable_user_protection(){
        
        // var_dump(getallheaders()[self::$user_key]);
        if( !(isset(getallheaders()[self::$user_key]) and isset(getallheaders()[self::$pass_key]))){
            http_response_code(403);
            exit;
        }
        else if( !(self::check_user(getallheaders()[self::$user_key], getallheaders()[self::$pass_key]))){
            http_response_code(403);
            exit;
        }
    }
    
    public static function allow_host(string $client){
        if(filter_var($client, FILTER_VALIDATE_DOMAIN) or filter_var($client, FILTER_VALIDATE_IP)){
            array_push(self::$client, $client);
        }else {
            throw new \Exception( 'O ip passado para validação "'.$client.'" não é um ip valido. Passe apenas ips ou urls');
        }
        
    }

    public static function load_host_array(Array $array_hosts){
        foreach($json_clients as $client){
            self::allow_host($client);
        }
    }
    public static function load_host_file($file_Name){
        $file = fopen ($file_Name, 'r');
        while(!feof($file)){
            $line = fgets($file, 1024);
            $client = trim($line);
            if($client=="" or $client[0] == "#"){
                continue;
            }
            self::allow_host($client);
        }
        fclose($file);
    }
    private static function check_host(string $client){
        if(in_array($client, self::$client)){
            return true;
        }
        return false;
    }

    public static function load_user_file(string $user_file){
        self::$user_file = $user_file;
    }
    private static function check_user(string $user, string $password){
        if(self::$user_file==""){
            throw new \Exception("user_file not found in method enable_user_protection. call the load_user_file method to define the user file.");
        }
        else{
            $file = fopen (self::$user_file, 'r');
            $valid_user = false;
            while(!feof($file)){
                $line = fgets($file, 1024);
                $line = trim($line);
                if($line=="" or $line[0] == "#"){
                    continue;
                }
                $user_of_file = explode(" ", $line)[0];
                $pass_of_file = explode(" ", $line)[1];
                if($user_of_file==$user and $pass_of_file == $password){
                    $valid_user = true;
                    break;  
                }
            }
            fclose($file);
            return $valid_user;
            
        }
    }
}