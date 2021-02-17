<?php

include_once "vendor/autoload.php";
use \App\SecureApi\SecureApi;

// secureApi::allow_client("lohan.local");
// secureApi::mode("Disable");
// secureApi::load_host_file("rangeip.txt");
// secureApi::enable_host_protection();

secureApi::load_user_file("user_file");
secureApi::enable_user_protection();


echo "ola mundo";



