<?php
/*
 * ss-mitm
 *
 */

define('ADDRTYPE_IPV4', 1);
define('ADDRTYPE_IPV6', 4);
define('ADDRTYPE_HOST', 3);

$http_method_list = array(
	"GET", "HEAD", "POST", "PUT", 
	"DELETE", "CONNECT", "OPTIONS", "TRACE", 
);



$domain_not = array();
for($i=0; $i<256; $i++) {
    if($i >= ord('0') && $i <= ord('9')) {
        continue;
    }
    if($i >= ord('a') && $i <= ord('z')) {
        continue;
    }
    if($i >= ord('A') && $i <= ord('Z')) {
        continue;
    }
    if($i == ord('.') || $i == ord('-')) {
        continue;
    }
    array_push($domain_not, chr($i));
}

function get_host_by_ssl_sni($buf)
{
    global $domain_not;
    $tls_header = substr($buf, 0, 5);
    $tls_header = unpack("C1content/n1version/n1length", $tls_header);
    if($tls_header['content'] != 0x16) {
        return false;
    }
    $len = strlen($buf);

    $buf_rep = str_replace($domain_not, "\x00", $buf);
    $arr_exp = explode("\x00", $buf_rep);
    foreach ($arr_exp as $key => $value) {
        if(strlen($value) < 4) {
            unset($arr_exp[$key]);
        }
    }
    if(count($arr_exp) == 0) {
        return false;
    }
    foreach ($arr_exp as $key => $value) {
        $name_length = strlen($value);
        $pos = strpos($buf, $value);
        $pos -= 5;

        $snie = substr($buf, $pos, 5);
        $sni_length = unpack("n1SNIL/C1SNT/n1SNL", $snie);
        if( $sni_length['SNIL'] == $sni_length['SNL'] + 3 
            && strlen($value) == $sni_length['SNL']){
            return $value;
        }

        $pos += 1;
        $name_length -= 1;
        $value = substr($value, 1);

        $snie = substr($buf, $pos, 5);
        $sni_length = unpack("n1SNIL/C1SNT/n1SNL", $snie);
        if( $sni_length['SNIL'] == $sni_length['SNL'] + 3
            && strlen($value) == $sni_length['SNL']){
            return $value;
        }
    }

    return false;
}

// Get any header except the HTTP response...
function getResponseHeader($header, $response)
{
	foreach ($response as $key => $r) {
		// Match the header name up to ':', compare lower case
		if (stripos($r, $header . ':') === 0) {
			list($headername, $headervalue) = explode(":", $r, 2);
			return trim($headervalue);
		}
	}
	return false;
}

function getTypeByAddress($addr)
{
	if(filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)){
		return ADDRTYPE_IPV4;
	}else if(filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)){
		return ADDRTYPE_IPV6;
	}else{
		return ADDRTYPE_HOST;
	}
}

function http_message_relay($msg)
{
	$relay ="HTTP/1.1 200 OK\r\n".
			"Connection: close\r\n".
			"Content-Length: " . strlen($msg) . "\r\n".
			"Content-Type: text/html;charset=utf-8\r\n".
			"\r\n$msg";
	return $relay;
}
