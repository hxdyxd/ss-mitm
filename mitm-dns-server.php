<?php
/**
 *  ss-mitm
 *
 * Licensed under The MIT License
 * For full copyright and license information, please see the MIT-LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 * 
 */
use \Workerman\Worker;
use \Workerman\Autoloader;
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/Workerman/Autoloader.php';

//windows
if (DIRECTORY_SEPARATOR === '\\') {
    Autoloader::setRootPath(__DIR__);
}

$qtype_table = array(
	'Unknow',
	'A',
	'NS',
	'MD',
	'MF',
	'CNAME',
	'SOA',
	'MB',
	'MG',
	'MR',
	'NULL',
	'WKS',
	'PTR',
	'HINFO',
	'MINFO',
	'MX',
	'TXT',  //16
	'RP',
	'AFSDB',
	'SIG',
	'24' => 'SIG',
	'25' => 'KEY',
	'28' => 'AAAA',
);
$gb_list = file_get_contents('gb_list.txt');
if($gb_list === false) {
	die("not found gb_list.txt");
}
$gb_list = explode("\n", $gb_list);
foreach ($gb_list as $key => $value) {
	$gb_list[$key] = strrev($value);
}

function domain_allow($domain)
{
	global $gb_list;
	$domain = strrev($domain);
	foreach ($gb_list as $key => $value) {
		if(strpos($domain, $value) === 0) {
			return false;
		}
	}
	return true;
}

function domain_decode($question)
{
	$i = 0;
	$domain = '';
	while(( $len = ord($question[$i]) ) != 0) {
		if($len > 63) {
			break;
		}
		$sum_domain = "." . substr($question, $i+1, $len);
		if($sum_domain == '') {
			break;
		}
		$domain .= $sum_domain;
		$i += $len+1;
	}
	$domain = substr($domain, 1);
	return array($domain, $i);
}

function domain_pack($id, $domain, $ip)
{
	$pack_buf = pack("n6", $id, 0x8180, 1, 1, 0, 0);
	$domain_list = explode('.', $domain);
	foreach ($domain_list as $key => $value) {
		$pack_buf .= chr(strlen($value)) . $value;
	}
	$pack_buf .= "\x00";
	$pack_buf .= pack("n2", 1, 1);
	//NAME   TYPE   CLASS    TTL    RDLENGTH    RDATA
	//0x0cc0  1       1      600      4          ip    
	$pack_buf .= pack("n3N1n1", 0xc00c, 1, 1, 600, 4);
	$pack_buf .= inet_pton($ip);
	return $pack_buf;
}

$worker_udp_dns = new Worker('udp://0.0.0.0:' . $DNS_BIND_PORT);
$worker_udp_dns->count = $PROCESS_COUNT;
$worker_udp_dns->name = 'mitm-dns-server';

$worker_udp_dns->onMessage = function($connection, $buffer)use($qtype_table, $DNS_PROXY_IP)
{
    //echo bin2hex($buffer) . "\n";
    $request_val = substr($buffer, 0, 12);
    $request_val = unpack("n1id/n1flag/n1QDCOUNT/n1ANCOUNT/n1NSCOUNT/n1ARCOUNT", $request_val);
    //print_r($request_val);
    for($qdcount = 0; $qdcount < $request_val['QDCOUNT'];$qdcount++) {
    	$question = substr($buffer, 12);
    	list($domain, $i) = domain_decode($question);
    	$q = substr($question, $i+1, 4);
    	$q = unpack("n1QTYPE/n1QCLASS", $q);
    	if($q['QTYPE'] != 1) {
    		//echo " REQ DOMAIN:" . $domain . " CLASS:" . $qtype_table[$q['QTYPE']] ."\n";
    		break;
    	}

    	if(domain_allow($domain)) {
    		$ip = gethostbyname($domain);
    	} else {
    		$ip = $DNS_PROXY_IP;
    	}
    	//$ip = $DNS_PROXY_IP;
    	if(!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    		echo "[mitm-dns-server] REQ DOMAIN:" . $domain . " CLASS:" . $qtype_table[$q['QTYPE']] . " gethost error\n";
    		break;
    	}
    	echo "[mitm-dns-server] REQ DOMAIN:" . $domain . " CLASS:" . $qtype_table[$q['QTYPE']] . " IP:" . $ip ."\n";
    	$pack_buf = domain_pack($request_val['id'], $domain, $ip);
    	$connection->send($pack_buf);
    	break;
    }
    //echo "id: " . bin2hex($id) . "\n";

    return $connection->close();
};

// Run.
//windows
if (DIRECTORY_SEPARATOR === '\\') {
    Worker::runAll();
}
