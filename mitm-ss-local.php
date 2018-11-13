<?php
/**
 * ss-mitm
 *
 * Licensed under The MIT License
 * For full copyright and license information, please see the MIT-LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 * 
 */
use \Workerman\Worker;
use \Workerman\Connection\AsyncTcpConnection;
use \Workerman\Autoloader;
require_once __DIR__ . '/Workerman/Autoloader.php';
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/common.php';

$mitm_ss_local_max = count($MITM_BIND_PORT);
//windows
if (DIRECTORY_SEPARATOR === '\\') {
    Autoloader::setRootPath(__DIR__);
    if($argc < 2) {
    	die("[error] for windows, run use php " . $argv[0] . " id\r\n");
    } else {
    	$start = $argv[1];
    }
    if($start >= $mitm_ss_local_max) {
    	die("[error] id:$start more than $mitm_ss_local_max failed\r\n");
    }
    $mitm_ss_local_max = $start+1;
} else {
    $start = 0;
}


$worker_mitm_ss_local = array();

for($i=$start; $i<$mitm_ss_local_max; $i++) {
    $worker_mitm_ss_local[$i] = new Worker('tcp://0.0.0.0:' . $MITM_BIND_PORT[$i]);
    $worker_mitm_ss_local[$i]->count = $PROCESS_COUNT;
    $worker_mitm_ss_local[$i]->name = 'mitm-ss-local-' . $MITM_BIND_PORT[$i];
    $worker_mitm_ss_local[$i]->onMessage = 'mitm_ss_local_on_message';
}


function mitm_ss_local_on_message($connection, $buffer)
{
    global $SERVER, $PORT;
    global $PASSWORD, $METHOD;
    global $http_method_list;
    //get host
    if($buffer[0] == "\x16") {
        $host = get_host_by_ssl_sni($buffer);
        if($host === false) {
            echo "[mitm-ss-local] host not found in sni\n";
            return $connection->close();
        }
    } else {
        // Parse http header.
        if(strlen($buffer) < 10) {
            echo "[mitm-ss-local] buf:[" . bin2hex($buffer) . "]\n";
            return $connection->close();
        }
        $method = explode(' ', $buffer)[0];
        if(in_array($method, $http_method_list)) {
            $host = getResponseHeader("Host", explode("\r\n", $buffer));
            if($host === false) {
                echo "[mitm-ss-local] host not found\n";
                return $connection->close();
            }
        } else {
            echo "[mitm-ss-local] method not support\n";
            return $connection->close();
        }
    }
        
    $port = $connection->getLocalPort();
    echo "[mitm-ss-local] connect to $host:$port\n";

    $addrtype = getTypeByAddress($host);
    if($addrtype == ADDRTYPE_IPV4){
    	$socks5_header = chr(ADDRTYPE_IPV4);
    	$socks5_header .= inet_pton($host);
    	$socks5_header .= pack('n', $port);
    }else if($addrtype == ADDRTYPE_HOST){
    	$socks5_header = chr(ADDRTYPE_HOST);
    	$socks5_header .= chr(strlen($host));
    	$socks5_header .= $host;
    	$socks5_header .= pack('n', $port);
    }else{
        $socks5_header = chr(ADDRTYPE_IPV6);
        $socks5_header .= inet_pton($host);
        $socks5_header .= pack('n', $port);
    }
    $address = "tcp://$SERVER:$PORT";
    $remote_connection = new AsyncTcpConnection($address);
    $connection->opposite = $remote_connection;
    $connection->encryptor = new Encryptor($PASSWORD, $METHOD);
    $remote_connection->opposite = $connection;
    // 流量控制
    $remote_connection->onBufferFull = function($remote_connection)
    {
        $remote_connection->opposite->pauseRecv();
    };
    $remote_connection->onBufferDrain = function($remote_connection)
    {
        $remote_connection->opposite->resumeRecv();
    };
    $remote_connection->onMessage = function($remote_connection, $buffer)
    {
        $remote_connection->opposite->send($remote_connection->opposite->encryptor->decrypt($buffer));
    };

    $remote_connection->onClose = function($remote_connection)
    {
        $remote_connection->opposite->close();
        $remote_connection->opposite = null;
    };
    // 远程连接发生错误时（一般是建立连接失败错误），关闭客户端的连接
    $remote_connection->onError = function($remote_connection, $code, $msg)use($address)
    {
        echo "remote_connection $address error code:$code msg:$msg\n";
        $remote_connection->close();
        if($remote_connection->opposite){
            $remote_connection->opposite->close();
        }
    };
    // 流量控制
    $connection->onBufferFull = function($connection)
    {
        $connection->opposite->pauseRecv();
    };
    $connection->onBufferDrain = function($connection)
    {
        $connection->opposite->resumeRecv();
    };
    $connection->onMessage = function($connection, $data)
    {
        $connection->opposite->send($connection->encryptor->encrypt($data));
    };
    $connection->onClose = function($connection)
    {
        $connection->opposite->close();
        $connection->opposite = null;
    };
    // 当客户端连接上有错误时，关闭远程服务端连接
    $connection->onError = function($connection, $code, $msg)
    {
        echo "connection err code:$code msg:$msg\n";
        $connection->close();
        if(isset($connection->opposite)){
            $connection->opposite->close();
        }
    };
    // 执行远程连接
    $remote_connection->connect();
    //转发首个数据包，包含SOCKS5格式封装的目标地址，端口号等信息
	$buffer = $socks5_header.$buffer;
	$buffer = $connection->encryptor->encrypt($buffer);
    $remote_connection->send($buffer);
};

// Run.
//windows
if (DIRECTORY_SEPARATOR === '\\') {
    Worker::runAll();
}