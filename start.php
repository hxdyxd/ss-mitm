<?php
/*
 * ss-mitm
 *
 */
use \Workerman\Worker;
use \Workerman\Autoloader;

require_once 'config.php';
require_once __DIR__ . '/Workerman/Autoloader.php';

Autoloader::setRootPath(__DIR__);


require_once 'mitm-dns-server.php';
require_once 'mitm-ss-local.php';

// Run.
Worker::runAll();
