#!/usr/bin/php
<?php
/*****
 * Version 0.1 - 2016-02-04 - Chris Kitzmiller
 *****/

// Get options
$shortopts = "H:hv";
$longopts = array(
	"help",
	"no-warn-pfs",
	"version"
);
$o = getopt($shortopts, $longopts);

// Resolve dependencies 
$TLSSCAN = exec("which tlsscan.php", $output, $retval);
if($retval) { echo("Unknown: Unable to find tlsscan.php\n"); exit(3); }

// Help
if(isset($o["h"]) || isset($o["help"])) { usage(); exit(3); }

// Version
if(isset($o["v"]) || isset($o["version"])) { version(); exit(3); }

// Check syntax
if(!isset($o["H"])) { usage(); exit(3); }

// Internal variables
$warnpfs = isset($o["no-warn-pfs"]) ? false : true;
$warning = false;
$critical = false;
$retvals = array();

$connect = $o["H"];
if(isset($o["p"])) { $connect .= " -p " . $o["p"]; }
unset($output);
$lastline = exec("$TLSSCAN -H $connect", $output, $retval);
if($retval) { echo("Unknown: $lastline\n"); exit(3); }

$data = json_decode($output[0]);
if(!$data) { echo("Unknown: Unable to parse tlsscan.php output\n"); exit(3); }

foreach($data as $proto => $val) {
	if($proto == "preferred") {
		foreach($val as $ciphersuite => $details) {
			$retval = "OK: " . $ciphersuite;
		}
	}
	if($proto == "ssl2") { $critical = true; $retvals[] = "SSLv2 enabled"; }
	if($proto == "ssl3") { $critical = true; $retvals[] = "SSLv3 enabled"; }
	foreach($val as $ciphersuite => $details) {
		if($warnpfs && !$details->forwardsecrecy) { $warning = true; $retvals[] = "No PFS(" . $ciphersuite . ")"; }
		if($details->export == true) { $critical = true; $retvals[] = "Export(" . $ciphersuite . ")"; }
		if(in_array($details->cipher, array("RC4", "RC2", "3DES", "DES"))) { $critical = true; $retvals[] = "Bad cipher " . $details->cipher . "($ciphersuite)"; }
		if(in_array($details->cipher, array("CAMILLIA", "IDEA", "SEED"))) { $critical = true; $retvals[] = "National cipher " . $details->cipher . "($ciphersuite)"; }
		if($details->cipher == "NULL") { $critical = true; $retvals[] = "Null cipher($ciphersuite)"; }
		if($details->authentication == "NULL") { $critical = true; $retvals[] = "Null Authentication($ciphersuite)"; }
		if($details->bitlength < 128) { $critical = true; $retvals[] = "Weak key($ciphersuite)"; }
		if($details->mac == "MD5") { $critical = true; $retvals[] = "Bad MAC " . $details->mac . "($ciphersuite)"; }
	}
}

$retvals = array_unique($retvals);

$retcode = 0;
if($warning) { $retcode = 1; $retval = "Warning: "; }
if($critical) { $retcode = 2; $retval = "Critical: "; }
$retval .= implode(", ", $retvals);

echo($retval . "\n"); exit($retcode);


function version() {
	global $argv, $TLSSCAN;
	echo($argv[0] . " v0.1 - " . exec($TLSSCAN. " --version") . "\n");
}

function usage() {
	global $argv, $OPENSSL;
	    //12345678901234567890123456789012345678901234567890123456789012345678901234567890
	echo($argv[0] . " [ OPTIONS ] -H host\n");
	echo("\n");
	echo("  Nagios check to scan for SSL/TLS protocols and cipher suites\n");
	echo("\n");
	echo("OPTIONS:\n");
	echo("  -H                 Hostname or IP address\n");
	echo("  -h, --help         This message\n");
	echo("  --no-warn-pfs      Skip warning on missing PFS\n");
	echo("  -p                 Port, defaults to 443\n");
	echo("  -v, --version      Show version information\n");
	echo("\n");
	echo("  Note: Because this program is dependent on OpenSSL its results will vary\n");
	echo("        with the version and capabilities of OpenSSL.\n");
}
