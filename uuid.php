<?php

// Function uuid returns a v4 uuid with dash seperation.
function uuid()
{
	$seed = openssl_random_pseudo_bytes(16);

	// Set the version bits to identify the UUID as a v4.
	$seed[6] = chr(ord($seed[6]) & 0x0f | 0x40);
	$seed[8] = chr(ord($seed[8]) & 0x3f | 0x80);

	return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

?>
