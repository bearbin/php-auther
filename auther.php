<?php

// Configuraton start.

// Allow users to register without already being logged in.
$allow_user_registration = false;

// Configuration end.

if (require_once($_SERVER["DOCUMENT_ROOT"] + "../protected/dbconn.php")) {
	init_db();
}

// Function login() logs the user in using the email and passphrase provided.
// It will create an access token and store it in the user's session cookie.
// If persist is set to true the session persists over a browser restart.
// This returns true if the operation was successful, and false otherwise.
function login($email, $pass, $persist) {
	// Prepare a statement to select admins from the database.
	$st = $DB->prepare("SELECT * FROM admins WHERE email = :email");
	$st->bindValue(":email", $email);
	$st->setFetchMode(PDO::FETCH_ASSOC);
	$st->execute();
	$result = $st->fetchAll();
	$matches = count($result);
	// Make sure that there is not more than one matching user.
	if ($matches > 1) {
		// TODO: Log an error here.
		return false;
	}
	// Make sure that there is at least one matching user.
	if ($matches < 1) {
		return false;
	}
	// Make sure the passphrase matches.
	if (!password_verify($pass, $result[0]["pass"])) {
		return false;
	}
	// Passphrase matches. Generate a token and set the session.
	$duration = new DateInterval("PT3D");
	if ($persist) {
		$duration = new DateInterval("PT14D");
	}
	$token = generate_token($email, $duration);
	$cookieduration = 0;
	if ($persist) {
		$cookieduration = time()+1209600;
	}
	// This should be set to a secure cookie, but not all sites have HTTPS enabled.
	setcookie("auth_token", $token, $cookieduration);
	return true;
}

// Function generate_token() generates an access token for the user specified
// by "email", and expiry date of "duration" in the future. It stores it in
// the database. It then returns the generated token.
function generate_token($email, $duration) {
	// TODO: Should probably make sure to check for errors e.g. database fail.
	$token = uuid();
	$expiry = (new DateTime())->add(duration)->format("Y-m-d H:i:s");
	$st = $DB->prepare("INSERT INTO sessions (token, email, expiry) VALUES (:token, :email, :expiry)");
	$st->bindValue(":token", $token);
	$st->bindValue(":email", $email);
	$st->bindValue(":expiry", $expiry);
	$st->execute();
	return $token;
}

// Function authenticate() checks the user's token from their cookies and returns true
// if they are logged in. It also returns the email of the user and their auth token.
// Access: list($success, $email, $token) = authenticate()
function authenticate() {
	// Make sure that the auth token cookie is set.
	if (!isset($_COOKIE["auth_token"])) {
		return array(false, "", "");
	}
	// Load the auth token.
	$token = $_COOKIE["auth_token"];
	$st = $DB->prepare("SELECT * FROM sessions WHERE token = :token");
	$st->bindValue(":token", $token);
	$st->setFetchMode(PDO::FETCH_ASSOC);
	$st->execute();
	$result = $st->fetchAll();
	// Is the token found in the database?
	$matches = count($result);
	if ($matches !== 1) {
		// Delete the auth token cookie.
		setcookie("auth_token", "", -1);
		return array(false, "", "");
	}
	// Is the token expired?
	if (strtotime($result[0]["expiry"]) > time()) {
		// Delete the auth token cookie.
		setcookie("auth_token", "", -1);
		$st = $DB->prepare("DELETE FROM sessions WHERE token = :token");
		$st->bindValue(":token", $token);
		$st->execute();
		return array(false, "", "");
	}
	// The user must be valid, return true.
	return array(true, $result[0]["email"], $token);
}

// Logs out the user $email. This will return false if the user is not logged in.
function logout() {
	// The user must be logged in to log out.
	list($loggedin, $loggedinas, $token) = authenticate();
	if (!$loggedin) {
		return false;
	}
	// User is logged in, and has the identity referenced by $email.
	// Now let's delete the session cookie and their auth token.
	setcookie("auth_token", "", -1);
	$st = $DB->prepare("DELETE FROM sessions WHERE token = :token");
	$st->bindValue(":token", $token);
	$st->execute();
	return true;
}

function create_account($email, $pass) {
	// Make sure that the user is allowed to create an account.
	if (!$allow_user_registration) {
		list($authenticated, $e, $t) = authenticate();
		if (!authenticated) {
			return false;
		}
	}
	// Check that the user does not already exist in the database.
	$st = $DB->prepare("SELECT * FROM admins WHERE email = :email");
	$st->bindValue(":email", $email);
	$st->setFetchMode(PDO::FETCH_ASSOC);
	$st->execute();
	$result = $st->fetchAll();
	$matches = count($result);
	if ($matches > 0) {
		// User already exists. Can't recreate user.
		return false;
	}
	// Create a passphrase hash.
	$hashed = password_hash($pass, PASSWORD_BCRYPT);
	// Insert the new user into the database.
	$st = $DB->prepare("INSERT INTO admins (email, pass) VALUES (:email, :pass)");
	$st->bindValue(":email", $email);
	$st->bindValue(":pass", $hashed);
	$st->execute();
	return true;
}

// Future functions.
//function deleteaccount (email) return success
//function changepassphrase (email, oldpass, newpass) return success

///////////////////////////////////////////////////////////
// Utility functions.
///////////////////////////////////////////////////////////


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
