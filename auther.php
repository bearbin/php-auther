<?php

// Configuraton start.

// Allow users to register without already being logged in.
$allow_user_registration = true;

// Configuration end.

// Require the libraries.
require_once "/home/protected/dbconn.php";
require_once "/home/protected/uuid.php";

// Function login() logs the user in using the email and passphrase provided.
// It will create an access token and store it in the user's session cookie.
// If persist is set to true the session persists over a browser restart.
// This returns true if the operation was successful, and false otherwise.
function login($email, $pass, $persist) {
	global $DB;
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
	// Set duration to 3 days if persistence is not enabled.
	$duration = 259200;
	if ($persist) {
		// Otherwise set the duration to 14 days.
		$duration = 1209600;
	}
	$token = generate_token($email, $duration);
	$cookieduration = 0;
	if ($persist) {
		$cookieduration = time() + $duration;
	}
	// This should be set to a secure cookie, but not all sites have HTTPS enabled.
	echo $token;
	setcookie("auth_token", $token, $cookieduration);
	return true;
}

// Function generate_token() generates an access token for the user specified
// by "email", and expiry date of "duration" in the future. It stores it in
// the database. It then returns the generated token.
function generate_token($email, $duration) {
	global $DB;
	// TODO: Should probably make sure to check for errors e.g. database fail.
	$token = uuid();
	$expiry = date("Y-m-d H:i:s", time() + $duration);
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
	global $DB;
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
	if (strtotime($result[0]["expiry"]) < time()) {
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
	global $DB;
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
	global $DB;
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

?>
