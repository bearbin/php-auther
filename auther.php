<?php

require_once("../protected/uuid.php");

if (require_once("../protected/dbconn.php")) {
	init_db();
}

// Function login() logs the user in using the email and passphrase provided.
// It will create an access token and store it in the user's session cookie.
// If persist is set to true the session persists over a browser restart.
// This returns true if the operation was successful, and false otherwise.
function login(email, pass, persist) {
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
	if (!password_verify($pass, $result[0]["pass"]) {
		return false;
	}
	// Passphrase matches. Generate a token and set the session.
	$duration = new DateInterval("PT3D")
	if ($persist) {
		$duration = new DateInterval("PT14D")
	}
	$token = generate_token($email, $duration);
	$cookieduration = 0;
	if ($persist) {
		$cookieduration = time()+1209600;
	}
	// This should be set to a secure cookie, but not all sites have HTTPS enabled.
	setcookie("auth_token", $token, $cookieduration)
	return true;
}

// Function generate_token() generates an access token for the user specified
// by "email", and expiry date of "duration" in the future. It stores it in 
// the database. It then returns the generated token.
function generate_token(email, duration) {
	// TODO: Should probably make sure to check for errors e.g. database fail.
	$token = uuid();
	$expiry = new DateTime()->add(duration)->format("Y-m-d H:i:s");
	$st = $DB->prepare("INSERT INTO sessions (token, email, expiry) VALUES (:token, :email, :expiry)");
	$st->bindValue(":token", $token);
	$st->bindValue(":email", $email);
	$st->bindValue(":expiry", $expiry);
	$st->execute();
	return $token;
}

// Function authenticate() checks the user's token from their cookies and returns true
// if they are logged in. It also returns the email of the user.
// Access: list($success, $email) = authenticate()
function authenticate() {
	// Make sure that the auth token cookie is set.
	if (!isset($_COOKIE["auth_token"])) {
		return array(false, "");
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
		return array(false, "");
	}
	// Is the token expired?
	if (strtotime($result[0]["expiry"] > time())) {
		// Delete the auth token cookie.
		setcookie("auth_token", "", -1);
		$st = $DB->prepare("DELETE FROM sessions WHERE token = :token");
		$st->bindValue(":token", $token);
		$st->execute();
		return array(false, "");
	}
	// The user must be valid, return true.
	return array(true, $result[0]["email"]);
}

function logout (email) return success

function createaccount (email, pass) return success

function deleteaccount (email) return success

?>
