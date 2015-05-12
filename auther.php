<?php

require_once("../protected/uuid.php");

if require_once("../protected/dbconn.php") {
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
	if (!password_verify(pass, $result[0]["pass"]) {
		return false;
	}
	// Passphrase matches. Generate a token and set the session.
	return true;
}

// Function generate_token() generates an access token for the user specified
// by "email", and expiry date of "duration" in the future. It stores it in 
// the database. It then returns the generated token.
function generate_token(email, duration) {
	// TODO: Should probably make sure to check for errors e.g. database fail.
	$token = uuid();
	$expiry = DateTime()->add(duration)
	$st = $DB->prepare("INSERT INTO sessions VALUES (:token, :email, :expiry);
	$st->bindValue(":token", $token);
	$st->bindValue(":email", $email);
	$st->bindValue(":expiry", $expiry");
	$st ->setFetchMode(PDO::FETCH_ASSOC);
}

function authenticate () return success, email

function logout (email) return success

?>
