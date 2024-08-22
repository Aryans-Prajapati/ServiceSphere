<?php
// Database credentials
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "servicesphere";

// Create a connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Debugging: Check if POST data is received
if (empty($_POST)) {
    die("Error: No data received.");
}

if (!isset($_POST['email']) || !isset($_POST['password'])) {
    die("Error: Email and password fields are required.");
}

// Get and sanitize form data
$email = trim($_POST['email']);
$password = trim($_POST['password']);

// Prepare and bind
$stmt = $conn->prepare("SELECT password FROM signup WHERE email = ?");
if ($stmt === false) {
    die("Prepare failed: " . $conn->error);
}

$stmt->bind_param("s", $email);

// Execute the statement
$stmt->execute();
$stmt->store_result();
if ($stmt->error) {
    die("Execute failed: " . $stmt->error);
}

// Check if user exists
if ($stmt->num_rows > 0) {
    // Bind the result to the hashed_password variable
    $stmt->bind_result($hashed_password);
    $stmt->fetch();

    // Verify the password
    if (password_verify($password, $hashed_password)) {
        // Successful login
        echo "Login successful!";
        // Redirect to another page (e.g., dashboard)
        header("Location: index.html");
        exit();
    } else {
        // Failed login
        echo "Invalid email or password.";
    }
} else {
    // User not found
    echo "Invalid email or password.";
}

// Close statement and connection
$stmt->close();
$conn->close();
?>
