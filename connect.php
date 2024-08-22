<?php
session_start();

// Database connection details
$servername = "localhost";
$username = "your_db_username";
$password = "your_db_password";
$dbname = "your_database_name";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Get form data
$form_username = $_POST['username'];
$form_password = $_POST['password'];

// Prevent SQL injection
$form_username = $conn->real_escape_string($form_username);
$form_password = $conn->real_escape_string($form_password);

// Query to check if the user exists
$sql = "SELECT * FROM users WHERE username='$form_username'";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    // User found, now check the password
    $user = $result->fetch_assoc();
    
    // Assuming passwords are hashed in the database
    if (password_verify($form_password, $user['password'])) {
        // Password matches, login successful
        $_SESSION['username'] = $user['username'];
        header("Location: welcome.php"); // Redirect to a welcome page
        exit();
    } else {
        echo "Invalid password.";
    }
} else {
    echo "No user found with that username.";
}

$conn->close();
?>
