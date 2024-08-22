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

// Sanitize and get form data
$firstName = $conn->real_escape_string(trim($_POST['firstname']));
$lastName = $conn->real_escape_string(trim($_POST['lastname']));
$mobileNo = $conn->real_escape_string(trim($_POST['mobileNo']));
$email = $conn->real_escape_string(trim($_POST['email']));
$address = $conn->real_escape_string(trim($_POST['address']));
$password = trim($_POST['password']);

// Hash the password
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

// Check if email already exists
$stmt = $conn->prepare("SELECT COUNT(*) FROM signup WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$stmt->bind_result($count);
$stmt->fetch();
$stmt->close();

if ($count > 0) {
    echo "Error: Email is already registered.";
} else {
    // Insert new user
    $stmt = $conn->prepare("INSERT INTO signup (firstname, lastname, mobileNo, email, address, password) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("ssssss", $firstName, $lastName, $mobileNo, $email, $address, $hashedPassword);

    if ($stmt->execute()) {
        // Redirect after successful registration
        header("Location: index.html");
        exit();
    } else {
        echo "Error: " . $stmt->error;
    }

    $stmt->close();
}


if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Retrieve form data
    $firstname = htmlspecialchars($_POST['firstname']);
    $lastname = htmlspecialchars($_POST['lastname']);
    $mobileNo = htmlspecialchars($_POST['mobileNo']);
    $email = htmlspecialchars($_POST['email']);
    $address = htmlspecialchars($_POST['address']);
    $password = htmlspecialchars($_POST['password']);
    $confirmPassword = htmlspecialchars($_POST['confirmPassword']);

    // Validate that passwords match
    if ($password !== $confirmPassword) {
        echo "Passwords do not match.";
        exit;
    }

    // Create the HTML content to be saved
    $content = "
    <div>
        <h2>User Information</h2>
        <p><strong>First Name:</strong> $firstname</p>
        <p><strong>Last Name:</strong> $lastname</p>
        <p><strong>Mobile No:</strong> $mobileNo</p>
        <p><strong>Email:</strong> $email</p>
        <p><strong>Address:</strong> $address</p>
    </div>
    <hr>";

    // Define the file where the data will be stored
    $file = 'account.html';

    // Append the content to the file
    file_put_contents($file, $content, FILE_APPEND);

    // Provide feedback to the user
    echo "Registration successful! Your information has been stored.";
}
?>


// Close connection
$conn->close();
?>
