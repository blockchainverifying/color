<?php
// register.php - Handles user registration by saving data to a database.

// Set headers for CORS (Cross-Origin Resource Sharing)
// IMPORTANT: In a production environment, replace '*' with the specific origin(s) of your frontend application
// to prevent security vulnerabilities.
header('Content-Type: application/json'); // Respond with JSON format
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS'); // Allow POST requests for registration
header('Access-Control-Allow-Headers: Content-Type, Authorization'); // Allow specific headers

// Handle preflight OPTIONS request (sent by browsers for CORS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Check if the request method is POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Decode the JSON input from the frontend
    $input = json_decode(file_get_contents('php://input'), true);

    // Get identifier (email/phone) and password from the input
    $identifier = $input['identifier'] ?? '';
    $password = $input['password'] ?? '';

    // Basic server-side validation (more robust validation should be done)
    if (empty($identifier) || empty($password)) {
        echo json_encode(['success' => false, 'message' => 'Identifier and password are required.']);
        exit();
    }
    if (strlen($password) < 6) {
        echo json_encode(['success' => false, 'message' => 'Password must be at least 6 characters.']);
        exit();
    }

    // --- Database Connection (Replace with your actual database credentials) ---
    $servername = "localhost"; // e.g., 'localhost' or your database host
    $username = "root";        // e.g., 'root' or your database username
    $db_password = "";         // e.g., 'your_db_password' or your database password
    $dbname = "user_auth_db";  // e.g., 'user_auth_db' or your database name

    // Create database connection
    $conn = new mysqli($servername, $username, $db_password, $dbname);

    // Check connection
    if ($conn->connect_error) {
        // Log the error for debugging, but don't expose sensitive info to the user
        error_log("Database connection failed: " . $conn->connect_error);
        echo json_encode(['success' => false, 'message' => 'Database connection error. Please try again later.']);
        exit();
    }

    // Hash the password securely before storing it in the database
    // ALWAYS use password_hash() for hashing passwords in production
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Prepare SQL statement to prevent SQL injection
    // Check if user already exists
    $stmt_check = $conn->prepare("SELECT id FROM users WHERE identifier = ?");
    $stmt_check->bind_param("s", $identifier);
    $stmt_check->execute();
    $stmt_check->store_result();

    if ($stmt_check->num_rows > 0) {
        // User already exists
        echo json_encode(['success' => false, 'message' => 'User with this identifier already exists.']);
    } else {
        // Insert new user into the database
        $stmt_insert = $conn->prepare("INSERT INTO users (identifier, password) VALUES (?, ?)");
        $stmt_insert->bind_param("ss", $identifier, $hashed_password);

        if ($stmt_insert->execute()) {
            echo json_encode(['success' => true, 'message' => 'Registration successful!']);
        } else {
            // Log the error for debugging
            error_log("Registration failed: " . $stmt_insert->error);
            echo json_encode(['success' => false, 'message' => 'Registration failed. Please try again.']);
        }
        $stmt_insert->close();
    }

    $stmt_check->close();
    $conn->close(); // Close database connection
} else {
    // If not a POST request, return an error
    echo json_encode(['success' => false, 'message' => 'Invalid request method.']);
}
?>
