<?php
// login.php - Handles user login by verifying credentials against a database.

// Set headers for CORS
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *'); // IMPORTANT: Restrict this in production!
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Check if the request method is POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Decode the JSON input from the frontend
    $input = json_decode(file_get_contents('php://input'), true);

    // Get identifier and password from the input
    $identifier = $input['identifier'] ?? '';
    $password = $input['password'] ?? '';

    // Basic server-side validation
    if (empty($identifier) || empty($password)) {
        echo json_encode(['success' => false, 'message' => 'Identifier and password are required.']);
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
        error_log("Database connection failed: " . $conn->connect_error);
        echo json_encode(['success' => false, 'message' => 'Database connection error. Please try again later.']);
        exit();
    }

    // Prepare SQL statement to retrieve user by identifier
    $stmt = $conn->prepare("SELECT id, password FROM users WHERE identifier = ?");
    $stmt->bind_param("s", $identifier);
    $stmt->execute();
    $stmt->store_result();
    $stmt->bind_result($user_id, $hashed_password_from_db);

    if ($stmt->num_rows === 1) {
        $stmt->fetch();
        // Verify the provided password against the hashed password from the database
        if (password_verify($password, $hashed_password_from_db)) {
            // Login successful
            // In a real application, you would create a session, issue a token, etc.
            echo json_encode(['success' => true, 'message' => 'Login successful!', 'user_id' => $user_id]);
        } else {
            // Password does not match
            echo json_encode(['success' => false, 'message' => 'Invalid credentials.']);
        }
    } else {
        // User not found
        echo json_encode(['success' => false, 'message' => 'Invalid credentials.']);
    }

    $stmt->close();
    $conn->close(); // Close database connection
} else {
    // If not a POST request, return an error
    echo json_encode(['success' => false, 'message' => 'Invalid request method.']);
}
?>
