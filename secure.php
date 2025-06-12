<?php
/*
* PHP Data Encryption/Decryption API Endpoint
*
* This API endpoint provides functionality to encrypt and decrypt data
* using AES-256-CBC cipher with OpenSSL functions.
*
* It accepts POST requests with JSON payloads for both encryption and decryption.
*
* Encryption Request:
* Method: POST
* Header: Content-Type: application/json
* Body:   {"data": "your_string_or_array_or_associative_array"}
* Response: {"status": "success", "encrypted_data": "base64_encoded_ciphertext"}
*
* Decryption Request:
* Method: POST
* Header: Content-Type: application/json
* Body:   {"encrypted_data": "base64_encoded_ciphertext"}
* Response: {"status": "success", "decrypted_data": "original_string_or_array_or_associative_array"}
*
* Error Responses: {"status": "error", "message": "Error description"}
*
* @author Akash Debnath
* @copyright 2025 Akash Debnath
* @license MIT http://opensource.org/licenses/MIT
* @version 1.0
* @link https://github.com/akashdebnath-swe/PHP-Data-Encryption-Decryption-API-Endpoint
* @file secure.php
* @created at 2025
*/

// --- Configuration ---
// IMPORTANT: THESE VALUES ARE FOR DEMONSTRATION ONLY.
// IN PRODUCTION, GENERATE A STRONG, RANDOM KEY AND IV.
// STORE THE KEY SECURELY (e.g., environment variables, KMS).
// A fixed IV, while simpler, reduces security if reused with the same key.
define('ENCRYPTION_KEY', 'a_very_strong_and_secret_key_of_32_bytes_for_aes256'); // 32 bytes = 256 bits for AES-256
define('ENCRYPTION_IV', '1234567890123456'); // 16 bytes = 128 bits for AES-256-CBC
define('CIPHER_ALGO', 'aes-256-cbc'); // Recommended cipher algorithm for PHP 5.6+

// Set the content type header to JSON for all responses
header('Content-Type: application/json');

// --- Helper Functions ---

/**
 * Encrypts data using OpenSSL AES-256-CBC.
 * The data is first JSON encoded to handle various types (string, array, object).
 * The encrypted data is then Base64 encoded for safe transmission.
 *
 * @param mixed $data The data to encrypt (string, array, or associative array).
 * @return string|false The Base64 encoded encrypted string, or false on failure.
 */
function encrypt_data($data)
{
    // Step 1: Serialize the input data into a JSON string.
    // This allows us to consistently encrypt strings, arrays, or associative arrays.
    $json_data = json_encode($data);
    if ($json_data === false) {
        // Log JSON encoding error for debugging purposes
        error_log("Encryption Error: JSON encoding failed - " . json_last_error_msg());
        return false;
    }

    // Step 2: Encrypt the JSON string using openssl_encrypt.
    // OPENSSL_RAW_DATA (0) means the output is raw binary.
    // PKCS7 padding is applied by default when flags are 0.
    $encrypted_binary_data = openssl_encrypt(
        $json_data,
        CIPHER_ALGO,
        ENCRYPTION_KEY,
        0, // flags, 0 means default behavior (PKCS7 padding)
        ENCRYPTION_IV
    );

    if ($encrypted_binary_data === false) {
        // Log OpenSSL encryption error
        error_log("Encryption Error: OpenSSL encryption failed. Check key, IV, and cipher algorithm.");
        return false;
    }

    // Step 3: Base64 encode the binary encrypted data.
    // This makes the encrypted string safe for transmission over HTTP (e.g., in JSON).
    return base64_encode($encrypted_binary_data);
}

/**
 * Decrypts data using OpenSSL AES-256-CBC.
 * The input is expected to be a Base64 encoded encrypted string.
 * The decrypted string is then JSON decoded back to its original data type.
 *
 * @param string $encrypted_string_base64 The Base64 encoded encrypted string received from the frontend.
 * @return mixed|false The original data (string, array, or associative array), or false on failure.
 */
function decrypt_data($encrypted_string_base64)
{
    // Step 1: Base64 decode the input string.
    // The 'true' argument ensures strict decoding (returns false for invalid Base64).
    $decoded_binary_data = base64_decode($encrypted_string_base64, true);
    if ($decoded_binary_data === false) {
        // Log Base64 decoding error
        error_log("Decryption Error: Base64 decoding failed. Invalid Base64 string.");
        return false;
    }

    // Step 2: Decrypt the binary data using openssl_decrypt.
    $decrypted_json_data = openssl_decrypt(
        $decoded_binary_data,
        CIPHER_ALGO,
        ENCRYPTION_KEY,
        0, // flags, same as encryption
        ENCRYPTION_IV
    );

    if ($decrypted_json_data === false) {
        // Log OpenSSL decryption error
        error_log("Decryption Error: OpenSSL decryption failed. Check key, IV, cipher, or corrupted data.");
        return false;
    }

    // Step 3: JSON decode the decrypted string.
    // The 'true' argument decodes objects into associative arrays.
    $data = json_decode($decrypted_json_data, true);

    // Check for JSON decoding errors.
    // If json_decode returns null AND there was a JSON error, then it truly failed.
    // If it returns null but no JSON error (e.g., for a plain string like "hello"), then it's a valid string.
    if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
        error_log("Decryption Error: JSON decoding of decrypted data failed - " . json_last_error_msg());
        return false;
    } else if ($data === null && json_last_error() === JSON_ERROR_NONE) {
        // If it was a simple string (not JSON) that was encrypted, json_decode will return null
        // and json_last_error() will be JSON_ERROR_NONE. In this case, return the raw string.
        return $decrypted_json_data;
    }

    // Return the original data (string, array, or associative array)
    return $data;
}

// --- API Endpoint Logic ---

// Check if the request method is POST. This API only supports POST requests.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get the raw POST data from the request body.
    $input_data = file_get_contents("php://input");

    // Decode the JSON input into a PHP associative array.
    $request_payload = json_decode($input_data, true);

    // Check if JSON decoding of the payload failed.
    if ($request_payload === null && json_last_error() !== JSON_ERROR_NONE) {
        http_response_code(400); // Bad Request
        echo json_encode(['status' => 'error', 'message' => 'Invalid JSON input.']);
        exit; // Terminate script execution
    }

    // --- Encryption Endpoint Logic ---
    // If the 'data' field is present in the request payload, perform encryption.
    if (isset($request_payload['data'])) {
        $data_to_encrypt = $request_payload['data'];

        $encrypted_result = encrypt_data($data_to_encrypt);

        if ($encrypted_result !== false) {
            // Return success response with the encrypted data.
            echo json_encode(['status' => 'success', 'encrypted_data' => $encrypted_result]);
        } else {
            // Return error response if encryption failed.
            http_response_code(500); // Internal Server Error
            echo json_encode(['status' => 'error', 'message' => 'Failed to encrypt data. Please check server logs.']);
        }
    }
    // --- Decryption Endpoint Logic ---
    // If the 'encrypted_data' field is present, perform decryption.
    elseif (isset($request_payload['encrypted_data'])) {
        $encrypted_data_to_decrypt = $request_payload['encrypted_data'];

        $decrypted_result = decrypt_data($encrypted_data_to_decrypt);

        if ($decrypted_result !== false) {
            // Return success response with the decrypted data.
            echo json_encode(['status' => 'success', 'decrypted_data' => $decrypted_result]);
        } else {
            // Return error response if decryption failed (e.g., invalid or corrupted input).
            http_response_code(400); // Bad Request (client sent invalid encrypted data)
            echo json_encode(['status' => 'error', 'message' => 'Failed to decrypt data. Invalid or corrupted encrypted data.']);
        }
    }
    // --- Invalid Request Payload ---
    // If neither 'data' nor 'encrypted_data' is found in the POST payload.
    else {
        http_response_code(400); // Bad Request
        echo json_encode(['status' => 'error', 'message' => 'Invalid POST request. Expecting "data" for encryption or "encrypted_data" for decryption.']);
    }
}
// --- Unsupported Request Method ---
// If the request method is not POST.
else {
    http_response_code(405); // Method Not Allowed
    header('Allow: POST'); // Inform the client which methods are allowed
    echo json_encode(['status' => 'error', 'message' => 'Method Not Allowed. Only POST requests are supported for this API.']);
}
