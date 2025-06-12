## PHP Data Encryption/Decryption API Endpoint
A simple, flexible, and powerful PHP API endpoint designed to encrypt and decrypt various data types (strings, arrays, and associative arrays) using AES-256-CBC with OpenSSL.

### 🚀 Features
- **Data Encryption**: Encrypts any given string, array, or associative array into a Base64-encoded ciphertext ("hashcode string").
- **Data Decryption**: Decrypts the Base64-encoded ciphertext back to its original data type.
- **JSON Support**: Handles data serialization and deserialization using JSON, ensuring compatibility with various data structures.
- **Secure Cipher**: Utilizes `AES-256-CBC` via PHP's `openssl_encrypt` and `openssl_decrypt` functions, suitable for PHP 5.6.40.
- **Error Handling**: Provides clear JSON responses for success and various error scenarios.

### 📋 Requirements
- **PHP 5.6.40** (or a compatible version with `openssl` extension enabled)
- **OpenSSL Extension** for PHP

### ⚙️ Installation & Setup
1. **Save the File**: Save the provided PHP code (e.g., `secure.php`) to your web server's document root or a subfolder.
2. **Web Server Configuration**: Ensure your web server (Apache, Nginx, etc.) is configured to serve PHP files.
3. **OpenSSL Extension**: Make sure the `php_openssl` extension is enabled in your `php.ini` file. You can usually find this line:

```
extension=php_openssl.dll  ; for Windows
extension=openssl.so     ; for Linux/Unix
```
Uncomment it if it's commented out, then restart your web server.

### 💡 Usage
The API is accessed via `POST` requests.

**Encryption Endpoint**
- **URL**: `http://yourdomain.com/path/to/secure.php`
- **Method**: `POST`
- **Headers**: `Content-Type: application/json`
- **Request Body (JSON)**:
```
{
    "data": "your_string_or_array_or_associative_array_to_encrypt"
}
```

#### Encryption Examples:
**Encrypting a String**:

**Request**:
```
{
    "data": "This is a secret message."
}
```
**Response (Success)**:
```
{
    "status": "success",
    "encrypted_data": "RmZadWwzK2o1c21QWlF2OTh2bXJldz09"
}
```
**Encrypting an Array**:

**Request**:
```
{
    "data": ["item1", "item2", "item3"]
}
```
**Response (Success)***:
```
{
    "status": "success",
    "encrypted_data": "Q2h6dERJdEtUWG8ycUZ0NmtIeHpxWmc9PQ=="
}
```
**Encrypting an Associative Array (Object)**:

**Request**:
```
{
    "data": {
        "user_id": 123,
        "username": "testuser",
        "email": "test@example.com"
    }
}
```
**Response (Success)**:
```
{
    "status": "success",
    "encrypted_data": "T050OWdEa2VnNDR2d0l0ajl3aW5jNXVWdGFnU0Q4R0h2SW95Z2p3ZW40c3c5eT09"
}
```
**Decryption Endpoint**
- **URL**: `http://yourdomain.com/path/to/secure.php`
- **Method**: `POST`
- **Headers**: `Content-Type: application/json`
- **Request Body (JSON)**:
```
{
    "encrypted_data": "the_base64_encoded_ciphertext_from_encryption"
}
```
**Decryption Example**:
Using the `encrypted_data` from the string encryption example (`RmZadWwzK2o1c21QWlF2OTh2bXJldz09`):

**Request**:
```
{
    "encrypted_data": "RmZadWwzK2o1c21QWlF2OTh2bXJldz09"
}
```
**Response (Success)**:
```
{
    "status": "success",
    "decrypted_data": "This is a secret message."
}
```
### 🔒 Security Considerations (VERY IMPORTANT)
- **Encryption Key & IV Management**: The `ENCRYPTION_KEY` and `ENCRYPTION_IV` are hardcoded in the provided example for simplicity. **In a production environment, you MUST NEVER hardcode these values**.
  1. **Key**: Generate a strong, random 32-byte (256-bit) key. Store it securely outside your codebase (e.g., in environment variables, a hardware security module (HSM), or a dedicated key management service (KMS)).
  2. **IV (Initialization Vector)**: For `AES-256-CBC`, a unique 16-byte (128-bit) IV should ideally be generated for each encryption. This IV does not need to be secret and can be safely transmitted alongside the ciphertext (e.g., prepended to the encrypted data). Using a fixed IV, as in the example, is less secure if the same key is reused multiple times.
- **HTTPS**: Always use HTTPS for all API communication. This protects your data during transit from eavesdropping and tampering. Without HTTPS, even encrypted data can reveal patterns or be vulnerable to traffic analysis.
- **Input Validation**: While the API handles data types, always perform robust input validation on the frontend and backend to prevent malicious data from being processed or injected.
- **Error Logging**: The code includes `error_log` calls. Ensure your PHP error logging is properly configured to capture these messages for debugging and security monitoring.

### 🙏 Contributing
Contributions are welcome! If you find a bug or have an idea for an improvement, please open an issue or submit a pull request.

### 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
