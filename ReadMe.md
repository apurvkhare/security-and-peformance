# Security and performance in NodeJS

## Difference between encoding, encryption and hashing

### Encoding

**Definition**: Encoding is the process of converting data from one format to another for various purposes, such as data transmission or storage. Unlike encryption and hashing, encoding is not meant for security but rather for data representation.

**Characteristics**:
- **Reversible**: Encoded data can be easily converted back to its original format.
- **No Security**: Encoding does not provide confidentiality or integrity; it is simply a way to represent data.
- **Use Cases**: Data transmission (e.g., Base64), data storage, and compatibility with different systems.

**Example**:
```javascript
// Function to encode data to Base64
function encode(text) {
    return Buffer.from(text).toString('base64'); // Encode to Base64
}

// Function to decode data from Base64
function decode(encodedText) {
    return Buffer.from(encodedText, 'base64').toString('utf8'); // Decode from Base64
}

// Example usage
const originalText = "Hello, World!";
const encodedText = encode(originalText);
const decodedText = decode(encodedText);
console.log("Encoded:", encodedText);
console.log("Decoded:", decodedText);
```

### Encryption

**Definition**: Encryption is the process of converting plaintext into ciphertext using an algorithm and a key. The main purpose of encryption is to ensure confidentiality, allowing only authorized parties to access the original data.

**Characteristics**:
- **Reversible**: Encrypted data can be decrypted back to its original form using the correct key.
- **Key-based**: Requires a key for both encryption and decryption.
- **Use Cases**: Secure communication, data protection, etc.

**Example**:
```javascript
const crypto = require('crypto');

// Function to encrypt data
function encrypt(text, key) {
    const iv = crypto.randomBytes(16); // Initialization vector
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted; // Return IV and encrypted data
}

// Example usage
const key = crypto.randomBytes(32); // Generate a random key
const originalText = "Hello, World!";
const encryptedText = encrypt(originalText, key);
console.log("Encrypted:", encryptedText);
```

### Hashing

**Definition**: Hashing is the process of converting data into a fixed-size string of characters, which is typically a digest that represents the original data. Hashing is a one-way function, meaning it cannot be reversed to retrieve the original data.

**Characteristics**:
- **Irreversible**: Once data is hashed, it cannot be converted back to its original form.
- **Deterministic**: The same input will always produce the same hash output.
- **Use Cases**: Data integrity verification, password storage, etc.

**Example**:
```javascript
const crypto = require('crypto');

// Function to hash data
function hash(text) {
    return crypto.createHash('sha256').update(text).digest('hex'); // SHA-256 hash
}

// Example usage
const originalText = "Hello, World!";
const hashedText = hash(originalText);
console.log("Hashed:", hashedText);
```

### Summary of Differences

| Feature         | Encryption                          | Hashing                          | Encoding                          |
|------------------|-------------------------------------|----------------------------------|-----------------------------------|
| Purpose          | Confidentiality                     | Data integrity                   | Data representation               |
| Reversibility    | Reversible (with key)              | Irreversible                     | Reversible                        |
| Output Size      | Variable (depends on algorithm)     | Fixed size                       | Variable (depends on encoding)    |
| Key Requirement  | Requires a key                      | No key required                  | No key required                   |
| Security         | Provides confidentiality            | Provides integrity                | No security                       |
| Use Cases        | Secure data transmission            | Password storage, data integrity | Data transmission, storage        |

### Summary

- **Encryption** is used to protect data confidentiality and requires a key for both encryption and decryption.
- **Hashing** is used to verify data integrity and is irreversible, meaning you cannot retrieve the original data from the hash.
- **Encoding** is used to convert data into a different format for compatibility or transmission purposes and is easily reversible.

Each of these techniques serves a different purpose in data handling and security, and understanding their differences is crucial for implementing the right solution in various scenarios.

## Common securtiy risks

### Cross-Site Request Forgery (CSRF) Attack Explained

**Definition**: Cross-Site Request Forgery (CSRF) is a type of attack that tricks a user into executing unwanted actions on a web application in which they are currently authenticated. This can lead to unauthorized actions being performed on behalf of the user without their consent.

### How CSRF Works

1. **User Authentication**: The user logs into a web application (e.g., a banking site) and receives an authentication token (usually stored in cookies).

2. **Malicious Website**: The user visits a malicious website while still logged into the target application. This malicious site can contain scripts or forms that make requests to the target application.

3. **Unwanted Request**: The malicious site sends a request to the target application using the user's credentials (e.g., cookies). Since the user is authenticated, the application processes the request as if it were a legitimate action initiated by the user.

4. **Consequences**: The target application performs the action (e.g., transferring funds, changing account settings) without the user's knowledge, leading to potential data loss or unauthorized transactions.

### Example Scenario

1. **User Logs In**: Alice logs into her online banking account, which sets a session cookie in her browser.

2. **Visiting a Malicious Site**: While still logged in, Alice visits a malicious website that contains the following HTML form:
   ```html
   <form action="https://bank.com/transfer" method="POST">
       <input type="hidden" name="amount" value="1000">
       <input type="hidden" name="to" value="attacker_account">
   </form>
   <script>
       document.forms[0].submit();
   </script>
   ```

3. **Automatic Submission**: The script automatically submits the form, sending a request to the bank's server to transfer $1000 to the attacker's account.

4. **Bank Processes the Request**: Since Alice is still logged in, the bank processes the request as if it were initiated by her, resulting in the transfer being completed without her consent.

### Why CSRF is Dangerous

- **User Trust**: Users often trust their browsers and the sites they visit. They may not realize that a malicious site can exploit their authenticated session.
- **Lack of User Awareness**: Users may not be aware that they are performing actions they did not intend to.
- **Impact on Sensitive Actions**: CSRF can be particularly damaging when it targets sensitive actions, such as fund transfers, changing passwords, or modifying account settings.

### Preventing CSRF Attacks

1. **CSRF Tokens**: Implement anti-CSRF tokens. Each form submission should include a unique token that is validated by the server. If the token is missing or invalid, the request is rejected.

   Example:
   ```html
   <form action="/transfer" method="POST">
       <input type="hidden" name="csrf_token" value="unique_token_here">
       <input type="hidden" name="amount" value="1000">
       <input type="hidden" name="to" value="attacker_account">
   </form>
   ```

2. **SameSite Cookies**: Use the `SameSite` attribute for cookies to restrict how cookies are sent with cross-origin requests. This can help mitigate CSRF attacks.

   Example:
   ```javascript
   res.cookie('session_id', 'your_session_id', { sameSite: 'Strict' });
   ```

3. **Check Referer Header**: Validate the `Referer` header to ensure that requests are coming from trusted sources. However, this method can be bypassed and is not foolproof.

4. **User Interaction**: Require user interaction for sensitive actions (e.g., re-entering a password for fund transfers).

### Conclusion

CSRF is a significant security vulnerability that can lead to unauthorized actions being performed on behalf of authenticated users. Understanding how CSRF works and implementing preventive measures is crucial for securing web applications and protecting users from potential attacks.

### Preventing DDoS Attacks

1. Rate Limiting: Limits each IP to 10 requests per second
2. Security Headers: Uses helmet to add various security headers
3. Payload Size Limiting: Prevents large payload attacks
4. Request Timeout: Prevents long-running request attacks

```js
const express = require('express');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const helmet = require('helmet');

const app = express();

// Enable various HTTP security headers using helmet
app.use(helmet());

// Configure rate limiter
const rateLimiter = new RateLimiterMemory({
    points: 10, // Number of requests
    duration: 1, // Per second
    blockDuration: 60 // Block for 1 minute if exceeded
});

// Middleware to handle rate limiting
const rateLimiterMiddleware = async (req, res, next) => {
    try {
        // Use IP address as key
        const key = req.ip;
        await rateLimiter.consume(key);
        next();
    } catch (err) {
        res.status(429).json({
            error: 'Too Many Requests',
            message: 'Please try again later'
        });
    }
};

// Apply rate limiting to all routes
app.use(rateLimiterMiddleware);

// Additional DDoS prevention middleware
app.use((req, res, next) => {
    // Limit payload size
    const contentLength = parseInt(req.headers['content-length'] || 0);
    if (contentLength > 1024 * 1024) { // 1MB limit
        return res.status(413).json({
            error: 'Payload Too Large',
            message: 'Request entity too large'
        });
    }

    // Add request timeout
    req.setTimeout(5000, () => {
        res.status(408).json({
            error: 'Request Timeout',
            message: 'Request took too long to process'
        });
    });

    next();
});

// Example protected route
app.get('/', (req, res) => {
    res.json({ message: 'Hello, protected world!' });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'Internal Server Error',
        message: 'Something went wrong'
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
```

#### Additional recommendations for DDoS protection:

1. Use a reverse proxy like Nginx
2. Implement caching when possible
3. Use a CDN service
4. Consider cloud-based DDoS protection services (like Cloudflare)
5. Monitor your traffic patterns
6. Keep your Node.js and packages updated


### Oauth 2 and OpenID Connect

```
OAuth 2.0 (Authorization Flow)
-----------------------------

+----------+                                  +---------------+
|          |         1. Auth Request         |               |
|  Client  |-------------------------------->| Authorization |
|          |                                 |    Server     |
|          |         2. Auth Code            |               |
|          |<--------------------------------|               |
|          |                                 |               |
|          | 3. Auth Code + Client Secret    |               |
|          |-------------------------------->|               |
|          |                                 |               |
|          |         4. Access Token         |               |
|          |<--------------------------------|               |
+----------+                                 +---------------+
     |                                              
     |                                      +---------------+
     |           5. Access Token            |   Resource    |
     +------------------------------------>|    Server     |
     |                                     |               |
     |           6. Resource               |               |
     |<------------------------------------+               |
     |                                     +---------------+

OpenID Connect (Authentication Flow)
----------------------------------

+----------+                                  +---------------+
|          | 1. Auth Request + scope=openid   |    OpenID     |
|  Client  |--------------------------------->|   Provider    |
|          |                                  |               |
|          |         2. Auth Code             |               |
|          |<---------------------------------|               |
|          |                                  |               |
|          | 3. Auth Code + Client Secret     |               |
|          |--------------------------------->|               |
|          |                                  |               |
|          | 4. ID Token + Access Token       |               |
|          |<---------------------------------|               |
+----------+                                  +---------------+
     |
     |         5. ID Token Used for Authentication
     |
     v
+---------------+
|   Identity    |
|   Verified    |
+---------------+

Key Differences:
---------------
OAuth 2.0:
- Focus on Authorization (what you can access)
- Returns Access Token
- Used for API access

OpenID Connect:
- Focus on Authentication (who you are)
- Returns ID Token + Access Token
- Used for user identity
- Built on top of OAuth 2.0
```