# 0.9.2
July 13, 2023

Switch to BCrypt for the default API key hash algorithm.
* Support for SHA256, SHA512, BCrypt, and PBKDF2 with 100K iterations.
* Switched from Base64 encoding to Base58, and replaced the colon separator with an underscore. Using
this approach, no un-copyable characters appear in an API key.  This should lead to users being able
to double click an API key and copy it easily.
* Added many more tests.

# 0.9.1
July 13, 2023

First release to NuGet; still in development.
