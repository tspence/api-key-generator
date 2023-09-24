# 0.9.5
September 24, 2023

Support NetStandard 2.0; remove dependency on SimpleBase.

# 0.9.4
September 21, 2023

Update library to avoid usage of nuspec files.
Refactoring to address some SonarCloud reported items.

# 0.9.3
July 14, 2023

Switch default algorithm to PBKDF2 with 100K iterations as specified by NIST 800-63B section 5.1.1.2.

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
