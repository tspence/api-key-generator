[![Nuget](https://img.shields.io/nuget/v/ApiKeyGenerator)](https://www.nuget.org/packages/ApiKeyGenerator)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/tspence/api-key-generator/dotnet.yml?branch=main)](https://github.com/tspence/api-key-generator/)
[![SonarCloud Coverage](https://sonarcloud.io/api/project_badges/measure?project=tspence_api-key-generator&metric=coverage)](https://sonarcloud.io/summary/overall?id=tspence_api-key-generator)
[![SonarCloud Bugs](https://sonarcloud.io/api/project_badges/measure?project=tspence_api-key-generator&metric=bugs)](https://sonarcloud.io/summary/overall?id=tspence_api-key-generator)
[![SonarCloud Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=tspence_api-key-generator&metric=vulnerabilities)](https://sonarcloud.io/summary/overall?id=tspence_api-key-generator)

# API Key Generator

A DotNet library for generating and validating API keys.  Although there are lots of libraries out there that help you
implement API key logic using middleware, this library attempts to isolate exactly the code that does API key generation
and validation using relatively safe practices.

The goal of this library is to strike the right balance between usability and reliability.

This library implements encryption of API keys as follows:
* The default algorithm uses BCrypt on key + salt.
* Hashing algorithms available include SHA256, SHA512, BCrypt, and PBKDF with 100k iterations.
* Key and salt length is configurable, defaulting to 512 bits / 64 bytes of randomness. 

The library is intended to support future generations of algorithms while still being compatible with previously
generated API keys.

For usability, this library works on a few basic principles:
* API key validation should be able to give clear error messages if the key is malformed.
* API keys are encoded with Base58 so they can be double-clicked to select the entire key.
* An API key is in the form `<prefix><key ID>_<client secret><suffix>`.
* The prefix and suffix values determine if the client is sending the wrong API key, or if the key has been truncated.
* The prefix and suffix also determine which generation of algorithm your key uses.
* The Key ID is a GUID that can be used to uniquely identify the key in your storage system.
* Salt and hash values can be stored wherever you like, as long as you can fetch them back for validation.  
* The validation and key generation logic are as general purpose as possible so you can fit this library anywhere.

# Algorithm Performance

These performance statistics were measured on my laptop, a Dell I7-12700H.  Benchmarks measure the length of time
taken to do 1,000 iterations of Generate or Validate.

|   Method |   HashType |          Mean |      Error |     StdDev |
|--------- |----------- |--------------:|-----------:|-----------:|
| Generate |     SHA256 |      2.659 ms |  0.0269 ms |  0.0239 ms |
| Validate |     SHA256 |      1.214 ms |  0.0091 ms |  0.0085 ms |
| Generate |     SHA512 |      3.321 ms |  0.0217 ms |  0.0203 ms |
| Validate |     SHA512 |      1.821 ms |  0.0078 ms |  0.0061 ms |
| Generate |     BCrypt | 12,097.053 ms | 32.9440 ms | 30.8158 ms |
| Validate |     BCrypt | 12,183.813 ms | 39.5346 ms | 36.9807 ms |
| Generate | PBKDF2100K |  9,105.861 ms | 32.3737 ms | 30.2824 ms |
| Validate | PBKDF2100K |  9,153.661 ms | 51.2219 ms | 47.9130 ms |
