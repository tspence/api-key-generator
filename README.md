![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/tspence/api-key-generator/dotnet.yml?branch=main)
[![SonarCloud Coverage](https://sonarcloud.io/api/project_badges/measure?project=tspence_api-key-generator&metric=coverage)](https://sonarcloud.io/component_measures/metric/coverage/list?id=tspence_api-key-generator)
[![SonarCloud Bugs](https://sonarcloud.io/api/project_badges/measure?project=tspence_api-key-generator&metric=bugs)](https://sonarcloud.io/component_measures/metric/reliability_rating/list?id=tspence_api-key-generator)
[![SonarCloud Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=tspence_api-key-generator&metric=vulnerabilities)](https://sonarcloud.io/component_measures/metric/security_rating/list?id=tspence_api-key-generator)

# API Key Generator

A DotNet library for generating and validating API keys.  Although there are lots of libraries out there that help you
implement API key logic using middleware, this library attempts to isolate exactly the code that does API key generation
and validation using relatively safe practices.

The goal of this library is to strike the right balance between usability and reliability.

This library implements encryption of API keys as follows:
* Encryption uses SHA256 on key + salt.
* Keys and salts are 512 bits of randomness. 

The library is intended to support future generations of algorithms while still being compatible with previously
generated API keys.

For usability, this library works on a few basic principles:
* API key validation should be able to give clear error messages if the key is malformed.
* An API key is in the form `<prefix><key ID>:<client secret><suffix>`.
* The prefix and suffix values determine if the client is sending the wrong API key, or if the key has been truncated.
* The prefix and suffix also determine which generation of algorithm your key uses.
* The Key ID is a GUID that can be used to uniquely identify the key in your storage system.
* Keys can be stored in a database, REDIS, filesystem, or any other persistence mechanism.  
* The validation and key generation logic are as general purpose as possible so you can fit this library anywhere.

# Using the API Key Generator
