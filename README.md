# WoW Knock
Most World of Warcraft server emulators leak information on whether an account exists during the authentication process.

 This tool serves as a simple proof-of-concept that allows for connecting to a server and testing whether the specified account exists.

It's hardcoded to support 1.12.1 5875 but would work with later clients with minimal modifications.

## Building
Requires CMake and optionally vcpkg to auto-install dependencies (Asio and Hexi).
```
cmake . -B build -DCMAKE_TOOLCHAIN_FILE=path/to/vcpkg.cmake
```

## Usage example
```
wowknock -host login.example.com -port 3724 -user administrator
```
### Example output
```
If found:
Account "administrator" exists or server is not leaking
Account has 2FA enabled

If not found:
Account "administrator" does not exist
```

## Plugging the leak
The correct fix for this information leak is for servers to indicate success in their `cmd_auth_logon_challenge` response, even if the account does not exist. The response should contain substituted data, which will result in an incorrect password response during the next stage.

Generating the salt must be deterministic (e.g. based on the username), otherwise account presence can still be detected with two queries. If the same salt generation method is not used for genuine accounts and that method is known, only one require is required.

