# CredAbstractor
A simple credential abstraction mechanism for minor implementation needs.

**This compiles with .NET 4.0.X and above.**

Almost all details on operation and implementation can be found in CryptUtil.cs and CryptDriver.cs.

# Quick Start
CryptUtil has three (3) public-facing methods for the client to use:
* your_instance.runCryptUtil():
    - retrieve plaintext credentials from encrypted file
* your_instance.setCredAndKeyFiles(cred_fpath, key_fpath):
    - set the file containing credentials, and which holds the key
* your_instance.setConfig(config_fpath):
    - credfile and keyfile will be created based on this

To use this in your C# project, include the CryptUtil namespace:
- `using CryptUtilNS;`

To execute (assuming you are indirectly passing credentials to another source):
- `ClientFunctionThatExecutes( your_instance.runCryptUtil() )`

^ This will calculate and pass credentials (after decryption) to the client function.

See CryptUtil.cs and CryptDriver.cs for more details.

# DISCLAIMER
PLEASE do not use this for _actual_ secure abstraction. This is very basic, and in no way secure enough for most applications!
This is also a work-in-progress and will be updated, hardened and improved over time.
