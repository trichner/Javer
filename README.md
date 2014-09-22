Javer
=====

Simple jar signature checker

## How to sign a jar

You have to use the java tool `jarsigner`, you can find the tool in your .../jdk-xyz/bin/ folder.
First you need a keystore and some keys to sign, either you use javas `keytool` or a GUI like [portecle](http://portecle.sourceforge.net/).

If you managed to create a keypair and saved your keystore you can sign a jar with following command:

`jarsigner -keystore path/to/keystore -verbose yourjar.jar your-key-alias`

and verify it with 

`jarsigner -keystore path/to/keystore yourjar.jar`

## How to verify the signature with Javer

Javer can either check signatures of provided jars or itself.
Usage:
java -jar javer.jar [jarfile]
If no jarfile is provided, Javer will try to verify if itself is signed.

You can find a correctly signed javer.jar in the root of this repo.


