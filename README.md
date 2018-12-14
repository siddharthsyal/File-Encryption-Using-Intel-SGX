# File Encryption Using Intel-SGX 

The repository contains the code for Windows console based application that uses Intel SGX technology to encrypt/decrypt the user data using random keys and authenticates the user with a remote server before performing any actions. 

Console Application Details

Main Function -:

* Before allowing the user to encrypt/decrypt the data. The user needs to be authenticated. 
* The console application creates a TLS connection to the remote server. 
* The console application uses mbedTLS stack for creating the connection to the remote server. 
* Once the application receives an appropriate server response, the application allows/denies the user access. 

Make Connection function -:

* Takes care of sending and receiving the HTTP response. 
* Builds and terminates the TLS connection. 
* Currently, the code bypasses the x509 cert validation due to testing purposes. This must be taken care of before actual deployment. 

Seal Function -:

* Request the enclave code to generate a random AES-128bit key.
* The enclave seals the generated key and passes it to the console application for storage in untrusted location. 

Encrypt Function -:

* Takes sealed data structure and the plain-text file as the user input.
* Shreds the plain-text file by writing random bits over the initial memory location of the plain-text. 
* Passes the plain-text file and the sealed data structure to the enclave. 
* The SGX enclave returns the cipher text that can be stored in the untrusted location. 

Decrypt function -:

* Decrypt function takes the sealed data structure and the cipher text file as the user input. 
* Shreds the cipher text file by writing random bits over the initial memory location of the cipher text.
* Passes the cipher text file content and the sealed data structure to the enclave. 
* The SGX enclave returns the plain-text that can be stored by the user. 

SGX enclave Details

Seal Function -:

* Generates a random 128-bit key for bulk encryption. 
* Uses the data sealing functionality to seal the generated key. 
* The sealed data structure is passed to the console application. 

Encrypt Function -:

* Parses the sealed data structure received from the console application. 
* If the sealed data structure is unsealed successfully, the SGX code continues else an error message is returned to the user. 
* Once the symmetric key has been unsealed from the sealed data structure, AES-128 bit GCM mode encrypt method is called inside the SGX enclave. 
* If the encryption is successful, the enclave returns the cipher text else it returns an error message. 

Decrypt Function -:

* Parses the sealed data structure received from the console application. 
* If the sealed data structure is unsealed successfully, the SGX code continues else an error message is returned to the user. 
* Once the symmetric key has been unsealed from the sealed data structure, AES-128 bit GCM mode decrypt method is called inside the SGX enclave. 
* If the decryption is successful, the enclave returns the plain-text else it returns an error message. 

Remote Server Details 

* The code has been written in GoLang
* The remote HTTP server parses the get request to fetch the user-name/password.
* After a successful verification, the server sends "true" as the response else "false" is returned. 

Dependencies -: 

* mbedTLS related libraries. Check mbedTLS website for reference. 
* Windows crypt32.lib for loading root CAs from Windows store.