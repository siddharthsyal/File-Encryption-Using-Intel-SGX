# File Encryption Using Intel-SGX

The repository contains the code for Windows console based application that uses Intel SGX technology to encrypt/decrypt the user input file using random keys. 

Details

Encrypt Function -:

* The Encrypt function takes the user file, which needs to be encrypted, as the user input. 
* Passes the file to the code running inside the enclave by calling the functions defined in the EDL file.
* Intel-SGX code creates a random AES-128 Bit key and uses the same key for encryption. 
* After a sucessful encryption, the randomly generated key is sealed using SGX data sealing.
* The sealed data is then stored on the user's hard drive. 

Decrypt function -:

* The decrypt function takes the encrypted file as the input along with the sealed data as the second user input. 
* The sealed data is unsealed using Intel SGX's own key. 
* The unsealed data provides SGX with AES-128 bit key that was used for bulk encryption.
* The derived key is then used to decrypt the data.