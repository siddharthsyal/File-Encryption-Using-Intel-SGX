#include "pch.h"
#include "sgx_tseal.h"
#include <stdio.h>
#include "Enclave1_u.h"
#include "sgx_urts.h"
#include <string>
#include "sgx_tcrypto.h"
#include <fstream>
#include <iostream>
#include <fstream>
#define ENCLAVE_FILE "Enclave1.signed.dll"
using namespace std;


void randomnessToFile(long flength,FILE *fp) {
	long i = 0;
	string random;
	for (i = 0; i < flength; i++) {
		random += rand();
	}
	fputs(random.c_str(), fp);
}

void decryptFile() {
	/*Delarations*/
	string plaintext_filename;
	string filename;
	string seal_filename;
	FILE *fp;
	long flength;
	long seal_length;
	errno_t err = 0;
	size_t seal_size_check;
	size_t plaintext_size_check;
	

	/*Debug Variables*/
	char debug[15] = "SUCCESS";
	uint8_t debug_size = 15;

	/*Enclave Initialization*/
	sgx_enclave_id_t eid;//Enclave ID
	sgx_status_t ret = SGX_SUCCESS; // For Checking if enclave was created successfully
	sgx_status_t ret2;
	int updated = 0;
	sgx_launch_token_t token = { 0 };
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("\nEnclave Cannot be initialized\n");
		return;
	}
	printf("\nSecure Enclave Initialized\n");

	/*Sealed Data mem allocation*/
	uint32_t sealed_data_size = 0;
	sizeOfSealData(eid, &sealed_data_size);
	sgx_sealed_data_t *sealed_data = (sgx_sealed_data_t *)malloc((sealed_data_size)*(sizeof(sgx_sealed_data_t)));

	/*Getting sealed data file location*/
	cin.sync();
	printf("\nPlease enter the file path for sealed data file. Format : Z:\sample1.txt\n");
	cin >> seal_filename;
	cin.sync();

	/*Reading Sealed Data*/
	if ((err = fopen_s(&fp, seal_filename.c_str(), "r")) != 0) {//"E:/sample1.txt"
		printf("\nFile Read Error \n");
		return;
	}
	if (fseek(fp, 0L, SEEK_END) == 0) //Getting the length of the text in the file
		seal_length = ftell(fp);
	if (fseek(fp, 0L, SEEK_SET) != 0) {
		printf("\nFile Pointer Error\n");
		return;
	}
	seal_size_check= fread(sealed_data, sizeof(sgx_sealed_data_t), sealed_data_size, fp);
	if (sealed_data_size != seal_size_check) {
		printf("\nThere is an issue with sealed data\n");
		return;
	}
	fclose(fp);

	/*Getting Cipher Text File Location*/
	printf("\nPlease enter the file path for ciphertext file. Format : Z:\sample1.txt\n");
	cin >> filename;
	cin.sync();

	/*CipherText File operations*/
	if ((err = fopen_s(&fp, filename.c_str(), "r+")) != 0) {//"E:/sample1.txt"
		printf("\nFile Read Error \n");
		return;
	}
	if (fseek(fp, 0L, SEEK_END) == 0) //Getting the length of the text in the file
		flength = ftell(fp);

	char *content = (char *)malloc((flength)*(sizeof(char)));
	if (fseek(fp, 0L, SEEK_SET) != 0) {
		printf("\nFile Pointer Error\n");
		return;
	}
	size_t read_length = fread(content, sizeof(char), flength, fp);
	if (read_length != flength) {
		printf("Read Error");
	//	return;
	}
	/*Ramdomising content in the ciphertext file*/
	if (fseek(fp, 0L, SEEK_SET) != 0) {
		printf("\nFile Pointer Error\n");
		return;
	}
	randomnessToFile(flength, fp);
	fclose(fp);

	/*Removing the cipher file*/
	if (remove(filename.c_str()) != 0) {
		printf("\nFile removal error\n");
		return;
	}

	/*Plaintext Memory Alloc*/
	int length = flength - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE;
	char* plaintext = (char *)malloc((length)*(sizeof(char)));
	/*Decrypting Cipher Text*/
	printf("\nDecryption Started\n");
	decryptText(eid,content, flength, plaintext,length, (sgx_sealed_data_t *)sealed_data, sealed_data_size, debug, debug_size);
	if (!strcmp(debug, "SUCCESS")) {
		printf("Error State.\nDebug Information - %s\n", debug);
		goto free_memory_dnc;
	}
	printf("\nFile Decryption Successful\n");

	/*Saving the plaintext to File*/
	cin.sync();
	printf("\nEnter the path with filename for storing plaintext data. Example : Z:\sample.txt\n");
	cin >> plaintext_filename;
	cin.sync();
	while (ifstream(plaintext_filename.c_str())) {
		printf("\nFile Already Exists\n");
		printf("\nEnter the path with filename for storing plaintext data. Example : Z:\sample.txt\n");
		cin.sync();
		getline(cin, plaintext_filename);
	}
	cin.sync();
	fopen_s(&fp, plaintext_filename.c_str(), "wb");
	plaintext_size_check = fwrite(plaintext, (size_t)sizeof(char), (size_t)length, fp);
	if (plaintext_size_check != (size_t)length)
		printf("\nError in Saving plaintext Data\n");
	fclose(fp);
	printf("\nPlaintext data written to the disk\n");

	/*Enclave Destruction*/
	if (SGX_SUCCESS != sgx_destroy_enclave(eid)) {
		printf("Enclave is not securely detroyed");
	}

	/*Free Memory Space*/
	free_memory_dnc:
	free(sealed_data);
	free(plaintext);
	free(content);

	printf("\nSecure Exit\n");
	return;
}

void encryptFile() {
	/*Delarations*/
	string filename ;
	FILE *fp;
	FILE *f_seal;
	long flength;
	errno_t err = 0;
	size_t seal_size_check, cipher_size_check;

	/*Debug Variables*/
	char debug[15] = "SUCCESS";
	uint8_t debug_size = 15;

	/*Getting File Location*/
	cin.clear();
	cin.ignore();
	printf("\nPlease enter the file path for plaintext  file. Format : Z:\sample1.txt\n");
	getline(cin,filename);

	/*File operations*/
	if ((err = fopen_s(&fp, filename.c_str(), "r+")) != 0) {//"E:\sample1.txt"
		printf("\nFile Read Error \n");
		return ;
	}
	if (fseek(fp, 0L, SEEK_END) == 0) //Getting the length of the text in the file
		flength = ftell(fp);

	char *content = (char *)malloc((flength)*(sizeof(char)));
	if (fseek(fp, 0L, SEEK_SET) != 0) {
		printf("\nFile Pointer Error\n");
		return ;
	}
	size_t read_length = fread(content, sizeof(char), flength, fp);
	if (read_length != flength) {
		printf("Read Error");
		return ;
	}

	/*Ramdomising content in the plaintext file*/
	if (fseek(fp, 0L, SEEK_SET) != 0) {
		printf("\nFile Pointer Error\n");
		return;
	}
	randomnessToFile(flength, fp);
	fclose(fp);

	/*Removing the plaintext file*/
	if (remove(filename.c_str()) != 0) {
		printf("\nFile removal error\n");
		return;
	}
	
	/*Enclave Initialization*/
	sgx_enclave_id_t eid;//Enclave ID
	sgx_status_t ret = SGX_SUCCESS; // For Checking if enclave was created successfully
	sgx_status_t ret2;
	int updated = 0;
	sgx_launch_token_t token = { 0 };
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("\nEnclave Cannot be initialized\n");
		return;
	}
	printf("\nSecure Enclave Initialized\n");

	/*Enclave Sealing data declaration*/
	uint32_t sealed_data_size = 0;
	sizeOfSealData(eid, &sealed_data_size);
	sgx_sealed_data_t *sealed_data = (sgx_sealed_data_t *)malloc((sealed_data_size)*(sizeof(sgx_sealed_data_t)));//Space allocation for sealed data

	/*CipherText length allocation*/
	size_t plaintext_len = flength;
	size_t ciphertext_len = plaintext_len + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE;
	char* cipherText = (char *)malloc((ciphertext_len)*(sizeof(char)));
	char * recovered = (char *)malloc((plaintext_len)*(sizeof(char)));

	/*Getting Sealed Key for bulk enc*/
	seal(eid,(sgx_sealed_data_t *) sealed_data, sealed_data_size, debug, debug_size);
	if (!strcmp(debug, "SUCCESS")) {
		printf("Error State.\nDebug Information - %s\n", debug);
		goto free_enc_mem;
	}

	/*Encrypting Data*/
	printf("\nFile Encryption Started\n");
	encryptText(eid, content, plaintext_len, cipherText, ciphertext_len, (sgx_sealed_data_t *)sealed_data, sealed_data_size, debug, debug_size);//Calling Encalve function for encryption
	if (!strcmp(debug, "SUCCESS")) {
		printf("Error State.\nDebug Information - %s\n", debug);
		goto free_enc_mem;
	}
	printf("\nFile Encryption Successful\n");

	/*Func to write the cipherText to a new file*/
	printf("\nEnter the path with filename for storing ciphertext. Example : Z:\sample.txt\n");
	getline(cin, filename);
	while (ifstream(filename.c_str())) {
		printf("\nFile Already Exists\n");
		printf("\nEnter the path with filename for storing ciphertext. Example : Z:\sample.txt\n");
		getline(cin, filename);
	}
	fopen_s(&fp, filename.c_str(), "wb");
	cipher_size_check = fwrite(cipherText,sizeof(char),ciphertext_len,fp);
	if (cipher_size_check != ciphertext_len)
		printf("\nError Saving Cipher Text\n");
	fclose(fp);
	printf("\nCiphertext written to the disk\n");

	/*Funct to save sealed data*/
	printf("\nEnter the path with filename for storing sealed data. Example : Z:\sample.txt\n");
	getline(cin, filename);
	while (ifstream(filename.c_str())) {
		printf("\nFile Already Exists\n");
		printf("\nEnter the path with filename for storing sealed data. Example : Z:\sample.txt\n");
		getline(cin, filename);
	}
	fopen_s(&f_seal,filename.c_str(), "wb");
	seal_size_check=  fwrite(sealed_data,(size_t)sizeof(sgx_sealed_data_t), (size_t)sealed_data_size,f_seal);
	if (seal_size_check != sealed_data_size)
		printf("\nError in Saving Sealing Data\n");
	fclose(f_seal);
	printf("\nSealed data written to the disk\n");

	/*Debug Stuff*/
	
	//decryptText(eid, cipherText, ciphertext_len, recovered, plaintext_len, (sgx_sealed_data_t *)sealed_data, sealed_data_size, debug, debug_size);
	//recovered[plaintext_len] = '\0';
	//printf("\nrecovered\n");
	//printf(recovered);
	
	/*Enclave Destruction*/
	if (SGX_SUCCESS != sgx_destroy_enclave(eid)) {
		printf("Enclave is not securely detroyed");
	}
	/*Realeasing memory*/
	free_enc_mem:
	free(content);
	free(sealed_data);
	free(cipherText);

	/*All Good. Exiting Now*/

	printf("\nSecure Exit\n");
	return;
}

int main() {
	int choice=0, user_input = 0;;
	printf("************************ SGX File Encryption Utility **********************\n");
	printf("Select from either one : \n1) Encrypt a file\n2) Decrypt a file\n Enter choice : ");
	cin.clear();
	cin >> choice;
	switch (choice) {
	case 1:
		cin.clear();
		encryptFile();
		break;
	case 2:
		decryptFile();
		break;
	defualt :
		printf("Ooops! Wrong input");
		break;
	}
	return 0;
}