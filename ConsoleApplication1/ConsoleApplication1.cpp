#include "pch.h"
#include "sgx_tseal.h"
#include "Enclave1_u.h"
#include "sgx_urts.h"
#include <string>
#include "sgx_tcrypto.h"
#include <fstream>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include <windows.h>
#include <algorithm>
#include <cctype>
#include <conio.h>
#define ENCLAVE_FILE "Enclave1.signed.dll"
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <windows.h>
#include <stdlib.h>
#include <wincrypt.h>
#define mbedtls_time            time
#define mbedtls_time_t          time_t
#define mbedtls_fprintf         fprintf
#define mbedtls_printf          printf
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif

#define DEBUG_LEVEL 1

static void my_debug(void *ctx, int level,
	const char *file, int line,
	const char *str)
{
	((void)level);

	mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
	fflush((FILE *)ctx);
}

using namespace std;

int makeConnection(string request,std::string   &result) {
#define SERVER_PORT "443"
#define SERVER_NAME "127.0.0.1"
#define GET_REQUEST = request
	//"GET /verify?username=John&&password=1password HTTP/1.0\r\n\r\n"
	int ret = 1, len;
	std::string result_data;
	int exit_code = MBEDTLS_EXIT_FAILURE;
	mbedtls_net_context server_fd;
	uint32_t flags;
	unsigned char buf[1024];
	const char *pers = "ssl_client1";

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;
	HCERTSTORE  hSystemStore;
	PCCERT_CONTEXT  pCertContext = NULL;
	mbedtls_x509_crt_init(&cacert);
	//PCCERT_CONTEXT  pCertContext1 = NULL;

#if defined(MBEDTLS_DEBUG_C)
	mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

	/*
	 * 0. Initialize the RNG and the session data
	 */
	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&cacert);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_printf("\nInitializing Random Number Generator : ");
	fflush(stdout);

	mbedtls_entropy_init(&entropy);
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char *)pers,
		strlen(pers))) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
		goto exit;
	}

	mbedtls_printf("ok\n");

	/*
	 * 0. Initialize certificates
	 */

	 /*Taking the certficates from the root windows store*/
	mbedtls_printf("Loading the CA root certificate :");
	fflush(stdout);
	if (hSystemStore = CertOpenSystemStore(0, "ROOT")) {
		while (pCertContext = CertEnumCertificatesInStore(hSystemStore, pCertContext)) {
			if (pCertContext->dwCertEncodingType == X509_ASN_ENCODING) {
				mbedtls_x509_crt_parse(&cacert, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
			}
		}
	}

	ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)mbedtls_test_cas_pem,
		mbedtls_test_cas_pem_len);
	if (ret < 0)
	{
		mbedtls_printf("\nIssue : Certificate Parsing \n");
		goto exit;
	}

	mbedtls_printf(" ok (%d skipped)\n", ret);

	/*
	 * 1. Start the connection
	 */
	mbedtls_printf("Connecting to tcp/%s/%s : ", SERVER_NAME, SERVER_PORT);
	fflush(stdout);

	if ((ret = mbedtls_net_connect(&server_fd, SERVER_NAME,
		SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
	{
		mbedtls_printf("Issue : TCP Issue\n");
		goto exit;
	}

	mbedtls_printf("ok\n");

	/*
	 * 2. Setup stuff
	 */
	mbedtls_printf("Initialzing TLS stack : ");
	fflush(stdout);

	if ((ret = mbedtls_ssl_config_defaults(&conf,
		MBEDTLS_SSL_IS_CLIENT,//Checking if SSL/TLS layer acts as client or server
		MBEDTLS_SSL_TRANSPORT_STREAM,//Checking if using TLS or DTLS
		MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
	{
		mbedtls_printf("Issue : TLS config error\n");
		goto exit;
	}

	/*Checks for validity of the server cert. Currently verfication is optional*/
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
	{
		goto exit;
	}

	if ((ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME)) != 0)
	{
		goto exit;
	}

	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

	/*
	 * 4. Handshake
	 */
	mbedtls_printf("Performing TLS handshake...");
	fflush(stdout);

	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
	{
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
			goto exit;
		}
	}

	mbedtls_printf(" ok\n");

	/*
	 * 5. Verify the server certificate
	 */
	mbedtls_printf("Verifying peer X.509 certificate : ");

	/* In real life, we probably want to bail out when ret != 0 */
	if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
	{
		char vrfy_buf[512];

		mbedtls_printf(" failed\n");

		mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

		mbedtls_printf("%s\n", vrfy_buf);
	}
	else
		mbedtls_printf(" ok\n");

	/*
	 * 3. Write the GET request
	 */
	mbedtls_printf("\nSending Request");
	fflush(stdout);

	len = strlen(request.c_str());
	strncpy((char*)buf, request.c_str(),len);
	//len = sizeof(request);
	//buf = request;

	while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0)
	{
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			goto exit;
		}
	}

	len = ret;
	mbedtls_printf("\nRequest Sent \n");

	/*
	 * 7. Read the HTTP response
	 */
	mbedtls_printf("Response from the server : ");
	fflush(stdout);
	do
	{
		len = sizeof(buf) - 1;
		memset(buf, 0, sizeof(buf));
		ret = mbedtls_ssl_read(&ssl, buf, len);
		char *data = strstr((char *)buf, "\r\n\r\n");
		if (data != NULL) {
			result_data = data;
			result_data.erase(std::remove_if(result_data.begin(), result_data.end(), ::isspace), result_data.end());
			result = result_data;
			break;
		}
	} while (1);
	//	mbedtls_ssl_close_notify(&ssl);
	if (mbedtls_ssl_close_notify(&ssl) == 0)
	{
		mbedtls_printf("TLS Connection Terminated\n");
	}
	exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

#ifdef MBEDTLS_ERROR_C
	if (exit_code != MBEDTLS_EXIT_SUCCESS)
	{
		mbedtls_printf("Connection Failure\n");
	}
#endif

	mbedtls_net_free(&server_fd);

	mbedtls_x509_crt_free(&cacert);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return exit_code;
}


void randomnessToFile(long flength, FILE *fp) {
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
	//sgx_status_t ret2;
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
	printf("\nPlease enter the file path for sealed data file. Format :  Z:\\sample1.txt\n");
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
	seal_size_check = fread(sealed_data, sizeof(sgx_sealed_data_t), sealed_data_size, fp);
	if (sealed_data_size != seal_size_check) {
		printf("\nThere is an issue with sealed data\n");
		return;
	}
	fclose(fp);

	/*Getting Cipher Text File Location*/
	printf("\nPlease enter the file path for ciphertext file. Format : Z:\\sample1.txt\n");
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
	decryptText(eid, content, flength, plaintext, length, (sgx_sealed_data_t *)sealed_data, sealed_data_size, debug, debug_size);
	if (!strcmp(debug, "SUCCESS")) {
		printf("Error State.\nDebug Information - %s\n", debug);
		goto free_memory_dnc;
	}
	printf("\nFile Decryption Successful\n");

	/*Saving the plaintext to File*/
	cin.sync();
	printf("\nEnter the path with filename for storing plaintext data. Example : Z:\\sample.txt\n");
	cin >> plaintext_filename;
	cin.sync();
	while (ifstream(plaintext_filename.c_str())) {
		printf("\nFile Already Exists\n");
		printf("\nEnter the path with filename for storing plaintext data. Example : Z:\\sample.txt\n");
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
	string filename;
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
	printf("\nPlease enter the file path for plaintext  file. Format : Z:\\sample1.txt\n");
	getline(cin, filename);

	/*File operations*/
	if ((err = fopen_s(&fp, filename.c_str(), "r+")) != 0) {//"E:\sample1.txt"
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
		return;
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
	seal(eid, (sgx_sealed_data_t *)sealed_data, sealed_data_size, debug, debug_size);
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
	printf("\nEnter the path with filename for storing ciphertext. Example : Z:\\sample.txt\n");
	getline(cin, filename);
	while (ifstream(filename.c_str())) {
		printf("\nFile Already Exists\n");
		printf("\nEnter the path with filename for storing ciphertext. Example : Z:\\sample.txt\n");
		getline(cin, filename);
	}
	fopen_s(&fp, filename.c_str(), "wb");
	cipher_size_check = fwrite(cipherText, sizeof(char), ciphertext_len, fp);
	if (cipher_size_check != ciphertext_len)
		printf("\nError Saving Cipher Text\n");
	fclose(fp);
	printf("\nCiphertext written to the disk\n");

	/*Funct to save sealed data*/
	printf("\nEnter the path with filename for storing sealed data. Example : Z:\\sample.txt\n");
	getline(cin, filename);
	while (ifstream(filename.c_str())) {
		printf("\nFile Already Exists\n");
		printf("\nEnter the path with filename for storing sealed data. Example : Z:\\sample.txt\n");
		getline(cin, filename);
	}
	fopen_s(&f_seal, filename.c_str(), "wb");
	seal_size_check = fwrite(sealed_data, (size_t)sizeof(sgx_sealed_data_t), (size_t)sealed_data_size, f_seal);
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
	printf("************************ SGX File Encryption Utility **********************\nPlease provide the authentication data \n");
	int choice = 0, user_input = 0;
	string get = "GET /verify?username=";
	string username;
	string password;
	char buffer = NULL;
	char *result= NULL;
	std::string result_data;
	printf("Enter the Username\n");
	cin >> username;
	get = get + username + "&&password=";
	printf("Enter the password : \n");
	do {
		if (buffer != NULL){
			password.push_back(buffer);
		}		
		buffer = _getch();
		cout << '*';
		
	} while (buffer != ' ');
	get = get + password + " HTTP/1.0\r\n\r\n";
	int connection_result = makeConnection(get,result_data);
	if (connection_result != 0) {
		return 0;
	}
	if (result_data.compare("true")==0){
		printf("\nAuthentication Successful\n");
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
		defualt:
			printf("Ooops! Wrong input");
			break;
		}
	}
	else {
		printf("Invalid Authentication\n");
	}
	return 0;
}
