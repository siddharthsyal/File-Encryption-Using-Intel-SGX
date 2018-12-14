#include "Enclave1_t.h"
#include <string>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_tseal.h"

void decryptText(char *encMsg, size_t len, char *plainText, size_t lenOut, sgx_sealed_data_t *sealedData, uint32_t sealed_Size, char *debug, uint8_t debug_size)
{
	sgx_status_t seal_status = SGX_SUCCESS;//Status variable for unsealing
	sgx_status_t decrypt_status = SGX_SUCCESS;//Status  variable for decryption
	uint8_t *encMessage = (uint8_t *)encMsg;
	uint8_t *p_dst = (uint8_t *)malloc(lenOut * sizeof(char));
	uint8_t key[SGX_AESGCM_KEY_SIZE];
	uint32_t key_size = SGX_AESGCM_KEY_SIZE;
	seal_status = sgx_unseal_data(sealedData, NULL, NULL, key, &key_size);
	if (seal_status != SGX_SUCCESS) {
		memcpy(debug, "Cannot Unseal the key", strlen("Cannot Unseal the key"));
		free(p_dst);
		return;
	}
	decrypt_status = sgx_rijndael128GCM_decrypt(
		&key,
		encMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		(uint32_t)lenOut,
		p_dst,
		encMessage + SGX_AESGCM_MAC_SIZE, //Base pointer plus IV
		SGX_AESGCM_IV_SIZE,//Size of IV
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *)encMsg);//Pointer to MAC
	if (decrypt_status != SGX_SUCCESS) {
		memcpy(debug, "Problem with data decryption", strlen("Problem with data decryption"));
		free(p_dst);
		return;
	}
	memcpy(plainText, p_dst, lenOut);
	free(p_dst);
	return;
}
void encryptText(char *plainText, size_t length, char *cipher, size_t len_cipher, sgx_sealed_data_t *sealed, uint32_t sealed_Size, char *debug, uint8_t debug_size)
{
	uint32_t key_size = SGX_AESGCM_KEY_SIZE;
	sgx_status_t seal_status;//Status variable for unsealing the key
	sgx_status_t encrypt_status;//Status variable for encrypting the data
	sgx_sealed_data_t *sealedData = sealed;
	uint8_t *plain = (uint8_t *)plainText;
	uint8_t *iv;
	size_t cipherTextSize = SGX_AESGCM_KEY_SIZE + SGX_AESGCM_MAC_SIZE + length;
	uint8_t *cipherText = (uint8_t *)malloc(cipherTextSize * sizeof(char));
	//	uint8_t cipherText[4098] = {0};
	uint8_t key[16];
	sgx_status_t ret;
	seal_status = sgx_unseal_data(sealedData, NULL, NULL, key, &key_size);
	if (seal_status != SGX_SUCCESS) {
		memcpy(debug, "Cannot Unseal the key", strlen("Cannot Unseal the key"));
		free(cipherText);
		return;
	}
	sgx_read_rand(cipherText + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);
	encrypt_status = sgx_rijndael128GCM_encrypt(
		&key,//Key
		plain,//Pointer to plaintext
		length,//Len of plaintext
		cipherText + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE,//Base pointer plus IV size + Mac size = Destination
		cipherText + SGX_AESGCM_MAC_SIZE,//IV...base pointer plus MAC
		SGX_AESGCM_IV_SIZE,//Size of IV
		NULL,
		0,
		(sgx_aes_gcm_128bit_tag_t *)(cipherText));
	if (encrypt_status != SGX_SUCCESS) {
		memcpy(debug, "Problem with data encryption", strlen("Problem with data encryption"));
		free(cipherText);
		return;
	}
	memcpy(cipher, cipherText, len_cipher);//Copying the cipherText to output buffer
	free(cipherText);
	return;
}

/*Function  that generates a random key and seals it*/
void seal(sgx_sealed_data_t  *sealedData, uint32_t seal_data_size, char *debug, uint8_t debug_size) {
	sgx_status_t ret = SGX_SUCCESS;
	uint8_t key[16];
	sgx_read_rand(key, SGX_AESGCM_KEY_SIZE);
	sgx_sealed_data_t *internal_buffer = (sgx_sealed_data_t *)malloc(seal_data_size);
	ret = sgx_seal_data(
		0,//Additional Mac Text len
		NULL,//Addition MAC text
		SGX_AESGCM_KEY_SIZE,//Length of data to be encrypted
		key,//Pointer to the key (Generated above)
		seal_data_size,//Sealed Data size
		internal_buffer);//pointer to sealed data
	if (ret != SGX_SUCCESS) {
		memcpy(debug, "Data Sealing Error", strlen("Data Sealing Error"));
		free(internal_buffer);
		return;
	}
	memcpy(sealedData, internal_buffer, seal_data_size);
	free(internal_buffer);
	return;
}


/*Function to get the size of the sealed data*/
uint32_t sizeOfSealData() {
	uint32_t size_data = sgx_calc_sealed_data_size(0, SGX_AESGCM_KEY_SIZE);
	return size_data;
}