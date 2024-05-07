#include <iostream>
#include <chrono>

#include <sodium.h>

#define CHUNK_SIZE 4096

static int encrypt_file(const char* target_file, const char* source_file, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
	unsigned char  buf_in[CHUNK_SIZE];
	unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
	unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	FILE* fp_t, * fp_s;
	unsigned long long out_len;
	size_t rlen;
	int eof;
	unsigned char tag;

	if (fopen_s(&fp_s, source_file, "rb") != 0) return EXIT_FAILURE;
	if (fp_s == NULL) return EXIT_FAILURE; // formality

	if (fopen_s(&fp_t, target_file, "wb") != 0) {
		fclose(fp_s);
		return EXIT_FAILURE;
	}
	if (fp_t == NULL) return EXIT_FAILURE; // formality

	crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
	fwrite(header, 1, sizeof header, fp_t);
	do {
		rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
		eof = feof(fp_s);
		tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
		crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen, NULL, 0, tag);
		fwrite(buf_out, 1, (size_t)out_len, fp_t);
	} while (!eof);

	fclose(fp_t);
	fclose(fp_s);

	return EXIT_SUCCESS;
}

static int decrypt_file(const char* target_file, const char* source_file, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
	unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
	unsigned char  buf_out[CHUNK_SIZE];
	unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	FILE* fp_t, * fp_s;
	unsigned long long out_len;
	size_t rlen;
	int eof;
	int ret = -1;
	unsigned char tag;

	if (fopen_s(&fp_s, source_file, "rb") == EINVAL) return EXIT_FAILURE;
	if (fp_s == NULL) return EXIT_FAILURE; // formality

	if (fopen_s(&fp_t, target_file, "wb") == EINVAL) {
		fclose(fp_s);
		return EXIT_FAILURE;
	}
	if (fp_t == NULL) return EXIT_FAILURE; // formality

	fread(header, 1, sizeof header, fp_s);
	if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
		goto err; /* incomplete header */
	}
	do {
		rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
		eof = feof(fp_s);
		if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag, buf_in, rlen, NULL, 0) != 0) {
			goto err; /* corrupted chunk */
		}
		if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
			if (!eof) {
				goto err; /* end of stream reached before the end of the file */
			}
		}
		else { /* not the final chunk yet */
			if (eof) {
				goto err; /* end of file reached before the end of the stream */
			}
		}
		fwrite(buf_out, 1, (size_t)out_len, fp_t);
	} while (!eof);

	ret = 0;

err:
	fclose(fp_t);
	fclose(fp_s);
	return ret;
}


int password_to_key() {
	std::string password = "Correct Horse Battery Staple";

	unsigned char salt[crypto_pwhash_SALTBYTES];
	unsigned char key[crypto_box_SEEDBYTES];

	randombytes_buf(salt, sizeof salt);

	if (crypto_pwhash(key, sizeof key, password.c_str(), password.length(), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int password_hash_and_check() {
	std::string password = "Correct Horse Battery Staple";

	char hashed_password[crypto_pwhash_STRBYTES];

	std::chrono::high_resolution_clock::time_point start;
	std::chrono::duration<float, std::milli> duriation;

	std::cout << "hashing started.\n";
	start = std::chrono::high_resolution_clock::now();
	if (crypto_pwhash_str(hashed_password, password.c_str(), password.length(), crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
		return EXIT_FAILURE;
	}
	duriation = std::chrono::high_resolution_clock::now() - start;
	std::cout << "hashing ended in " << duriation.count() << "ms." << "\n";

	std::cout << "verification started.\n";
	start = std::chrono::high_resolution_clock::now();
	if (crypto_pwhash_str_verify(hashed_password, password.c_str(), password.length()) != 0) {
		duriation = std::chrono::high_resolution_clock::now() - start;
		std::cout << "verification failed in " << duriation.count() << "ms." << "\n";

		return EXIT_FAILURE;
	}
	duriation = std::chrono::high_resolution_clock::now() - start;
	std::cout << "verification ended in " << duriation.count() << "ms." << "\n";

	return EXIT_SUCCESS;
}

// note: unsecure memory
int public_key_encryption() {
	// raw message
	std::string raw_message = "test message of arbitrary length lol :333";
#define MAX_MESSAGE_LENGTH 64

	std::cout << "raw message: " << raw_message << "\n";

	// padding message
	unsigned char padded_message[MAX_MESSAGE_LENGTH];
	size_t padded_message_buffer_length = sizeof(padded_message);

	size_t raw_message_length = raw_message.length();
	memcpy(padded_message, raw_message.c_str(), raw_message_length);

	size_t padded_message_length;
	size_t block_size = 16;

	if (sodium_pad(&padded_message_length, padded_message, raw_message_length, block_size, padded_message_buffer_length) != 0) {
		return EXIT_FAILURE;
	}

	// keys
	unsigned char server_publickey[crypto_box_PUBLICKEYBYTES];
	unsigned char server_secretkey[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(server_publickey, server_secretkey);

	unsigned char client_publickey[crypto_box_PUBLICKEYBYTES];
	unsigned char client_secretkey[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(client_publickey, client_secretkey);

	// key exchange - generates 2 secret keys that are shared (server_rx = client_tx and server_tx = client_rx)
	/*
	unsigned char server_rx[crypto_kx_sessionkeybytes], server_tx[crypto_kx_sessionkeybytes];
	if (crypto_kx_server_session_keys(server_rx, server_tx, server_publickey, server_secretkey, client_publickey) != 0) {
		return EXIT_FAILURE;
	}

	unsigned char client_rx[crypto_kx_sessionkeybytes], client_tx[crypto_kx_sessionkeybytes];
	if (crypto_kx_client_session_keys(client_rx, client_tx, client_publickey, client_secretkey, server_publickey) != 0) {
		return EXIT_FAILURE;
	}
	*/

	// nonce
	unsigned char nonce[crypto_box_NONCEBYTES];
	randombytes_buf(nonce, sizeof nonce);

	// encryption
	unsigned char* encrypted_message = new unsigned char[padded_message_length];
	unsigned char mac[crypto_box_MACBYTES];
	if (crypto_box_detached(encrypted_message, mac, padded_message, padded_message_length, nonce, client_publickey, server_secretkey) != 0) {
		return EXIT_FAILURE;
	}

	// decryption
	unsigned char* decrypted_message = new unsigned char[padded_message_length];
	if (crypto_box_open_detached(decrypted_message, encrypted_message, mac, padded_message_length, nonce, server_publickey, client_secretkey) != 0) {
		return EXIT_FAILURE;
	}

	delete[] encrypted_message;

	// unpadding message
	size_t unpadded_message_length;

	if (sodium_unpad(&unpadded_message_length, decrypted_message, padded_message_length, block_size) != 0) {
		return EXIT_FAILURE;
	}

	// copy the message of unpadded_message_length into a null terminated buffer
	unsigned char* final_message = new unsigned char[unpadded_message_length + 1];
	memcpy(final_message, decrypted_message, unpadded_message_length);
	final_message[unpadded_message_length] = '\0';

	delete[] decrypted_message;

	std::cout << "decrypted message: " << final_message << "\n";

	return EXIT_SUCCESS;
}

int main()
{
	if (sodium_init() < 0) {
		return EXIT_FAILURE;
	}

	int result = public_key_encryption();
	std::cout << "! public_key_encryption returned " << result << ".\n";

	result = password_hash_and_check();
	std::cout << "! password_hash_and_check returned " << result << ".\n";

	result = password_to_key();
	std::cout << "! password_to_key returned " << result << ".\n";

#pragma region file stuff
	unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	crypto_secretstream_xchacha20poly1305_keygen(key);

	if (encrypt_file("encrypted", "original.png", key) != 0) {
		return EXIT_FAILURE;
	}
	if (decrypt_file("decrypted.png", "encrypted", key) != 0) {
		return EXIT_FAILURE;
	}
#pragma endregion

	return EXIT_SUCCESS;
}

/*
// A simple program that uses LoadLibrary and 
// GetProcAddress to access myPuts from Myputs.dll. 

#include <windows.h> 
#include <stdio.h> 

int dynamic_linking()
{
	HINSTANCE hinstLib;
	FARPROC ProcAdd;
	BOOL RunTimeLinkSuccess = FALSE;

	// Get a handle to the DLL module.
	hinstLib = LoadLibraryW(L"test.dll");

	// If the handle is valid, try to get the function address.
	if (hinstLib != NULL)
	{
		ProcAdd = GetProcAddress(hinstLib, "test");

		// If the function address is valid, call the function.
		if (ProcAdd != NULL)
		{
			RunTimeLinkSuccess = TRUE;
			(ProcAdd)();
		}

		// Free the DLL module.
		if (FreeLibrary(hinstLib) == FALSE)
			return 1;
	}

	// If unable to call the DLL function, use an alternative.
	if (!RunTimeLinkSuccess)
		return 1;

	return 0;
}
*/