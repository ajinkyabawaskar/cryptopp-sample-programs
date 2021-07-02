#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h" // PRNG
#include "cryptopp/hex.h" // Hex Encoder/Decoder
#include "cryptopp/files.h" // File Source and Sink
#include "cryptopp/randpool.h" // PRNG
#include "cryptopp/secblock.h"
#include "cryptopp/md5.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"

#include <iostream>
#include <iomanip>

#define CIPHER AES
#define CIPHER_MODE CBC_Mode

class RSAKeyPair {

	public:
	void create() {
			std::string PrivateKeyFile = "key.pv";
			std::string PublicKeyFile = "key.pb";

			CryptoPP::AutoSeededRandomPool rng;

			// Specify 512 bit modulus, accept e = 17
			CryptoPP::RSAES_OAEP_SHA_Decryptor Decryptor(rng, 512 /*, e
			*/);
			CryptoPP::HexEncoder privFile(new
				CryptoPP::FileSink(PrivateKeyFile.c_str())
			); // Hex Encoder

			Decryptor.AccessMaterial().Save(privFile);
			privFile.MessageEnd();

			CryptoPP::RSAES_OAEP_SHA_Encryptor Encryptor(Decryptor);
			CryptoPP::HexEncoder pubFile(new
				CryptoPP::FileSink(PublicKeyFile.c_str())
			); // Hex Encoder
			Encryptor.AccessMaterial().Save(pubFile);
			pubFile.MessageEnd();

			std::cout << "Key Pair Saved." << std::endl;
		}

};

class RandomNumberGenerator {
public:
	void create() {
		// Scratch Area
		const unsigned int BLOCKSIZE = 16 * 8;
		CryptoPP::SecByteBlock scratch(BLOCKSIZE);

		// Construction
		CryptoPP::AutoSeededRandomPool rng;

		// Random Block
		rng.GenerateBlock(scratch, scratch.size());

		std::string token; 

		CryptoPP::HexEncoder hex(new CryptoPP::StringSink(token));
		hex.Put(scratch.data(), scratch.size());
		hex.MessageEnd();

		std::cout << token << std::endl;
	}
};

class SHA256Hash {
public:
	void create() {
		CryptoPP::MD5 hash;
		CryptoPP::byte digest[CryptoPP::MD5::DIGESTSIZE];
		std::string message = "abcdefghijklmnopqrstuvwxyz";

		hash.CalculateDigest(digest, (CryptoPP::byte*)message.c_str(), message.length());

		CryptoPP::HexEncoder encoder;
		std::string output;
		encoder.Attach(new CryptoPP::StringSink(output));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		std::cout << output << std::endl;
	}
};


class SymmerticCipher {
public:
	void create() {
		// Key and IV setup
		CryptoPP::byte key[32],
			iv[16];
		// CryptoPP::CIPHER::DEFAULT_KEYLENGTH
		// CryptoPP::CIPHER::BLOCKSIZE
		::memset(key, 0x01, 32);
		::memset(iv, 0x01, 16);

		// Message M
		std::string PlainText = "Yoda said, Do or Do Not. There is no try.";

		// Cipher Text Sink
		std::string CipherText;

		// Encryptor
		CryptoPP::CIPHER_MODE<CryptoPP::CIPHER>::Encryption
			Encryptor(key, sizeof(key), iv);

		// Encryption
		CryptoPP::StringSource(PlainText, true,
			new CryptoPP::StreamTransformationFilter(Encryptor,
				new CryptoPP::StringSink(CipherText)
			) // StreamTransformationFilter
		); // StringSource

		// Recovered Text Sink
		std::string RecoveredText;

		// Decryptor
		CryptoPP::CIPHER_MODE<CryptoPP::CIPHER>::Decryption
			Decryptor(key, sizeof(key), iv);

		// Decryption
		CryptoPP::StringSource(CipherText, true,
			new CryptoPP::StreamTransformationFilter(Decryptor,
				new CryptoPP::StringSink(RecoveredText)
			) // StreamTransformationFilter
		); // StringSource


		std::cout << "Algorithm:" << std::endl;
		std::cout << " " << Encryptor.AlgorithmName() << std::endl;
		std::cout << "Minimum Key Size:" << std::endl;
		std::cout << " " << Encryptor.MinKeyLength() << " bytes" << std::endl;
		std::cout << std::endl;

		std::cout << "Plain Text (" << PlainText.length() << " bytes)" << std::endl;
		std::cout << " '" << PlainText << "'" << std::endl;
		std::cout << std::endl;

		std::cout << "Cipher Text Size:" << std::endl;
		std::cout << " " << CipherText.size() << " bytes" << std::endl;
		std::cout << std::endl;

		std::cout << "Recovered Text:" << std::endl;
		std::cout << " '" << RecoveredText << "'" << std::endl;
		std::cout << std::endl;
	}
};
int main(int argc, char* argv[])
{
	try
	{
		//RSAKeyPair rsa;
		//rsa.create();

		//RandomNumberGenerator rand;
		//rand.create();

		//SHA256Hash sha;
		//sha.create();

		SymmerticCipher sym;
		sym.create();
	}

	catch (CryptoPP::Exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}

	catch (...) {
		std::cerr << "Unknown Error" << std::endl;
	}

	return 0;
}