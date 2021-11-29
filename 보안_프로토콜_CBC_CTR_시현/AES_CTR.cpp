
#include <iostream>
#include <fstream>
#include "AES32.h"

using namespace std;
typedef unsigned char byte;

void XOR_state(byte state[16], byte xor_value[16]) {
	for (int i = 0; i < 16; i++) {
		state[i] ^= xor_value[i];
	}
}

void Copy_state(byte src[16], byte dest[16]) {
	for (int i = 0; i < 16; i++) {
		dest[i] = src[16];
	}
}

void AES_Enc_CTR(const char* pPT, byte key[16], byte Counter[16], const char* pCT) {
	ifstream fin;
	ofstream fout;

	fin.open(pPT, ios::binary);
	if (fin.fail()) {
		cout << "Input File Open Error!" << endl;
		return;
	}

	fout.open(pCT, ios::binary);
	if (fout.fail()) {
		cout << "Output File Open Error!" << endl;
		return;
	}

	int file_size;
	fin.seekg(0, fin.end);
	file_size = fin.tellg();
	fin.seekg(0, fin.beg);

	int num_block;
	num_block = file_size / 16 + 1;

	byte pt[16], ct[16];
	u32 rk[11][4];

	AES32_Enc_KeySchedule(key, rk);

	for (int i = 0; i < num_block-1; i++) {
		fin.read((char*)pt, 16);
		AES32_Encrypt(Counter + i, rk, ct);
		XOR_state(ct, pt);
		std::cout << "\nCiphertext Block " << i + 1 << " =";
		for (int j = 0; j < 16; j++) {
			std::cout << " " << ct[j];
		}
		fout.write((char*)ct, 16);
	}

	fin.close();
	fout.close();
}

void File_CTR_test() {
	const char* pPT = "PT.bin";
	const char* pCT = "CT_CTR.bin";
	const char* pDecPT = "DecPT_CTR.bin";

	byte key[16] = { 0, };
	byte Counter[16];
	for (int i = 0; i < 16; i++) {
		key[i] = i;
		Counter[i] = 0xf0 + i;
	}

	cout << "\nAES_CTR_Encrypt..." << endl;
	AES_Enc_CTR(pPT, key, Counter, pCT);

	cout << "\nAES_CTR_Decrypt..." << endl;
	AES_Enc_CTR(pCT, key, Counter, pDecPT);
}

int main()
{
	File_CTR_test();
}
