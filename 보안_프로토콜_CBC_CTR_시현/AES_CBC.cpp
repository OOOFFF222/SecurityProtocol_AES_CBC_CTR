
#include <iostream>
#include <fstream>
#include "AES32.h"

using namespace std;
typedef unsigned char byte;

void padding(byte in[], int in_len, byte out[16]) {
	byte pad_byte = 0x80;
	for (int i = 0; i < in_len; i++) {
		out[i] = in[i];
	}
	out[in_len] = 0x80;
	for (int i = in_len + 1; i < 16; i++) {
		out[i] = 0x00;
	}
}

// 패딩을 제외한 바이트 수 구하기
// 출력값 : 0, ..., 15 -> 오류시 -1
int pt_length(byte padded[16]) {
	int position80;
	position80 = 15;
	for (int i = 15; i > 0; i--) {
		if (padded[i] != 0x00) break;
		position80--;
	}
	if (padded[position80] != 0x80) {
		cout << "Padding Error : 0x80 not found." << endl;
		return -1;
	}
	else {
		return position80;
	}
}

void XOR_state(byte state[16], byte xor_value[16]) {
	for (int i = 0; i < 16; i++) {
		state[i] ^= xor_value[16];
	}
}

void Copy_state(byte src[16], byte dest[16]) {
	for (int i = 0; i < 16; i++) {
		dest[i] = src[16];
	}
}

void AES_Enc_CBC(const char* pPT, byte key[16], byte IV[16], const char* pCT) {
	ifstream fin;
	ofstream fout;

	char ch;

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

	int num_block, remainder;
	num_block = file_size / 16 + 1;
	remainder = file_size - (num_block - 1) * 16;

	byte pt[16], ct[16];
	u32 rk[11][4];
	byte prev_iv[16];

	AES32_Enc_KeySchedule(key, rk);

	Copy_state(IV, prev_iv);

	for (int i = 0; i < num_block - 1; i++) {
		fin.read((char*)pt, 16);
		XOR_state(pt, prev_iv);
		AES32_Encrypt(pt, rk, ct);
		std::cout << "\nCiphertext Block " << i + 1 << " =";
		for (int j = 0; j < 16; j++) {
			std::cout << " " << ct[j];
		}
		fout.write((char*)ct, 16);
		Copy_state(ct, prev_iv);
	}

	byte pt_pad[16];
	for (int i = 0; i < remainder; i++) {
		fin.read(&ch, 1);
		pt[i] = ch;
	}
	padding(pt, remainder, pt_pad);
	XOR_state(pt_pad, prev_iv);
	AES32_Encrypt(pt_pad, rk, ct);
	std::cout << "\nCiphertext Block " << num_block << " =";
	for (int j = 0; j < 16; j++) {
		std::cout << " " << ct[j];
	}
	fout.write((char*)ct, 16);

	fin.close();
	fout.close();
}

void AES_Dec_CBC(const char* pCT, byte key[16], byte IV[16], const char* pDecPT) {
	ifstream fin;
	ofstream fout;

	char ch;

	fin.open(pCT, ios::binary);
	if (fin.fail()) {
		cout << "Input File Open Error!" << endl;
		return;
	}

	fout.open(pDecPT, ios::binary);
	if (fout.fail()) {
		cout << "Output File Open Error!" << endl;
		return;
	}

	int file_size;
	fin.seekg(0, fin.end);
	file_size = fin.tellg();
	fin.seekg(0, fin.beg);

	int num_block, remainder;
	num_block = file_size / 16;
	remainder = file_size - num_block * 16;
	if (remainder != 0) {
		cout << "File size Error (Not a multiple of 16)" << endl;
	}

	byte pt[16], ct[16];
	u32 rk[11][4];
	byte prev_iv[16];

	AES32_Dec_KeySchedule(key, rk);

	Copy_state(IV, prev_iv);

	for (int i = 0; i < num_block - 1; i++) {
		fin.read((char*)ct, 16);
		AES32_EqDecrypt(ct, rk, pt);
		XOR_state(pt, prev_iv);
		std::cout << "\nPlaintext Block " << i + 1 << " =";
		for (int j = 0; j < 16; j++) {
			std::cout << " " << pt[j];
		}
		Copy_state(ct, prev_iv);
		fout.write((char*)pt, 16);
	}

	int last_pt_len;
	fin.read((char*)ct, 16);
	AES32_EqDecrypt(ct, rk, pt);
	XOR_state(pt, prev_iv);
	std::cout << "\nPlaintext Block " << num_block << " =";
	for (int j = 0; j < 16; j++) {
		std::cout << " " << pt[j];
	}
	last_pt_len = pt_length(pt);
	if (last_pt_len < 0) {
		//cout << "Padding Errpr" << endl;
		return;
	}

	for (int i = 0; i < last_pt_len; i++) {
		ch = pt[i];
		fout.write(&ch, 1);
	}

	fin.close();
	fout.close();
}

void File_CBC_test() {
	const char* pPT = "PT.bin";
	const char* pCT = "CT_CBC.bin";
	const char* pDecPT = "DecPT_CBC.bin";

	byte key[16] = { 0, };
	byte IV[16];
	for (int i = 0; i < 16; i++) {
		key[i] = i;
		IV[i] = 0xf0 + i;
	}

	cout << "\nAES_CBC_Encrypt..." << endl;
	AES_Enc_CBC(pPT, key, IV, pCT);

	cout << "\nAES_CBC_Decrypt..." << endl;
	AES_Dec_CBC(pCT, key, IV, pDecPT);
}

int main()
{
	File_CBC_test();
}
