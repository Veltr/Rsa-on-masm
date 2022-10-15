#include <iostream>

extern "C" void Init_lib(register int _primes_number);
extern "C" int* GetKeys();
extern "C" int* RSA_encrypt(register char* _base, register int _size, register int _a, register int _n);
extern "C" char* RSA_decrypt(register int* _base, register int _size, register int _a, register int _n); 

int main() {
	Init_lib(1000); // initialize lib vals and generate primes below 1000
	int* keys = GetKeys();

	std::string in;
	std::cout << "Input:\t";
	std::cin >> in;

	int n = in.size();
	int* en = RSA_encrypt((char*)in.c_str(), in.size(), keys[0], keys[2]);

	std::cout << "Encrypt:\n";
	for (int i = 0; i < n; i++) std::cout << en[i] << ' ';
	std::cout << '\n';

	char* de = RSA_decrypt(en, n, keys[1], keys[2]);

	std::cout << "Decrt:\t";
	for (int i = 0; i < n; i++) std::cout << de[i];
	std::cout << '\n';
	
	return 0;
}
