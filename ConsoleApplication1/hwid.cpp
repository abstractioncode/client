#include "hwid.h"

namespace get_hwid {
	std::string get_comp_username(bool User)
	{
		std::string CompUserName = "";
		char szCompName[MAX_COMPUTERNAME_LENGTH + 1];
		char szUserName[MAX_COMPUTERNAME_LENGTH + 1];

		DWORD dwCompSize = sizeof(szCompName);
		DWORD dwUserSize = sizeof(szUserName);

		if (GetComputerNameA(szCompName, &dwCompSize))
		{
			CompUserName = szCompName;
			if (User && GetUserNameA(szUserName, &dwUserSize))
			{
				CompUserName = szUserName;
			}
		}
		return CompUserName;
	}

	std::string get_cpuid() {
		int CPUInfo[4] = { -1 };
		char CPUBrandString[0x40];
		__cpuid(CPUInfo, 0x80000000);
		unsigned int nExIds = CPUInfo[0];

		memset(CPUBrandString, 0, sizeof(CPUBrandString));

		for (size_t i = 0x80000000; i <= nExIds; ++i)
		{
			__cpuid(CPUInfo, i);
			if (i == 0x80000002)
				memcpy(CPUBrandString, CPUInfo, sizeof(CPUInfo));
			else if (i == 0x80000003)
				memcpy(CPUBrandString + 16, CPUInfo, sizeof(CPUInfo));
			else if (i == 0x80000004)
				memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));
		}
		std::string cpuid = CPUBrandString;
		return cpuid;
	}
	DWORD get_volimeid()
	{
		DWORD VolumeSerialNumber;
		BOOL GetVolumeInformationFlag = GetVolumeInformationA("c:\\", 0, 0, &VolumeSerialNumber, 0, 0, 0, 0);
		if (GetVolumeInformationFlag) return VolumeSerialNumber;
		return 0;
	}
	std::string string_to_hex(const std::string input)
	{
		const char* lut = "0123456789ABCDEF";
		size_t len = input.length();
		std::string output = "";

		output.reserve(2 * len);

		for (size_t i = 0; i < len; i++)
		{
			const unsigned char c = input[i];
			output.push_back(lut[c >> 4]);
			output.push_back(lut[c & 15]);
		}

		return output;
	}
	std::string get_hwidkey()
	{
		std::string SerialKey = "61A345B5496B2";
		std::string CompName = get_comp_username(false);
		std::string UserName = get_comp_username(true);


		SerialKey.append(string_to_hex(std::to_string(get_volimeid())));
		SerialKey.append("-");
		SerialKey.append(string_to_hex(CompName));
		SerialKey.append("-");
		SerialKey.append(string_to_hex(UserName));

		return SerialKey;
	}

	std::string get_hash_text(const void* data, const size_t data_size) {
		HCRYPTPROV hProv = NULL;

		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return "";

		BOOL hash_ok = FALSE;
		HCRYPTPROV hHash = NULL;

		hash_ok = CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
		if (!hash_ok)
		{
			CryptReleaseContext(hProv, 0);
			return "";
		}

		if (!CryptHashData(hHash, static_cast<const BYTE*>(data), data_size, 0))
		{
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);
			return "";
		}

		DWORD cbHashSize = 0, dwCount = sizeof(DWORD);
		if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&cbHashSize, &dwCount, 0))
		{
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);
			return "";
		}

		std::vector<BYTE> buffer(cbHashSize);

		if (!CryptGetHashParam(hHash, HP_HASHVAL, reinterpret_cast<BYTE*>(&buffer[0]), &cbHashSize, 0))
		{
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);
			return "";
		}

		std::ostringstream oss;

		for (std::vector<BYTE>::const_iterator iter = buffer.begin(); iter != buffer.end(); ++iter)
		{
			oss.fill('0');
			oss.width(2);
			oss << std::hex << static_cast<const int>(*iter);
		}

		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return oss.str();
	}
	std::string get_hash_serial_key() {
		std::string SerialKey = get_hwidkey();
		const void* pData = SerialKey.c_str();
		size_t Size = SerialKey.size();
		std::string Hash = get_hash_text(pData, Size);

		for (auto& c : Hash)
		{
			if (c >= 'a' && c <= 'f') c = '4';
			else if (c == 'b') c = '5';
			else if (c == 'c')c = '6';
			else if (c == 'd') c = '7';
			else if (c == 'e') c = '8';
			else if (c == 'f') c = '9';
			c = toupper(c);
		}

		return Hash;
	}
	std::string get_hash_cpuid() {
		std::string Cpuid = get_cpuid();
		const void* pData = Cpuid.c_str();
		size_t Size = Cpuid.size();
		std::string Hash = get_hash_text(pData, Size);

		for (auto& c : Hash)
		{
			if (c >= 'a' && c <= 'f') c = '4';
			else if (c == 'b') c = '5';
			else if (c == 'c')c = '6';
			else if (c == 'd') c = '7';
			else if (c == 'e') c = '8';
			else if (c == 'f') c = '9';
			c = toupper(c);
		}

		return Hash;
	}
	std::string hwid() {
		std::string Serial = "";
		std::string HashSerialKey = get_hash_serial_key();

		std::string Serial1 = HashSerialKey.substr(0, 4);
		std::string Serial2 = HashSerialKey.substr(4, 4);
		std::string Serial3 = HashSerialKey.substr(8, 4);
		std::string Serial4 = HashSerialKey.substr(12, 4);

		std::string HashCpuid = get_hash_cpuid();
		std::string Serial5 = HashSerialKey.substr(HashCpuid.size() / 2 - 2, 4);

		Serial += Serial1;
		Serial += '-';
		Serial += Serial2;
		Serial += '-';
		Serial += Serial3;
		Serial += '-';
		Serial += Serial4;
		Serial += '-';
		Serial += Serial5;

		return Serial;
	}
}