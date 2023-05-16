#include <iostream>
#include <iomanip>
#include <unordered_map>

struct Block128
{
	static constexpr int m_size{ 16 };
	unsigned char* m_data{ nullptr };
};

struct EncryptKey256
{
	static constexpr int m_size{ 32 };
	unsigned char* m_data{ nullptr };
};

std::unordered_map<uint8_t, uint8_t> H_TABLE
{
	{0x00, 0xB1}, {0x01, 0x94}, {0x02, 0xBA}, {0x03, 0xC8}, {0x04, 0x0A}, {0x05, 0x08}, {0x06, 0xF5}, {0x07, 0x3B}, {0x08, 0x36}, {0x09, 0x6D}, {0x0A, 0x00}, {0x0B, 0x8E}, {0x0C, 0x58}, {0x0D, 0x4A}, {0x0E, 0x5D}, {0x0F, 0xE4},
	{0x10, 0x85}, {0x11, 0x04}, {0x12, 0xFA}, {0x13, 0x9D}, {0x14, 0x1B}, {0x15, 0xB6}, {0x16, 0xC7}, {0x17, 0xAC}, {0x18, 0x25}, {0x19, 0x2E}, {0x1A, 0x72}, {0x1B, 0xC2}, {0x1C, 0x02}, {0x1D, 0xFD}, {0x1E, 0xCE}, {0x1F, 0x0D},
	{0x20, 0x5B}, {0x21, 0xE3}, {0x22, 0xD6}, {0x23, 0x12}, {0x24, 0x17}, {0x25, 0xB9}, {0x26, 0x61}, {0x27, 0x81}, {0x28, 0xFE}, {0x29, 0x67}, {0x2A, 0x86}, {0x2B, 0xAD}, {0x2C, 0x71}, {0x2D, 0x6B}, {0x2E, 0x89}, {0x2F, 0x0B},
	{0x30, 0x5C}, {0x31, 0xB0}, {0x32, 0xC0}, {0x33, 0xFF}, {0x34, 0x33}, {0x35, 0xC3}, {0x36, 0x56}, {0x37, 0xB8}, {0x38, 0x35}, {0x39, 0xC4}, {0x3A, 0x05}, {0x3B, 0xAE}, {0x3C, 0xD8}, {0x3D, 0xE0}, {0x3E, 0x7F}, {0x3F, 0x99},
	{0x40, 0xE1}, {0x41, 0x2B}, {0x42, 0xDC}, {0x43, 0x1A}, {0x44, 0xE2}, {0x45, 0x82}, {0x46, 0x57}, {0x47, 0xEC}, {0x48, 0x70}, {0x49, 0x3F}, {0x4A, 0xCC}, {0x4B, 0xF0}, {0x4C, 0x95}, {0x4D, 0xEE}, {0x4E, 0x8D}, {0x4F, 0xF1},
	{0x50, 0xC1}, {0x51, 0xAB}, {0x52, 0x76}, {0x53, 0x38}, {0x54, 0x9F}, {0x55, 0xE6}, {0x56, 0x78}, {0x57, 0xCA}, {0x58, 0xF7}, {0x59, 0xC6}, {0x5A, 0xF8}, {0x5B, 0x60}, {0x5C, 0xD5}, {0x5D, 0xBB}, {0x5E, 0x9C}, {0x5F, 0x4F},
	{0x60, 0xF3}, {0x61, 0x3C}, {0x62, 0x65}, {0x63, 0x7B}, {0x64, 0x63}, {0x65, 0x7C}, {0x66, 0x30}, {0x67, 0x6A}, {0x68, 0xDD}, {0x69, 0x4E}, {0x6A, 0xA7}, {0x6B, 0x79}, {0x6C, 0x9E}, {0x6D, 0xB2}, {0x6E, 0x3D}, {0x6F, 0x31},
	{0x70, 0x3E}, {0x71, 0x98}, {0x72, 0xB5}, {0x73, 0x6E}, {0x74, 0x27}, {0x75, 0xD3}, {0x76, 0xBC}, {0x77, 0xCF}, {0x78, 0x59}, {0x79, 0x1E}, {0x7A, 0x18}, {0x7B, 0x1F}, {0x7C, 0x4C}, {0x7D, 0x5A}, {0x7E, 0xB7}, {0x7F, 0x93},
	{0x80, 0xE9}, {0x81, 0xDE}, {0x82, 0xE7}, {0x83, 0x2C}, {0x84, 0x8F}, {0x85, 0x0C}, {0x86, 0x0F}, {0x87, 0xA6}, {0x88, 0x2D}, {0x89, 0xDB}, {0x8A, 0x49}, {0x8B, 0xF4}, {0x8C, 0x6F}, {0x8D, 0x73}, {0x8E, 0x96}, {0x8F, 0x47},
	{0x90, 0x06}, {0x91, 0x07}, {0x92, 0x53}, {0x93, 0x16}, {0x94, 0xED}, {0x95, 0x24}, {0x96, 0x7A}, {0x97, 0x37}, {0x98, 0x39}, {0x99, 0xCB}, {0x9A, 0xA3}, {0x9B, 0x83}, {0x9C, 0x03}, {0x9D, 0xA9}, {0x9E, 0x8B}, {0x9F, 0xF6},
	{0xA0, 0x92}, {0xA1, 0xBD}, {0xA2, 0x9B}, {0xA3, 0x1C}, {0xA4, 0xE5}, {0xA5, 0xD1}, {0xA6, 0x41}, {0xA7, 0x01}, {0xA8, 0x54}, {0xA9, 0x45}, {0xAA, 0xFB}, {0xAB, 0xC9}, {0xAC, 0x5E}, {0xAD, 0x4D}, {0xAE, 0x0E}, {0xAF, 0xF2},
	{0xB0, 0x68}, {0xB1, 0x20}, {0xB2, 0x80}, {0xB3, 0xAA}, {0xB4, 0x22}, {0xB5, 0x7D}, {0xB6, 0x64}, {0xB7, 0x2F}, {0xB8, 0x26}, {0xB9, 0x87}, {0xBA, 0xF9}, {0xBB, 0x34}, {0xBC, 0x90}, {0xBD, 0x40}, {0xBE, 0x55}, {0xBF, 0x11},
	{0xC0, 0xBE}, {0xC1, 0x32}, {0xC2, 0x97}, {0xC3, 0x13}, {0xC4, 0x43}, {0xC5, 0xFC}, {0xC6, 0x9A}, {0xC7, 0x48}, {0xC8, 0xA0}, {0xC9, 0x2A}, {0xCA, 0x88}, {0xCB, 0x5F}, {0xCC, 0x19}, {0xCD, 0x4B}, {0xCE, 0x09}, {0xCF, 0xA1},
	{0xD0, 0x7E}, {0xD1, 0xCD}, {0xD2, 0xA4}, {0xD3, 0xD0}, {0xD4, 0x15}, {0xD5, 0x44}, {0xD6, 0xAF}, {0xD7, 0x8C}, {0xD8, 0xA5}, {0xD9, 0x84}, {0xDA, 0x50}, {0xDB, 0xBF}, {0xDC, 0x66}, {0xDD, 0xD2}, {0xDE, 0xE8}, {0xDF, 0x8A},
	{0xE0, 0xA2}, {0xE1, 0xD7}, {0xE2, 0x46}, {0xE3, 0x52}, {0xE4, 0x42}, {0xE5, 0xA8}, {0xE6, 0xDF}, {0xE7, 0xB3}, {0xE8, 0x69}, {0xE9, 0x74}, {0xEA, 0xC5}, {0xEB, 0x51}, {0xEC, 0xEB}, {0xED, 0x23}, {0xEE, 0x29}, {0xEF, 0x21},
	{0xF0, 0xD4}, {0xF1, 0xEF}, {0xF2, 0xD9}, {0xF3, 0xB4}, {0xF4, 0x3A}, {0xF5, 0x62}, {0xF6, 0x28}, {0xF7, 0x75}, {0xF8, 0x91}, {0xF9, 0x14}, {0xFA, 0x10}, {0xFB, 0xEA}, {0xFC, 0x77}, {0xFD, 0x6C}, {0xFE, 0xDA}, {0xFF, 0x1D}
};

void checkHTable()
{
	std::cout << "size: " << H_TABLE.size() << '\n';
	int duplicates{};

	for (const auto& it1 : H_TABLE)
	{
		duplicates = -1;

		for (const auto& it2 : H_TABLE)
		{
			if (it1.second == it2.second)
				++duplicates;
		}

		std::cout << "For " << static_cast<int>(it1.second) << "\t" << duplicates << " duplicates in H_TABLE\n";
	}
}

uint32_t getLeftCicleRotationResult(uint8_t r, uint8_t u1, uint8_t u2, uint8_t u3, uint8_t u4)
{
	uint32_t argument{ (static_cast<uint32_t>(H_TABLE.at(u1)) << 24)
		| (static_cast<uint32_t>(H_TABLE.at(u2)) << 16)
		| (static_cast<uint32_t>(H_TABLE.at(u3)) << 8)
		| static_cast<uint32_t>(H_TABLE.at(u4)) };

	return (argument << r) | (argument >> (32 - r));
}

void printABCDE(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
{
	std::cout << '\n';
	std::cout << "a\t" << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << a << '\n';
	std::cout << "b\t" << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << b << '\n';
	std::cout << "c\t" << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << c << '\n';
	std::cout << "d\t" << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << d << '\n';
	std::cout << "e\t" << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << e << '\n';
	std::cout << '\n';
}

void printKArray(const uint32_t* k)
{
	std::cout << "K array:\n";

	for (int i{ 0 }; i < 56; i += 8)
	{
		std::cout << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << k[i] << ' ';
		std::cout << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << k[i + 1] << ' ';
		std::cout << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << k[i + 2] << ' ';
		std::cout << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << k[i + 3] << ' ';
		std::cout << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << k[i + 4] << ' ';
		std::cout << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << k[i + 5] << ' ';
		std::cout << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << k[i + 6] << ' ';
		std::cout << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << k[i + 7] << '\n';
	}
}

uint32_t convertLittleBigEndian(uint32_t value)
{
	return ((value & 0xFF) << 24)
		| ((value & 0xFF00) << 8)
		| ((value & 0xFF0000) >> 8)
		| ((value & 0xFF000000) >> 24);
}

Block128 encryptBlock(const Block128& block, const EncryptKey256& key)
{
	uint32_t x1{ (static_cast<uint32_t>(block.m_data[0]) << 24)
	| (static_cast<uint32_t>(block.m_data[1]) << 16) 
	| (static_cast<uint32_t>(block.m_data[2]) << 8) 
	| static_cast<uint32_t>(block.m_data[3]) };

	uint32_t x2{ (static_cast<uint32_t>(block.m_data[4]) << 24)
	| (static_cast<uint32_t>(block.m_data[5]) << 16)
	| (static_cast<uint32_t>(block.m_data[6]) << 8)
	| static_cast<uint32_t>(block.m_data[7]) };

	uint32_t x3{ (static_cast<uint32_t>(block.m_data[8]) << 24)
	| (static_cast<uint32_t>(block.m_data[9]) << 16)
	| (static_cast<uint32_t>(block.m_data[10]) << 8)
	| static_cast<uint32_t>(block.m_data[11]) };

	uint32_t x4{ (static_cast<uint32_t>(block.m_data[12]) << 24)
	| (static_cast<uint32_t>(block.m_data[13]) << 16)
	| (static_cast<uint32_t>(block.m_data[14]) << 8)
	| static_cast<uint32_t>(block.m_data[15]) };

	x1 = convertLittleBigEndian(x1);
	x2 = convertLittleBigEndian(x2);
	x3 = convertLittleBigEndian(x3);
	x4 = convertLittleBigEndian(x4);

	uint32_t o1{ (static_cast<uint32_t>(key.m_data[0]) << 24)
	| (static_cast<uint32_t>(key.m_data[1]) << 16)
	| (static_cast<uint32_t>(key.m_data[2]) << 8)
	| static_cast<uint32_t>(key.m_data[3]) };

	uint32_t o2{ (static_cast<uint32_t>(key.m_data[4]) << 24)
	| (static_cast<uint32_t>(key.m_data[5]) << 16)
	| (static_cast<uint32_t>(key.m_data[6]) << 8)
	| static_cast<uint32_t>(key.m_data[7]) };

	uint32_t o3{ (static_cast<uint32_t>(key.m_data[8]) << 24)
	| (static_cast<uint32_t>(key.m_data[9]) << 16)
	| (static_cast<uint32_t>(key.m_data[10]) << 8)
	| static_cast<uint32_t>(key.m_data[11]) };

	uint32_t o4{ (static_cast<uint32_t>(key.m_data[12]) << 24)
	| (static_cast<uint32_t>(key.m_data[13]) << 16)
	| (static_cast<uint32_t>(key.m_data[14]) << 8)
	| static_cast<uint32_t>(key.m_data[15]) };

	uint32_t o5{ (static_cast<uint32_t>(key.m_data[16]) << 24)
	| (static_cast<uint32_t>(key.m_data[17]) << 16)
	| (static_cast<uint32_t>(key.m_data[18]) << 8)
	| static_cast<uint32_t>(key.m_data[19]) };

	uint32_t o6{ (static_cast<uint32_t>(key.m_data[20]) << 24)
	| (static_cast<uint32_t>(key.m_data[21]) << 16)
	| (static_cast<uint32_t>(key.m_data[22]) << 8)
	| static_cast<uint32_t>(key.m_data[23]) };

	uint32_t o7{ (static_cast<uint32_t>(key.m_data[24]) << 24)
	| (static_cast<uint32_t>(key.m_data[25]) << 16)
	| (static_cast<uint32_t>(key.m_data[26]) << 8)
	| static_cast<uint32_t>(key.m_data[27]) };

	uint32_t o8{ (static_cast<uint32_t>(key.m_data[28]) << 24)
	| (static_cast<uint32_t>(key.m_data[29]) << 16)
	| (static_cast<uint32_t>(key.m_data[30]) << 8)
	| static_cast<uint32_t>(key.m_data[31]) };

	o1 = convertLittleBigEndian(o1);
	o2 = convertLittleBigEndian(o2);
	o3 = convertLittleBigEndian(o3);
	o4 = convertLittleBigEndian(o4);
	o5 = convertLittleBigEndian(o5);
	o6 = convertLittleBigEndian(o6);
	o7 = convertLittleBigEndian(o7);
	o8 = convertLittleBigEndian(o8);

	uint32_t k[56]{};
	for (int i{ 0 }; i < 56; i += 8)
	{
		k[i] = o1;
		k[i + 1] = o2;
		k[i + 2] = o3;
		k[i + 3] = o4;
		k[i + 4] = o5;
		k[i + 5] = o6;
		k[i + 6] = o7;
		k[i + 7] = o8;
	}

	uint32_t temp{};
	uint32_t e{};
	std::cout << '\n';

	for (uint32_t i{ 1 }; i <= 8; ++i)
	{
		//1
		temp = x1 + k[7 * i - 7];
		x2 = x2 ^ getLeftCicleRotationResult(5, static_cast<uint8_t>(temp >> 24)
			, static_cast<uint8_t>(temp >> 16)
			, static_cast<uint8_t>(temp >> 8)
			, static_cast<uint8_t>(temp));
		
		if (i == 1)
		{
			std::cout << "\t1 operation, first iteration\n";
			printABCDE(convertLittleBigEndian(x1),
				convertLittleBigEndian(x2),
				convertLittleBigEndian(x3),
				convertLittleBigEndian(x4),
				convertLittleBigEndian(e));
		}

		//2
		temp = x4 + k[7 * i - 6];
		x3 = x3 ^ getLeftCicleRotationResult(21, static_cast<uint8_t>(temp >> 24)
			, static_cast<uint8_t>(temp >> 16)
			, static_cast<uint8_t>(temp >> 8)
			, static_cast<uint8_t>(temp));

		if (i == 1)
		{
			std::cout << "\t2 operation, first iteration\n";
			printABCDE(convertLittleBigEndian(x1),
				convertLittleBigEndian(x2),
				convertLittleBigEndian(x3),
				convertLittleBigEndian(x4),
				convertLittleBigEndian(e));
		}

		//3
		temp = x2 + k[7 * i - 5];
		x1 = x1 - getLeftCicleRotationResult(13, static_cast<uint8_t>(temp >> 24)
			, static_cast<uint8_t>(temp >> 16)
			, static_cast<uint8_t>(temp >> 8)
			, static_cast<uint8_t>(temp));

		if (i == 1)
		{
			std::cout << "\t3 operation, first iteration\n";
			printABCDE(convertLittleBigEndian(x1),
				convertLittleBigEndian(x2),
				convertLittleBigEndian(x3),
				convertLittleBigEndian(x4),
				convertLittleBigEndian(e));
		}

		//4
		temp = x2 + x3 + k[7 * i - 4];
		e = i ^ getLeftCicleRotationResult(21, static_cast<uint8_t>(temp >> 24)
			, static_cast<uint8_t>(temp >> 16)
			, static_cast<uint8_t>(temp >> 8)
			, static_cast<uint8_t>(temp));

		if (i == 1)
		{
			std::cout << "\t4 operation, first iteration\n";
			printABCDE(convertLittleBigEndian(x1),
				convertLittleBigEndian(x2),
				convertLittleBigEndian(x3),
				convertLittleBigEndian(x4),
				convertLittleBigEndian(e));
		}

		//5
		x2 = x2 + e;

		if (i == 1)
		{
			std::cout << "\t5 operation, first iteration\n";
			printABCDE(convertLittleBigEndian(x1),
				convertLittleBigEndian(x2),
				convertLittleBigEndian(x3),
				convertLittleBigEndian(x4),
				convertLittleBigEndian(e));
		}

		//6
		x3 = x3 - e;

		if (i == 1)
		{
			std::cout << "\t6 operation, first iteration\n";
			printABCDE(convertLittleBigEndian(x1),
				convertLittleBigEndian(x2),
				convertLittleBigEndian(x3),
				convertLittleBigEndian(x4),
				convertLittleBigEndian(e));
		}

		//7
		temp = x3 + k[7 * i - 3];
		x4 = x4 + getLeftCicleRotationResult(13, static_cast<uint8_t>(temp >> 24)
			, static_cast<uint8_t>(temp >> 16)
			, static_cast<uint8_t>(temp >> 8)
			, static_cast<uint8_t>(temp));

		if (i == 1)
		{
			std::cout << "\t7 operation, first iteration\n";
			printABCDE(convertLittleBigEndian(x1),
				convertLittleBigEndian(x2),
				convertLittleBigEndian(x3),
				convertLittleBigEndian(x4),
				convertLittleBigEndian(e));
		}

		//8
		temp = x1 + k[7 * i - 2];
		x2 = x2 ^ getLeftCicleRotationResult(21, static_cast<uint8_t>(temp >> 24)
			, static_cast<uint8_t>(temp >> 16)
			, static_cast<uint8_t>(temp >> 8)
			, static_cast<uint8_t>(temp));

		if (i == 1)
		{
			std::cout << "\t8 operation, first iteration\n";
			printABCDE(convertLittleBigEndian(x1),
				convertLittleBigEndian(x2),
				convertLittleBigEndian(x3),
				convertLittleBigEndian(x4),
				convertLittleBigEndian(e));
		}

		//9
		temp = x4 + k[7 * i - 1];
		x3 = x3 ^ getLeftCicleRotationResult(5, static_cast<uint8_t>(temp >> 24)
			, static_cast<uint8_t>(temp >> 16)
			, static_cast<uint8_t>(temp >> 8)
			, static_cast<uint8_t>(temp));

		if (i == 1)
		{
			std::cout << "\t9 operation, first iteration\n";
			printABCDE(convertLittleBigEndian(x1),
				convertLittleBigEndian(x2),
				convertLittleBigEndian(x3),
				convertLittleBigEndian(x4),
				convertLittleBigEndian(e));
		}

		//10
		temp = x1;
		x1 = x2;
		x2 = temp;

		if (i == 1)
		{
			std::cout << "\t10 operation, first iteration\n";
			printABCDE(convertLittleBigEndian(x1),
				convertLittleBigEndian(x2),
				convertLittleBigEndian(x3),
				convertLittleBigEndian(x4),
				convertLittleBigEndian(e));
		}

		//11
		temp = x3;
		x3 = x4;
		x4 = temp;

		if (i == 1)
		{
			std::cout << "\t11 operation, first iteration\n";
			printABCDE(convertLittleBigEndian(x1),
				convertLittleBigEndian(x2),
				convertLittleBigEndian(x3),
				convertLittleBigEndian(x4),
				convertLittleBigEndian(e));
		}

		//12
		temp = x2;
		x2 = x3;
		x3 = temp;

		if (i == 1)
		{
			std::cout << "\t12 operation, first iteration\n";
			printABCDE(convertLittleBigEndian(x1),
				convertLittleBigEndian(x2),
				convertLittleBigEndian(x3),
				convertLittleBigEndian(x4),
				convertLittleBigEndian(e));
		}

		std::cout << '\t' << i << " iteration\n";
		printABCDE(convertLittleBigEndian(x1),
			convertLittleBigEndian(x2),
			convertLittleBigEndian(x3),
			convertLittleBigEndian(x4),
			convertLittleBigEndian(e));
	}

	x1 = convertLittleBigEndian(x1);
	x2 = convertLittleBigEndian(x2);
	x3 = convertLittleBigEndian(x3);
	x4 = convertLittleBigEndian(x4);

	Block128 result;
	result.m_data = new unsigned char[result.m_size] { static_cast<unsigned char>(x2 >> 24), static_cast<unsigned char>(x2 >> 16), static_cast<unsigned char>(x2 >> 8), static_cast<unsigned char>(x2),
		static_cast<unsigned char>(x4 >> 24), static_cast<unsigned char>(x4 >> 16), static_cast<unsigned char>(x4 >> 8), static_cast<unsigned char>(x4),
		static_cast<unsigned char>(x1 >> 24), static_cast<unsigned char>(x1 >> 16), static_cast<unsigned char>(x1 >> 8), static_cast<unsigned char>(x1), 
		static_cast<unsigned char>(x3 >> 24), static_cast<unsigned char>(x3 >> 16), static_cast<unsigned char>(x3 >> 8), static_cast<unsigned char>(x3), };

	return result;
}

void printBytesInHexFormat(const unsigned char* block, int size)
{
	for (int i{ 0 }; i < size; ++i)
	{
		std::cout << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << static_cast<int>(block[i]);
		if ((i + 1) % 4 == 0)
			std::cout << ' ';
	}
}

int main(int argc, char* argv[])
{
	Block128 block;
	block.m_data = new unsigned char[block.m_size] { 0xB1, 0x94, 0xBA, 0xC8,
		0x0A, 0x08, 0xF5, 0x3B, 
		0x36, 0x6D, 0x00, 0x8E, 
		0x58, 0x4A, 0x5D, 0xE4 };

	EncryptKey256 encryptKey;
	encryptKey.m_data = new unsigned char[encryptKey.m_size] { 0xE9, 0xDE, 0xE7, 0x2C,
		0x8F, 0x0C, 0x0F, 0xA6,
		0x2D, 0xDB, 0x49, 0xF4,
		0x6F, 0x73, 0x96, 0x47,
		0x06, 0x07, 0x53, 0x16,
		0xED, 0x24, 0x7A, 0x37,
		0x39, 0xCB, 0xA3, 0x83,
		0x03, 0xA9, 0x8B, 0xF6 };

	std::cout << "Block is: ";
	printBytesInHexFormat(block.m_data, block.m_size);
	std::cout << '\n';

	std::cout << "Key is: ";
	printBytesInHexFormat(encryptKey.m_data, encryptKey.m_size);
	std::cout << '\n';

	auto result{ encryptBlock(block, encryptKey) };

	std::cout << "Result is: ";
	printBytesInHexFormat(result.m_data, result.m_size);
	std::cout << '\n';

	return 0;
}