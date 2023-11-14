#pragma once

/* --------------------------------- ABOUT -------------------------------------

Original Author: Adam Yaxley
Website: https://github.com/adamyaxley
License: See end of file

Unified Version Author: Unam Sanctam
Website: https://github.com/UnamSanctam
License: See end of file

Current unified version is stripped of some functions that the original version has but those can be re-added easily if wanted.

----------------------------------------------------------------------------- */

#ifndef AYU_OBF_DEF_KEY
	#define AYU_OBF_DEF_KEY ayu::generate_key(__LINE__)
#endif

namespace ayu {
	using size_type = unsigned long long;
	using key_type = unsigned long long;

	constexpr key_type generate_key(key_type seed) {
		key_type key = seed;
		key ^= (key >> 33);
		key *= 0xff51afd7ed558ccd;
		key ^= (key >> 33);
		key *= 0xc4ceb9fe1a85ec53;
		key ^= (key >> 33);

		key |= 0x0101010101010101ull;

		return key;
	}

	template <typename CharT, size_type N, key_type KEY>
	class obfuscator {
	public:
		constexpr obfuscator(const CharT* data) {
			for (size_type i = 0; i < N; i++) {
				m_data[i] = (data[i] + KEY) % 256;
			}
		}

		constexpr const CharT* data() const {
			return &m_data[0];
		}
	private:
		CharT m_data[N]{};
	};

	template <typename CharT, size_type N, key_type KEY>
	class obfuscated_data {
	public:
		obfuscated_data(const obfuscator<CharT, N, KEY>& obfuscator) {
			for (size_type i = 0; i < N; i++) {
				m_data[i] = obfuscator.data()[i];
			}
		}

		~obfuscated_data() {
			for (size_type i = 0; i < N; i++) {
				m_data[i] = 0;
			}
		}

		operator CharT*() {
			if (m_encrypted) {
				for (size_type i = 0; i < N; i++) {
					m_data[i] = (m_data[i] - KEY + 256) % 256;
				}
				m_encrypted = false;
			}
			return m_data;
		}
	private:
		CharT m_data[N];
		bool m_encrypted{ true };
	};

	template <key_type KEY>
	class obfuscated_constant {
	public:
		constexpr obfuscated_constant(key_type value) : m_encryptedValue(value + KEY) {}

		operator key_type() const {
			return m_encryptedValue - KEY;
		}
	private:
		key_type m_encryptedValue;
	};
}

#define AYU_OBFA(data) AYU_OBFK(char, data, AYU_OBF_DEF_KEY)
#define AYU_OBFW(data) AYU_OBFK(wchar_t, data, AYU_OBF_DEF_KEY)

#define AYU_OBFK(CharT, data, key) \
	[]() -> ayu::obfuscated_data<CharT, sizeof(data)/sizeof(data[0]), key>& { \
		constexpr auto n = sizeof(data)/sizeof(data[0]); \
		constexpr auto obfuscator = ayu::obfuscator<CharT, n, key>(data); \
		static auto obfuscated_data = ayu::obfuscated_data<CharT, n, key>(obfuscator); \
		return obfuscated_data; \
	}()

#define AYU_OBFC(value) \
    []() -> ayu::obfuscated_constant<AYU_OBF_DEF_KEY>& { \
        static auto obfuscated_const = ayu::obfuscated_constant<AYU_OBF_DEF_KEY>(value); \
        return obfuscated_const; \
    }()

/* -------------------------------- LICENSE ------------------------------------

Public Domain (http://www.unlicense.org)

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.

In jurisdictions that recognize copyright laws, the author or authors of this
software dedicate any and all copyright interest in the software to the public
domain. We make this dedication for the benefit of the public at large and to
the detriment of our heirs and successors. We intend this dedication to be an
overt act of relinquishment in perpetuity of all present and future rights to
this software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

----------------------------------------------------------------------------- */