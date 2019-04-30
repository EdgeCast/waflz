//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    md5.h
//: \details: TODO
//: \author:  David Andrews
//: \date:    02/07/2014
//:
//:   Licensed under the Apache License, Version 2.0 (the "License");
//:   you may not use this file except in compliance with the License.
//:   You may obtain a copy of the License at
//:
//:       http://www.apache.org/licenses/LICENSE-2.0
//:
//:   Unless required by applicable law or agreed to in writing, software
//:   distributed under the License is distributed on an "AS IS" BASIS,
//:   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//:   See the License for the specific language governing permissions and
//:   limitations under the License.
//:
//: ----------------------------------------------------------------------------
#ifndef _MD5_H_
#define _MD5_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <openssl/md5.h>
#include <stdint.h>
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: md5 hasher obj
//: ----------------------------------------------------------------------------
class md5
{
public:
        // -------------------------------------------------
        // public constants
        // -------------------------------------------------
        static const uint16_t s_hash_len = 16;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        //: ------------------------------------------------
        //: \details TODO
        //: \return  TODO
        //: ------------------------------------------------
        md5():
                m_ctx(),
                m_finished(false),
                m_hash_hex()
        {
                MD5_Init(&m_ctx);
        }
        //: ------------------------------------------------
        //: \details TODO
        //: \return  TODO
        //: ------------------------------------------------
        void update(const char* a_str, unsigned int a_len)
        {
                MD5_Update(&m_ctx, (const unsigned char*)a_str, a_len);
        }
        //: ------------------------------------------------
        //: \details TODO
        //: \return  TODO
        //: ------------------------------------------------
        void finish()
        {
                if(m_finished)
                {
                        return;
                }
                MD5_Final((unsigned char *)m_hash, &m_ctx);
                static const char s_hexchars[] =
                {
                        '0', '1', '2', '3',
                        '4', '5', '6', '7',
                        '8', '9', 'a', 'b',
                        'c', 'd', 'e', 'f'
                };
                for(size_t i = 0; i < s_hash_len; ++i)
                {
                        m_hash_hex[2 * i + 0] = s_hexchars[(m_hash[i] & 0xf0) >> 4];
                        m_hash_hex[2 * i + 1] = s_hexchars[m_hash[i] & 0x0f];
                }
                m_hash_hex[32] = '\0';
                m_finished = true;
        }
        //: ------------------------------------------------
        //: \details TODO
        //: \return  TODO
        //: ------------------------------------------------
        const char* get_hash_hex()
        {
                finish();
                return m_hash_hex;
        }
        //: ------------------------------------------------
        //: \details TODO
        //: \return  TODO
        //: ------------------------------------------------
        const unsigned char* get_hash()
        {
                finish();
                return m_hash;
        }
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        md5(const md5&);
        md5& operator=(const md5&);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        MD5_CTX m_ctx;
        bool m_finished;
        unsigned char m_hash[s_hash_len];
        char m_hash_hex[33];
};
}
#endif // _MD5_HASHER_H_
