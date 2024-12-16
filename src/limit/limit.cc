//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <cmath>
#include "support/ndebug.h"
#include "jspb/jspb.h"
#include "waflz/city.h"
#include "waflz/limit.h"
#include "waflz/kv_db.h"
#include "rapidjson/document.h"
#include "rapidjson/error/error.h"
#include "rapidjson/error/en.h"
#include "limit.pb.h"
#include <string_view>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
// the maximum size of the json defining configuration for a ddos enforcement (1MB)
#define _CONFIG_MAX_SIZE (1<<20)
#define _MAX_KEY_LEN 1024
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define _GET_HEADER(_header) do { \
    l_d.m_data = _header; \
    l_d.m_len = sizeof(_header) - 1; \
    data_unordered_map_t::const_iterator i_h = a_ctx->m_header_map.find(l_d); \
    if(i_h != a_ctx->m_header_map.end()) \
    { \
            l_v.m_data = i_h->second.m_data; \
            l_v.m_len = i_h->second.m_len; \
    } \
    } while(0)
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
limit::limit(kv_db &a_db,
             bool a_case_insensitive_headers):
        rl_obj(a_case_insensitive_headers),
        m_init(false),
        m_pb(NULL),
        m_db(a_db),
        m_id(),
        m_cust_id(),
        m_team_config(false),
        m_enable_pop_count(false),
        m_status_codes()
{
        m_pb = new waflz_pb::limit();
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
limit::~limit()
{
        if(m_pb) { delete m_pb; m_pb = NULL; }
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t limit::load(const char *a_buf, uint32_t a_buf_len)
{
        if(a_buf_len > _CONFIG_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg, "config file size(%u) > max size(%u)",
                             a_buf_len,
                             _CONFIG_MAX_SIZE);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        rapidjson::Document *l_js = new rapidjson::Document();
        rapidjson::ParseResult l_ok;
        l_ok = l_js->Parse(a_buf, a_buf_len);
        if (!l_ok)
        {
                WAFLZ_PERROR(m_err_msg, "JSON parse error: %s (%d)",
                             rapidjson::GetParseError_En(l_ok.Code()), (int)l_ok.Offset());
                if(l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // load...
        // -------------------------------------------------
        int32_t l_s;
        l_s = load((void *)l_js);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_js) { delete l_js; l_js = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        if(l_js) { delete l_js; l_js = NULL; }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t limit::load(void *a_js)
{
        const rapidjson::Value &l_js = *((rapidjson::Value *)a_js);
        // -------------------------------------------------
        // load pbuf
        // -------------------------------------------------
        int32_t l_s;
        l_s = update_from_json(*m_pb, l_js);
        if(l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // init...
        // -------------------------------------------------
        l_s = init();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details parses the buffer and loads the waflz client_waf proto
//! \return  waflz status code
//! \param   a_pb: a limit protobuf
//! ----------------------------------------------------------------------------
int32_t limit::load(waflz_pb::limit* a_pb)
{
        // -------------------------------------------------
        // quick exit if no proto was passed
        // -------------------------------------------------
        if (!a_pb)
        {
                WAFLZ_PERROR(m_err_msg, "a_pb == nullptr");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // remove old proto and create a new proto
        // -------------------------------------------------
        if (m_pb) { delete m_pb; m_pb = nullptr; }
        m_pb = new waflz_pb::limit();
        m_pb->CopyFrom(*a_pb);
        // -------------------------------------------------
        // initalize the object
        // -------------------------------------------------
        m_init = false;
        return init();
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
const std::string& limit::get_last_modified_date()
{
        if(m_pb &&
           m_pb->has_last_modified_date())
        {
                return m_pb->last_modified_date();
        }
        static std::string s_ret = "";
        return s_ret;
}
//! ----------------------------------------------------------------------------
//! @details creates a status_code_range_t for a given token and saves it to
//! the m_status_codes member
//! @return  waflz status
//! @param   std::string& a_token - the token to parse
//! ----------------------------------------------------------------------------
int32_t limit::load_status_codes_token( const std::string& a_token )
{
        // -------------------------------------------------
        // quick check for empty string
        // -------------------------------------------------
        if ( a_token.empty() ) { return WAFLZ_STATUS_ERROR; }
        // -------------------------------------------------
        // bits need to parse token
        // -------------------------------------------------
        uint64_t l_temp_store;
        uint32_t l_start, l_stop;
        char* l_error_chk;
        size_t l_pos;
        // -------------------------------------------------
        // check if we are dealing with a range
        // -------------------------------------------------
        if ( (l_pos = a_token.find("-")) != std::string::npos )
        {
                // -----------------------------------------
                // error checking
                //
                // we want complete ranges. nothing like:
                // "-1" or "1-"
                // -----------------------------------------
                if ( l_pos == 0 || l_pos == a_token.length()-1 )
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // grab the beginning of the range
                // -----------------------------------------
                const std::string l_start_of_range = a_token.substr(0, l_pos);
                l_temp_store = std::strtoul(l_start_of_range.c_str(), &l_error_chk, 10);
                // -----------------------------------------
                // error checking
                // -----------------------------------------
                if ((*l_error_chk) ||(l_temp_store >= UINT32_MAX))
                {
                        return WAFLZ_STATUS_ERROR;
                }
                l_start = (uint32_t) l_temp_store;
                // -----------------------------------------
                // grab the end of the range
                // -----------------------------------------
                const char* l_end_of_range = a_token.c_str() + l_pos + 1;
                l_temp_store = std::strtoul(l_end_of_range, &l_error_chk, 10);
                // -----------------------------------------
                // error checking
                // -----------------------------------------
                if ((*l_error_chk) ||(l_temp_store >= UINT32_MAX))
                {
                        return WAFLZ_STATUS_ERROR;
                }
                l_stop = (uint32_t) l_temp_store;
        }
        else
        {
                // -----------------------------------------
                // treat token as number
                // -----------------------------------------
                l_temp_store = std::strtoul(a_token.c_str(), &l_error_chk, 10);
                // -----------------------------------------
                // error checking
                // -----------------------------------------
                if ((*l_error_chk) ||(l_temp_store >= UINT32_MAX))
                {
                        return WAFLZ_STATUS_ERROR;
                }
                l_start = l_stop = (uint32_t) l_temp_store;
        }
        // -------------------------------------------------
        // error checking
        // -------------------------------------------------
        if((l_start == ULONG_MAX) || (l_stop  == ULONG_MAX))
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // being nice - flip range if they gave it
        // backwards
        // -------------------------------------------------
        if (l_start > l_stop) { std::swap(l_start, l_stop); }
        // -------------------------------------------------
        // add new entry and true done!
        // -------------------------------------------------
        m_status_codes.emplace_back(l_start, l_stop);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details parses the status_code key and creates all the status_code_range_ts
//! @return  waflz status
//! @param   std::string& a_input - the status code key
//! ----------------------------------------------------------------------------
int32_t limit::load_status_codes_key( const std::string& a_input )
{
        // -------------------------------------------------
        // load input into a stream
        // -------------------------------------------------
        std::istringstream l_status_codes( a_input.c_str() + sizeof("STATUS_CODE:") - 1 );
        // -------------------------------------------------
        // parse token from the stream
        // -------------------------------------------------
        std::string l_token;
        while ( std::getline(l_status_codes, l_token, ',') )
        {
                if (load_status_codes_token( l_token ) != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg,
                                "failed to parse token: '%s' in entry: '%s'",
                                l_token.c_str(), a_input.c_str());
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // return success
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t limit::init()
{
        if(m_init)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // *************************************************
        //              V A L I D A T I O N
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // has id
        // -------------------------------------------------
        if(!m_pb->has_id() ||
            m_pb->id().empty())
        {
                WAFLZ_PERROR(m_err_msg, "missing id field or empty");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // has num
        // -------------------------------------------------
        if(!m_pb->has_num() ||
           (m_pb->num() <= 0))
        {
                WAFLZ_PERROR(m_err_msg, "limit missing num field or num is <= 0");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // has duration
        // -------------------------------------------------
        if(!m_pb->has_duration_sec())
        {
                WAFLZ_PERROR(m_err_msg, "limit missing duration field");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // set id and cust_id
        // -------------------------------------------------
        m_id = m_pb->id();
        m_cust_id = m_pb->customer_id();
        if(m_pb->has_team_config())
        {
                m_team_config = m_pb->team_config();
        }
        if(m_pb->has_enable_pop_count())
        {
                m_enable_pop_count = m_pb->enable_pop_count();
        }
        // -------------------------------------------------
        // validate fields in keys
        // -------------------------------------------------
        for (int i_r = 0; i_r < m_pb->keys_size(); ++i_r)
        {
                const std::string& l_e = m_pb->keys(i_r);
                if (
                        strcasecmp(l_e.c_str(), "IP") == 0 ||
                        strcasecmp(l_e.c_str(), "USER_AGENT") == 0 ||
                        strcasecmp(l_e.c_str(), "ASN") == 0 ||
                        strcasecmp(l_e.c_str(), "JA3") == 0 ||
                        strcasecmp(l_e.c_str(), "JA4") == 0 ||
                        strncasecmp(l_e.c_str(), "HEADER:", (sizeof("HEADER:") - 1)) == 0 ||
                        strncasecmp(l_e.c_str(), "COOKIE:", (sizeof("COOKIE:") - 1)) == 0 ||
                        strncasecmp(l_e.c_str(), "ARGS:", (sizeof("ARGS:") - 1)) == 0
                )
                {
                        continue;
                }
                // -----------------------------------------
                // special case - response codes need to be
                // parsed
                // -----------------------------------------
                if (strncasecmp(l_e.c_str(), "STATUS_CODE:", (sizeof("STATUS_CODE:") - 1)) == 0)
                {
                        // ---------------------------------
                        // parse status code key
                        // ---------------------------------
                        if (load_status_codes_key(l_e) != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        continue;
                }
                // -----------------------------------------
                // unknown key type
                // -----------------------------------------
                WAFLZ_PERROR(m_err_msg, "failed to identify type of key: '%s'", l_e.c_str());
                return WAFLZ_STATUS_ERROR;
        }
        // *************************************************
        //                C O M P I L E
        // *************************************************
        // -------------------------------------------------
        int32_t l_s;
        l_s = compile_limit(*m_pb);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "compiling limit");
                return WAFLZ_STATUS_ERROR;
        }
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t limit::process(bool &ao_exceeds,
                       const waflz_pb::condition_group** ao_cg,
                       const std::string& a_scope_id,
                       rqst_ctx* a_ctx,
                       bool a_increment_key)
{
        // -------------------------------------------------
        // sanity check...
        // -------------------------------------------------
        if(!ao_cg)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_cg = NULL;
        // init to false
        ao_exceeds = false;
        // -------------------------------------------------
        // overall algorithm:
        //   ...
        //   If a limit match indicates entire limit matched
        //     Construct db key
        //     Increment key value in db
        //     If value above limits limit
        //       Record limit being exceeded
        //   If limit exceeded for customer
        //     synthesize into enforcement config
        //   ...
        // -------------------------------------------------
        if(!m_pb)
        {
                // TODO log error reason
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // limits...
        // -------------------------------------------------
        waflz_pb::limit &i_limit = *m_pb;
        // -------------------------------------------------
        // disabled???
        // -------------------------------------------------
        if(i_limit.has_disabled() &&
           i_limit.disabled())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // match-less limits...
        // -------------------------------------------------
        if(i_limit.condition_groups_size() == 0)
        {
                // -----------------------------------------
                // ****************MATCH********************
                // -----------------------------------------
                // TODO log?
                // TRC_DEBUG("Matched enforcement limit completely!\n");
                int32_t l_s;
                if (a_increment_key)
                {
                        l_s = incr_key(ao_exceeds, a_scope_id, a_ctx);
                }
                else
                {
                        l_s = key_is_exceeded(ao_exceeds, a_scope_id, a_ctx);
                }
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO log error reason
                        return WAFLZ_STATUS_ERROR;
                }
                if(ao_exceeds)
                {
                        return WAFLZ_STATUS_OK;
                }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // limits w/condition_groups
        // -------------------------------------------------
        // ===================== O R =======================
        // -------------------------------------------------
        for(int i_ms = 0; i_ms < i_limit.condition_groups_size(); ++i_ms)
        {
                //NDBG_PRINT("limit[%d]: limit[%d] process\n", i_t, i_r);
                const waflz_pb::condition_group &l_cg = i_limit.condition_groups(i_ms);
                bool l_matched = false;
                int32_t l_s;
                l_s = process_condition_group(l_matched, l_cg, a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_matched == false)
                {
                        // no match -continue
                        continue;
                }
                //NDBG_PRINT("limit[%d]: limit[%d] MATCHED\n", i_t, i_r);
                // -----------------------------------------
                // ****************MATCH********************
                // -----------------------------------------
                if (a_increment_key)
                {
                        l_s = incr_key(ao_exceeds, a_scope_id, a_ctx);
                }
                else
                {
                        l_s = key_is_exceeded(ao_exceeds, a_scope_id, a_ctx);
                }
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO log error reason
                        return WAFLZ_STATUS_ERROR;
                }
                if(ao_exceeds)
                {
                        *ao_cg = &l_cg;
                        return WAFLZ_STATUS_OK;
                }
                // -----------------------------------------
                // Stop the loop if any condition_group matches
                // -----------------------------------------
                if (l_matched)
                {
                        break;
                }
        }
        return WAFLZ_STATUS_OK;
}
int32_t limit::key_is_exceeded(bool &ao_exceeds,
                               const std::string& a_scope_id,
                               rqst_ctx* a_ctx)
{
        // -------------------------------------------------
        // get key for limit
        // -------------------------------------------------
        // Construct db key eg:
        //   AN:LIMIT_ID:DIM1=DIM1VAL:...DIMN=DIMNVAL
        //
        // if WAFLZ_STATUS_OK is not returned, then not
        // every key was found. in that case we just return
        // -------------------------------------------------
        char l_key[_MAX_KEY_LEN];
        int32_t l_s;
        l_s = get_key(l_key, a_scope_id, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                ao_exceeds = false;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // DEBUG: key
        // -------------------------------------------------
        // NDBG_PRINT("l_key: %s\n", l_key);
        // -------------------------------------------------
        // get key value in db
        // -------------------------------------------------
        int64_t l_cur_num = 0;
        l_s = m_db.get_full_count_for_rl_key(l_cur_num,
                                             l_key,
                                             strlen(l_key),
                                             false);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "Failed to perform db get key for limit id: '%s' key: %s",
                             m_pb->id().c_str(),
                             l_key);
                NDBG_PRINT("error with mdb: %s\n", m_db.get_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // DEBUG: key + value
        // -------------------------------------------------
        // NDBG_PRINT("'%s' = %ld\n", l_key, l_cur_num);
        // -------------------------------------------------
        // check if key is past threshold
        // -------------------------------------------------
        int64_t l_threshold = (int64_t)(m_pb->num());
        if(l_cur_num > l_threshold)
        {
                ao_exceeds = true;
                m_pb->set__reserved_match(std::string(l_key));
        }
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t limit::incr_key(bool &ao_exceeds,
                        const std::string& a_scope_id,
                        rqst_ctx* a_ctx)
{
        // -------------------------------------------------
        // get key for limit
        // -------------------------------------------------
        // Construct db key eg:
        //   AN:LIMIT_ID:DIM1=DIM1VAL:...DIMN=DIMNVAL
        //
        // if WAFLZ_STATUS_OK is not returned, then the not
        // every key was found. in that case we dont
        // increment a key - just return
        // -------------------------------------------------
        char l_key[_MAX_KEY_LEN];
        int32_t l_s;
        l_s = get_key(l_key, a_scope_id, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                ao_exceeds = false;
                return WAFLZ_STATUS_OK;
        }
        // NDBG_PRINT("l_key: %s\n", l_key);
        // -------------------------------------------------
        // increment key value in db
        // -------------------------------------------------
        // increment one of our counters
        // this count automatically rolls over because key
        // includes bucketing information
        // gives historical data as well as auto-rollover
        // -------------------------------------------------
        int64_t l_cur_num = 0;
        int64_t l_threshold = (int64_t)(m_pb->num());
        bool l_is_pop_count_set = false;
        l_s = m_db.increment_key(l_cur_num,
                                 l_key,
                                 m_pb->duration_sec()*1000,
                                 m_enable_pop_count,
                                 l_is_pop_count_set);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "Failed to perform db key increment for limit id: '%s' key: %s",
                             m_pb->id().c_str(),
                             l_key);
                return WAFLZ_STATUS_ERROR;
        }
        // NDBG_PRINT("KEY: %s VAL: %li\n", l_key, l_cur_num);
        // TODO log?
        //TRACE("Incremented time bucket key '%s' count to: %" PRIi64, bucket_key.b_str(), l_current_number);
        // -------------------------------------------------
        // limit is exceeding???
        // -------------------------------------------------
        // -------------------------------------------------
        // If pop_count is enabled and pop count currently
        // set to 0 for this key( very first hit), and if this resource is already hot,
        // which means hot_servers are set to >1. Use hot_server
        // formula to adjust threshold. This is needed for a corner
        // case when a large number of requests are spread around
        // at exactly the same time because the hot-servers are
        // already configured to a value > 1. On the next run
        // redlmd would have updated the pop count and this
        // check will prevent hot-server count formula to be applied
        // -------------------------------------------------
#if 0
        if(m_enable_pop_count &&
           !l_is_pop_count_set &&
           a_ctx->m_actual_hot_servers > 1 &&
           l_threshold > 0)
        {
                
                float l_th_num = static_cast<float>(l_threshold / a_ctx->m_actual_hot_servers);
                // Ceil up the number
                l_threshold = std::ceil(l_th_num) + 10;
        }
#endif
        if(l_cur_num > l_threshold)
        {
                ao_exceeds = true;
                m_pb->set__reserved_match(std::string(l_key));
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t limit::get_key(char* ao_key,
                       const std::string& a_scope_id,
                       rqst_ctx *a_ctx)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        uint64_t l_dim_hash = 0;
        // -------------------------------------------------
        // for each key...
        // -------------------------------------------------
        bool l_all_optional_keys_found = true;
        for(int i_r = 0; i_r < m_pb->keys_size(); ++i_r)
        {
                const std::string& l_e = m_pb->keys(i_r);
                // -----------------------------------------
                // IP
                // -----------------------------------------
                if (strcasecmp(l_e.c_str(), "IP") == 0)
                {
                        const data_t &l_d = a_ctx->m_src_addr;
                        if ( l_d.m_data && l_d.m_len )
                        {
                                l_dim_hash += CityHash64(l_d.m_data, l_d.m_len);
                        }
                }
                // -----------------------------------------
                // user agent
                // -----------------------------------------
                else if (strcasecmp(l_e.c_str(), "USER_AGENT") == 0)
                {
                        const data_t* l_ua = a_ctx->get_header(std::string_view("User-Agent"));
                        if ( l_ua && l_ua->m_data && l_ua->m_len)
                        {
                                l_dim_hash += CityHash64(l_ua->m_data, l_ua->m_len);
                        }
                }
                // -----------------------------------------
                // ASN
                // -----------------------------------------
                else if (strcasecmp(l_e.c_str(), "ASN") == 0)
                {
                        const ns_waflz::mutable_data_t l_asn = a_ctx->m_src_asn_str;
                        if (l_asn.m_data && l_asn.m_len)
                        {
                                l_dim_hash += CityHash64(l_asn.m_data, l_asn.m_len);
                        }
                        else
                        {
                                l_all_optional_keys_found = false;
                                break;
                        }
                }
                // -----------------------------------------
                // JA3
                // -----------------------------------------
                else if (strcasecmp(l_e.c_str(), "JA3") == 0)
                {
                        const data_t& l_d = a_ctx->m_virt_ssl_client_ja3_md5;
                        if (l_d.m_data && l_d.m_len)
                        {
                                l_dim_hash += CityHash64(l_d.m_data, l_d.m_len);
                        }
                        else
                        {
                                l_all_optional_keys_found = false;
                                break;
                        }
                }
                // -----------------------------------------
                // JA4
                // -----------------------------------------
                else if (strcasecmp(l_e.c_str(), "JA4") == 0)
                {
                        const data_t& l_d = a_ctx->m_virt_ssl_client_ja4;
                        if (l_d.m_data && l_d.m_len)
                        {
                                l_dim_hash += CityHash64(l_d.m_data, l_d.m_len);
                        }
                        else
                        {
                                l_all_optional_keys_found = false;
                                break;
                        }
                }
                // -----------------------------------------
                // special case: header
                // -----------------------------------------
                else if (strncasecmp(l_e.c_str(), "HEADER:", (sizeof("HEADER:") - 1)) == 0)
                {
                        std::string_view l_t(l_e.c_str() + (sizeof("HEADER:") - 1));
                        const data_t* l_hv = a_ctx->get_header(l_t);
                        if (l_hv && l_hv->m_data && l_hv->m_len)
                        {
                                l_dim_hash += CityHash64(l_hv->m_data, l_hv->m_len);
                        }
                        else
                        {
                                l_all_optional_keys_found = false;
                                break;
                        }
                }
                // -----------------------------------------
                // special case: cookie
                // -----------------------------------------
                else if (strncasecmp(l_e.c_str(), "COOKIE:", (sizeof("COOKIE:") - 1)) == 0)
                {
                        data_t l_search_val;
                        l_search_val.m_data = l_e.c_str() + (sizeof("COOKIE:") - 1);
                        l_search_val.m_len = l_e.length() - (sizeof("COOKIE:") - 1);
                        const auto l_cookie_val = a_ctx->m_cookie_map.find(l_search_val);
                        if (l_cookie_val != a_ctx->m_cookie_map.end())
                        {
                                l_dim_hash += CityHash64(l_cookie_val->second.m_data, l_cookie_val->second.m_len);
                        }
                        else
                        {
                                l_all_optional_keys_found = false;
                                break;
                        }
                }
                // -----------------------------------------
                // special case: args
                // -----------------------------------------
                else if (strncasecmp(l_e.c_str(), "ARGS:", (sizeof("ARGS:") - 1)) == 0)
                {
                        // ---------------------------------
                        // get search value
                        // ---------------------------------
                        data_t l_search_val;
                        l_search_val.m_data = l_e.c_str() + (sizeof("ARGS:") - 1);
                        l_search_val.m_len = l_e.length() - (sizeof("ARGS:") - 1);
                        // ---------------------------------
                        // hash if found in query map
                        // ---------------------------------
                        const auto l_arg_val = a_ctx->m_query_arg_map.find(l_search_val);
                        if (l_arg_val != a_ctx->m_query_arg_map.end())
                        {
                                l_dim_hash += CityHash64(l_arg_val->second.m_data, l_arg_val->second.m_len);
                                continue;
                        }
                        else
                        {
                                l_all_optional_keys_found = false;
                                break;
                        }
                }
                // -----------------------------------------
                // special case: status codes
                //
                // NOTE: because we are in the request -
                // which has no status code, we assume that
                // the request would trip the limit. this
                // allows us to check the lmdb key in the
                // request phase.
                // -----------------------------------------
                else if (strncasecmp(l_e.c_str(), "STATUS_CODE:", (sizeof("STATUS_CODE:") - 1)) == 0)
                {
                        l_dim_hash += CityHash64(l_e.c_str(), l_e.length());
                }
        }
        // -------------------------------------------------
        // quick return if we were missing a key
        // NOTE: doesnt apply to IP and User-Agent. This is
        // to keep consistent with pervious implementation 
        // -------------------------------------------------
        if (!l_all_optional_keys_found)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // *************************************************
        //                K E Y   F O R M A T
        // *************************************************
        // -------------------------------------------------
        // SF:RL:<CUSTOMER_ID>:<SCOPE_ID>::<LIMIT_ID>:
        // -------------------------------------------------
        if(m_pb->has__reserved_1() &&
           !m_pb->_reserved_1().empty())
        {
                snprintf(ao_key, _MAX_KEY_LEN, "SF:RL:%s:%s:%s:%" PRIX64 "", m_pb->customer_id().c_str(), a_scope_id.c_str(), m_pb->_reserved_1().c_str(), l_dim_hash);
        }
        else
        {
                snprintf(ao_key, _MAX_KEY_LEN, "SF:RL:%s:%s:%s:%" PRIX64 "", m_pb->customer_id().c_str(), a_scope_id.c_str(), m_pb->id().c_str(), l_dim_hash);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t limit::process_response(bool &ao_exceeds,
                                const waflz_pb::condition_group** ao_cg,
                                const std::string& a_scope_id,
                                resp_ctx* a_ctx)
{
        // -------------------------------------------------
        // sanity check...
        // -------------------------------------------------
        if(!ao_cg)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_cg = NULL;
        // init to false
        ao_exceeds = false;
        // -------------------------------------------------
        // overall algorithm:
        //   ...
        //   If a limit match indicates entire limit matched
        //     Construct db key
        //     Increment key value in db
        //     If value above limits limit
        //       Record limit being exceeded
        //   If limit exceeded for customer
        //     synthesize into enforcement config
        //   ...
        // -------------------------------------------------
        if(!m_pb)
        {
                // TODO log error reason
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // limits...
        // -------------------------------------------------
        waflz_pb::limit &i_limit = *m_pb;
        // -------------------------------------------------
        // disabled???
        // -------------------------------------------------
        if(i_limit.has_disabled() &&
           i_limit.disabled())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // match-less limits...
        // -------------------------------------------------
        if(i_limit.condition_groups_size() == 0)
        {
                // -----------------------------------------
                // ****************MATCH********************
                // -----------------------------------------
                // TODO log?
                // TRC_DEBUG("Matched enforcement limit completely!\n");
                int32_t l_s;
                l_s = incr_key_for_response(ao_exceeds, a_scope_id, a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO log error reason
                        return WAFLZ_STATUS_ERROR;
                }
                if(ao_exceeds)
                {
                        return WAFLZ_STATUS_OK;
                }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // limits w/condition_groups
        // -------------------------------------------------
        // ===================== O R =======================
        // -------------------------------------------------
        for(int i_ms = 0; i_ms < i_limit.condition_groups_size(); ++i_ms)
        {
                //NDBG_PRINT("limit[%d]: limit[%d] process\n", i_t, i_r);
                const waflz_pb::condition_group &l_cg = i_limit.condition_groups(i_ms);
                bool l_matched = false;
                int32_t l_s;
                l_s = process_condition_group_for_response(l_matched, l_cg, a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_matched == false)
                {
                        // no match -continue
                        continue;
                }
                //NDBG_PRINT("limit[%d]: limit[%d] MATCHED\n", i_t, i_r);
                // -----------------------------------------
                // ****************MATCH********************
                // -----------------------------------------
                l_s = incr_key_for_response(ao_exceeds, a_scope_id, a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO log error reason
                        return WAFLZ_STATUS_ERROR;
                }
                if(ao_exceeds)
                {
                        *ao_cg = &l_cg;
                        return WAFLZ_STATUS_OK;
                }
                // -----------------------------------------
                // Stop the loop if any condition_group matches
                // -----------------------------------------
                if (l_matched)
                {
                        break;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t limit::incr_key_for_response(bool &ao_exceeds,
                                     const std::string& a_scope_id,
                                     resp_ctx* a_ctx)
{
        // -------------------------------------------------
        // get key for limit
        // -------------------------------------------------
        // Construct db key eg:
        //   AN:LIMIT_ID:DIM1=DIM1VAL:...DIMN=DIMNVAL
        //
        // if WAFLZ_STATUS_OK is not returned, then the not
        // every key was found. in that case we dont
        // increment a key - just return
        // -------------------------------------------------
        char l_key[_MAX_KEY_LEN];
        int32_t l_s;
        l_s = get_key_for_response(l_key, a_scope_id, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                ao_exceeds = false;
                return WAFLZ_STATUS_OK;
        }
        // NDBG_PRINT("l_key: %s\n", l_key);
        // -------------------------------------------------
        // increment key value in db
        // -------------------------------------------------
        // increment one of our counters
        // this count automatically rolls over because key
        // includes bucketing information
        // gives historical data as well as auto-rollover
        // -------------------------------------------------
        int64_t l_cur_num = 0;
        int64_t l_threshold = (int64_t)(m_pb->num());
        bool l_is_pop_count_set = false;
        l_s = m_db.increment_key(l_cur_num,
                                 l_key,
                                 m_pb->duration_sec()*1000,
                                 m_enable_pop_count,
                                 l_is_pop_count_set);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "Failed to perform db key increment for limit id: '%s' key: %s",
                             m_pb->id().c_str(),
                             l_key);
                return WAFLZ_STATUS_ERROR;
        }
        // NDBG_PRINT("KEY: %s VAL: %li\n", l_key, l_cur_num);
        // TODO log?
        //TRACE("Incremented time bucket key '%s' count to: %" PRIi64, bucket_key.b_str(), l_current_number);
        // -------------------------------------------------
        // limit is exceeding???
        // -------------------------------------------------
        if(l_cur_num > l_threshold)
        {
                ao_exceeds = true;
                m_pb->set__reserved_match(std::string(l_key));
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t limit::get_key_for_response(char* ao_key,
                       const std::string& a_scope_id,
                       resp_ctx *a_ctx)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        uint64_t l_dim_hash = 0;
        // -------------------------------------------------
        // for each key...
        // -------------------------------------------------
        bool l_all_optional_keys_found = true;
        for(int i_r = 0; i_r < m_pb->keys_size(); ++i_r)
        {
                const std::string& l_e = m_pb->keys(i_r);
                // -----------------------------------------
                // IP
                // -----------------------------------------
                if (strcasecmp(l_e.c_str(), "IP") == 0)
                {
                        const data_t &l_d = a_ctx->m_src_addr;
                        if ( l_d.m_data && l_d.m_len )
                        {
                                l_dim_hash += CityHash64(l_d.m_data, l_d.m_len);
                        }
                }
                // -----------------------------------------
                // user agent
                // -----------------------------------------
                else if (strcasecmp(l_e.c_str(), "USER_AGENT") == 0)
                {
                        const data_t* l_ua = a_ctx->get_header(std::string_view("User-Agent"));
                        if ( l_ua && l_ua->m_data && l_ua->m_len)
                        {
                                l_dim_hash += CityHash64(l_ua->m_data, l_ua->m_len);
                        }
                }
                // -----------------------------------------
                // special case: header
                // -----------------------------------------
                else if (strncasecmp(l_e.c_str(), "HEADER:", (sizeof("HEADER:") - 1)) == 0)
                {
                        std::string_view l_t(l_e.c_str() + (sizeof("HEADER:") - 1));
                        const data_t* l_hv = a_ctx->get_header(l_t);
                        if (l_hv && l_hv->m_data && l_hv->m_len)
                        {
                                l_dim_hash += CityHash64(l_hv->m_data, l_hv->m_len);
                        }
                        else
                        {
                                l_all_optional_keys_found = false;
                                break;
                        }
                }
                // -----------------------------------------
                // special case: status codes
                // -----------------------------------------
                else if (strncasecmp(l_e.c_str(), "STATUS_CODE:", (sizeof("STATUS_CODE:") - 1)) == 0)
                {
                        // ---------------------------------
                        // get the response status code
                        // ---------------------------------
                        uint32_t l_status_code = a_ctx->m_resp_status;
                        // ---------------------------------
                        // hash if found in query map
                        // ---------------------------------
                        bool matched = false;
                        for ( const auto& i_status_range : m_status_codes )
                        {
                                matched = ( (l_status_code >= i_status_range.m_start) &&
                                            (l_status_code <= i_status_range.m_end ));
                                if (matched)
                                {
                                        l_dim_hash += CityHash64(l_e.c_str(), l_e.length());
                                        break;
                                }
                        }
                        if (!matched)
                        {
                                l_all_optional_keys_found = false;
                                break;
                        }
                }

        }
        // -------------------------------------------------
        // quick return if we were missing a key
        // NOTE: doesnt apply to IP and User-Agent. This is
        // to keep consistent with pervious implementation 
        // -------------------------------------------------
        if (!l_all_optional_keys_found)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // *************************************************
        //                K E Y   F O R M A T
        // *************************************************
        // -------------------------------------------------
        // SF:RL:<CUSTOMER_ID>:<SCOPE_ID>::<LIMIT_ID>:
        // -------------------------------------------------
        if(m_pb->has__reserved_1() &&
           !m_pb->_reserved_1().empty())
        {
                snprintf(ao_key, _MAX_KEY_LEN, "SF:RL:%s:%s:%s:%" PRIX64 "", m_pb->customer_id().c_str(), a_scope_id.c_str(), m_pb->_reserved_1().c_str(), l_dim_hash);
        }
        else
        {
                snprintf(ao_key, _MAX_KEY_LEN, "SF:RL:%s:%s:%s:%" PRIX64 "", m_pb->customer_id().c_str(), a_scope_id.c_str(), m_pb->id().c_str(), l_dim_hash);
        }
        return WAFLZ_STATUS_OK;
}

}
