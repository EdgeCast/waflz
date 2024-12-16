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
#include <inttypes.h>
#include <rapidjson/document.h>
#include <rapidjson/error/error.h>
#include <rapidjson/error/en.h>
#include "ectoken/ectoken_v3.h"
#include "waflz/captcha.h"
#include "waflz/render.h"
#include "support/file_util.h"
#include "support/time_util.h"
#include "core/decode.h"
#include "event.pb.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _DEFAULT_KEY "b9RCuEKmbYTd4DDP" //TODO: change this key
#define CONFIG_SECURITY_CAPTCHA_CONFIG_MAX_SIZE (1<<20)
// ectoken payload params...
#define _TOKEN_FIELD_IP "ip"
#define _TOKEN_FIELD_UA "ua"
#define _TOKEN_FIELD_TIME "time"
//
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
namespace ns_waflz{
///-----------------------------------------------------------------------------
//! @brief  constructor
//! ----------------------------------------------------------------------------
captcha::captcha(void):
         m_captcha_b64(),
         m_g_site_verify_url(SITE_VERIFY_URL),
         m_err_msg()
{
}
//! ----------------------------------------------------------------------------
//! @brief  destructor
//! ----------------------------------------------------------------------------
captcha::~captcha()
{
}
//! ----------------------------------------------------------------------------
//! @brief set google seite verify url
//! ----------------------------------------------------------------------------
void captcha::set_google_site_verify_url(const std::string& a_url)
{
        m_g_site_verify_url.assign(a_url);
}
//! ----------------------------------------------------------------------------
//! @brief   loads the captcha html
//! @param   <a_file_path> - path to file
//! @param   <a_file_path_len> - length of a_file_path
//! @return  WAFLZ_STATUS_OK on success, WAFLZ_STATUS_ERROR on failure
//! ----------------------------------------------------------------------------
int32_t captcha::load_file(const char* a_file_path, uint32_t a_file_path_len)
{
        int32_t l_s;
        char *l_buf = NULL;
        uint32_t l_buf_len;
        l_s = read_file(a_file_path, &l_buf, l_buf_len);
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing read_file: %s",
                             a_file_path);
                if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check buffer length
        // -------------------------------------------------
        if (l_buf_len > CONFIG_SECURITY_CAPTCHA_CONFIG_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg, "config file size(%u) > max size(%u)",
                             l_buf_len,
                             CONFIG_SECURITY_CAPTCHA_CONFIG_MAX_SIZE);
                if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // assign it to string
        // -------------------------------------------------
        m_captcha_b64.assign(l_buf, l_buf_len);
        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
        return WAFLZ_STATUS_OK;   
}
//! ----------------------------------------------------------------------------
//! @brief TODO
//! @param <ao_arg_list> - arg list to clean
//! @return TODO
//! ----------------------------------------------------------------------------
static void free_arg_list(arg_list_t &ao_arg_list)
{
        for (arg_list_t::iterator i_q = ao_arg_list.begin();
             i_q != ao_arg_list.end();
             ++i_q)
        {
                if (i_q->m_key) { free(i_q->m_key); i_q->m_key = NULL; }
                if (i_q->m_val) { free(i_q->m_val); i_q->m_val = NULL; }
        }
}
//! ----------------------------------------------------------------------------
//! @brief   captcha ec token
//! @param   
//! @param   
//! @return  WAFLZ_STATUS_OK on success, WAFLZ_STATUS_ERROR on failure
//! ----------------------------------------------------------------------------
int32_t captcha::set_captcha_verified_ec_token(rqst_ctx* a_ctx)
{
        int32_t l_s;
        if (!a_ctx)
        {
                WAFLZ_PERROR(m_err_msg, "rqst_ctx == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get user-agent
        // -------------------------------------------------
        data_t l_d;
        data_t l_v;
        _GET_HEADER("User-Agent");
        // -------------------------------------------------
        // get current time in microseconds
        // -------------------------------------------------
        uint64_t l_ct = get_time_s();
        // -------------------------------------------------
        // format ectoken input
        // -------------------------------------------------
        char *l_token_clr = NULL;
        int l_token_clr_len = 0;
        l_token_clr_len = asprintf(&l_token_clr,
                                   "ip=%.*s&ua=%.*s&time=%" PRIu64,
                                   a_ctx->m_src_addr.m_len,
                                   a_ctx->m_src_addr.m_data,
                                   l_v.m_len,
                                   l_v.m_data,
                                   l_ct);
        if (l_token_clr_len < 0)
        {
                if (l_token_clr) { free(l_token_clr); l_token_clr = NULL; }
                WAFLZ_PERROR(m_err_msg, "sprintf failed");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // encrypt ectoken
        // -------------------------------------------------
        size_t l_token_len = 0;
        l_token_len = ns_ectoken_v3::ectoken_encrypt_required_size(l_token_clr_len);
        char *l_token = NULL;
        l_token = (char *)malloc(l_token_len);
        l_s = ns_ectoken_v3::ectoken_encrypt_token(l_token,
                                                   &l_token_len,
                                                   l_token_clr,
                                                   l_token_clr_len,
                                                   _DEFAULT_KEY,
                                                   sizeof(_DEFAULT_KEY) - 1);
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "ectoken encrypt failed");
                if (l_token_clr) { free(l_token_clr); l_token_clr = NULL; }
                if (l_token) { free(l_token); l_token = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        a_ctx->m_ec_resp_token.assign(l_token, l_token_len);
        a_ctx->m_resp_token = true;
        if (l_token) { free(l_token); l_token = NULL; }
        if (l_token_clr) { free(l_token_clr); l_token_clr = NULL; }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @brief   check google token
//! @param   
//! @param   
//! @return  WAFLZ_STATUS_ERROR if there is not token
//!          WAFLZ_STATUS_WAIT if the subrequest is issued
//! ----------------------------------------------------------------------------
int32_t captcha::check_google_token(rqst_ctx* a_ctx,
                                     waflz_pb::event* l_event,
                                     const waflz_pb::enforcement* a_enf,
                                     bool& ao_issue_captcha)
{
        int32_t l_s;
        data_t l_ck_k;
        data_map_t::const_iterator i_h;
        // -------------------------------------------------
        // get __ecreha__
        // -------------------------------------------------
        l_ck_k.m_data = CAPTCHA_GOOGLE_TOKEN;
        l_ck_k.m_len = strlen(CAPTCHA_GOOGLE_TOKEN);
        i_h = a_ctx->m_cookie_map.find(l_ck_k);
        if(i_h == a_ctx->m_cookie_map.end())
        {
                //no google token, issue captcha;
                l_event->set_captcha_status(waflz_pb::event_captcha_status_t_CAPTCHA_ISSUED_NO_GOOGLE_TOKEN);
                ao_issue_captcha = true;
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // issue subrequest and return STATUS_WAIT.
        // if subrequest was successful, validate_google_token
        // will be called to get the result of subrequest
        // copy the second enforcement to rqst ctx var which will be
        // used to enforce the request, if its bot
        // -------------------------------------------------
        std::string l_g_token(i_h->second.m_data, i_h->second.m_len);
        std::string l_resp;
        
        a_ctx->m_captcha_enf = (void*)a_enf;
        l_s = a_ctx->do_subrequest(m_g_site_verify_url, 
                                   a_ctx->m_recaptcha_secret_key, 
                                   l_g_token);
        if(l_s != WAFLZ_STATUS_OK)
        {
                //subr was not issued
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_WAIT;
}
//! ----------------------------------------------------------------------------
//! @brief   validate google token
//! @param   
//! @param   
//! @return  WAFLZ_STATUS_ERROR if subr resp to be validated is empty
//!          WAFLZ_STATUS_OK if the subrequest response was verified
//! ----------------------------------------------------------------------------
int32_t captcha::validate_google_token(rqst_ctx* a_ctx,
                                       waflz_pb::event** ao_event,
                                       bool& ao_is_bot)
{
        int32_t l_s;
        if( a_ctx == NULL)
        {
                WAFLZ_PERROR(m_err_msg, "rqst ctx is null");
                return WAFLZ_STATUS_ERROR;
        }
        if(a_ctx->m_subr_resp.empty())
        {
                WAFLZ_PERROR(m_err_msg, "subrequest response is empty\n");
                return WAFLZ_STATUS_ERROR;   
        }
        // -------------------------------------------------
        // parse json response and take action.
        // any parser failures could be third party changing
        // the response format. So let the request go,
        // set verified token and slack alert
        // -------------------------------------------------
        rapidjson::Document l_js;
        rapidjson::ParseResult l_ok;
        l_ok = l_js.Parse(a_ctx->m_subr_resp.c_str(), a_ctx->m_subr_resp.length());
        if (!l_ok)
        {
                WAFLZ_PERROR(m_err_msg, "JSON parse error: %s (%d)",
                             rapidjson::GetParseError_En(l_ok.Code()), (int)l_ok.Offset());
                ao_is_bot = false;
                a_ctx->m_tp_subr_fail = true;
                return WAFLZ_STATUS_OK;
        }
        if (!l_js.IsObject())
        {
                WAFLZ_PERROR(m_err_msg, "invalid format of captcha resp, must be an object/dict");
                ao_is_bot = false;
                a_ctx->m_tp_subr_fail = true;
                return WAFLZ_STATUS_OK;
        }
        if (!l_js.HasMember("success"))
        {
                WAFLZ_PERROR(m_err_msg, "recaptcha response is invalid");
                ao_is_bot = false;
                a_ctx->m_tp_subr_fail = true;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // if success == false, possible error-codes
        // from google can be [Missing input secret,
        // Invalid secret key, Missing input response,
        // Invalid input response, bad Request,
        // Timeout or duplicate].
        // implement captcha failed action, 
        // set verfied token and send
        // an event with error code
        // -------------------------------------------------
        bool l_is_success = l_js["success"].GetBool();
        if (!l_is_success)
        {
                 std::string l_error_codes;
                if (l_js.HasMember("error-codes"))
                {
                        const rapidjson::Value& l_err_codes = l_js["error-codes"];
                        for (rapidjson::SizeType i = 0; i < l_err_codes.Size(); i++)
                        {
                                l_error_codes.append(l_err_codes[i].GetString());
                                l_error_codes.append("/");
                        }       
                }
                if((*ao_event) != NULL)
                {
                        printf("setting captcha status\n");
                        (*ao_event)->set_captcha_status(waflz_pb::event_captcha_status_t_CAPTCHA_FAILED_RESULT_ERROR);
                        (*ao_event)->set_captcha_error_message(l_error_codes.c_str());
                }
                ao_is_bot = true;
                l_s = set_captcha_verified_ec_token(a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "getting verified ec token failed");
                        return WAFLZ_STATUS_ERROR;
                }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // if success == true, compare bot scores
        // bot score less than 0.5 is considered as bots
        // if bot, apply bad/second action
        // and set response token in ctx
        // -------------------------------------------------
        float l_bot_score = 0.0;
        if (l_js.HasMember("score"))
        {
            l_bot_score = l_js["score"].GetDouble();
        }
        if (l_bot_score <= 0.5)
        {
                (*ao_event)->set_captcha_status((waflz_pb::event_captcha_status_t_CAPTCHA_FAILED_RESULT_BOT));
                (*ao_event)->set_captcha_bot_score(l_bot_score);
                ao_is_bot = true;
                l_s = set_captcha_verified_ec_token(a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "getting verified ec token failed");
                        return WAFLZ_STATUS_ERROR;
                }
                return WAFLZ_STATUS_OK;
        }
        //if not bot, set the token in ctx to set in response headers. Let the
        // request go
        ao_is_bot = false;
        l_s = set_captcha_verified_ec_token(a_ctx);
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "getting verified ec token failed");
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @brief Decrypts ec token and validate 
//! @param 
//! @return WAFLZ_STATUS_OK on successful validation
//!         WAFLZ_STATUS_ERROR if validation failed 
//! ----------------------------------------------------------------------------
int32_t captcha::verify_ec_token(data_t* l_ec_token,
                                 uint32_t a_valid_for_s,
                                 rqst_ctx* a_ctx,
                                 bool& ao_issue_captcha,
                                 waflz_pb::event *ao_event)
{
        int32_t l_s;
        if (!l_ec_token)
        {
                WAFLZ_PERROR(m_err_msg, "ec token is null");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // decrypt captcha ectoken
        // -------------------------------------------------
        size_t l_tk_len = ns_ectoken_v3::ectoken_decrypt_required_size(l_ec_token->m_len);
        char* l_tk = NULL;
        l_tk = (char *)malloc(l_tk_len);
        l_s = ns_ectoken_v3::ectoken_decrypt_token(l_tk,
                                                   &l_tk_len,
                                                   l_ec_token->m_data,
                                                   l_ec_token->m_len,
                                                   _DEFAULT_KEY,
                                                   sizeof(_DEFAULT_KEY) - 1);
        if (l_s != 0)
        {
                WAFLZ_PERROR(m_err_msg, "ec token decrypt failed");
                ao_event->set_captcha_status(waflz_pb::event_captcha_status_t_CAPTCHA_ECTOKEN_CORRUPTED);
                ao_issue_captcha = true;
                if (l_tk) { free(l_tk); l_tk = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // parse args in the token
        // -------------------------------------------------
        arg_list_t l_tk_list;
        data_unordered_map_t l_tk_map;
        uint32_t l_unused;
        l_s = parse_args(l_tk_list, l_tk_map, l_unused, l_tk, l_tk_len, '&');
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "ec token decrypt failed");
                ao_event->set_captcha_status(waflz_pb::event_captcha_status_t_CAPTCHA_ECTOKEN_CORRUPTED);
                ao_issue_captcha = true;
                if (l_tk) { free(l_tk); l_tk = NULL; }
                free_arg_list(l_tk_list);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // macro...
        // -------------------------------------------------
        data_unordered_map_t::const_iterator i_t;
        data_t l_key;
#define _GET_TOKEN_FIELD_FIELD(_field) do { \
        l_key.m_data = _field; \
        l_key.m_len = sizeof(_field) - 1; \
        i_t = l_tk_map.find(l_key); \
        if (i_t == l_tk_map.end()) { \
                WAFLZ_PERROR(m_err_msg, "missing %s in token", _field); \
                return WAFLZ_STATUS_ERROR; \
        } } while(0)
        // -------------------------------------------------
        // validate ip
        // -------------------------------------------------
        _GET_TOKEN_FIELD_FIELD(_TOKEN_FIELD_IP);
        if ((a_ctx->m_src_addr.m_data == NULL) ||
           (a_ctx->m_src_addr.m_len <= 0))
        {
                WAFLZ_PERROR(m_err_msg, "ip missing in the ctx");
                ao_event->set_captcha_status(waflz_pb::event_captcha_status_t_CAPTCHA_ECTOKEN_IP_MISMATCH);
                ao_issue_captcha = true;
                if(l_tk) { free(l_tk); l_tk = NULL; }
                free_arg_list(l_tk_list);
                return WAFLZ_STATUS_ERROR;
        }
        if (strncmp(a_ctx->m_src_addr.m_data, 
                    i_t->second.m_data,
                    i_t->second.m_len) != 0)
        {
                WAFLZ_PERROR(m_err_msg, "token ip validation failed");
                ao_event->set_captcha_status(waflz_pb::event_captcha_status_t_CAPTCHA_ECTOKEN_IP_MISMATCH);
                ao_issue_captcha = true;
                if(l_tk) { free(l_tk); l_tk = NULL; }
                free_arg_list(l_tk_list);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get user-agent
        // -------------------------------------------------
        data_t l_d;
        data_t l_v;
        _GET_HEADER("User-Agent");
        // -------------------------------------------------
        // validate ua
        // -------------------------------------------------
        _GET_TOKEN_FIELD_FIELD(_TOKEN_FIELD_UA);
        if ((l_v.m_data == NULL) ||
           (l_v.m_len <= 0))
        {
                WAFLZ_PERROR(m_err_msg, "user-agent missing in the ctx");
                ao_event->set_captcha_status(waflz_pb::event_captcha_status_t_CAPTCHA_ECTOKEN_UA_MISMATCH);
                ao_issue_captcha = true;
                if(l_tk) { free(l_tk); l_tk = NULL; }
                free_arg_list(l_tk_list);
                return WAFLZ_STATUS_ERROR;
        }
        if (strncmp(l_v.m_data, i_t->second.m_data, i_t->second.m_len) != 0)
        {
                WAFLZ_PERROR(m_err_msg, "token user-agent validation failed");
                ao_event->set_captcha_status(waflz_pb::event_captcha_status_t_CAPTCHA_ECTOKEN_UA_MISMATCH);
                ao_issue_captcha = true;
                if (l_tk) { free(l_tk); l_tk = NULL; }
                free_arg_list(l_tk_list);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate time
        // -------------------------------------------------
        _GET_TOKEN_FIELD_FIELD(_TOKEN_FIELD_TIME);
        uint64_t l_time_cur = get_time_s();
        uint64_t l_time_tok = (uint64_t)strntol(i_t->second.m_data, i_t->second.m_len, NULL, 10);
        if ((l_time_cur-l_time_tok) >= a_valid_for_s)
        {
                WAFLZ_PERROR(m_err_msg, "token expired");
                ao_issue_captcha = true;
                ao_event->set_captcha_status(waflz_pb::event_captcha_status_t_CAPTCHA_ECTOKEN_EXPIRED);
                if (l_tk) { free(l_tk); l_tk = NULL; }
                free_arg_list(l_tk_list);
                return WAFLZ_STATUS_ERROR;
        }
        // token verification passed...
        if (l_tk) { free(l_tk); l_tk = NULL; }
        free_arg_list(l_tk_list);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @brief   Steps to verify and issue captcha listed below:
//!          - Fresh request without ec token and google token, issue captcha
//!          - Request with google token and without ectoken, verify
//!            google token by doing sub request to google verify api.
//!            If the response is bot, enforce the request(captcha_failed_action)
//!            and set response token to prevent spamming.
//!            If the response is not bot, create the ec verified token aka response token.
//!            Server should send this response token back to the client via
//!            response headers.
//!          - Request with both google token and ec verified token or just ec verified token. 
//!            If the ec verified token is still valid, return STATUS_OK.
//!            If the token is corrupted or expired, re issue captcha.        
//! @param   
//! @param   
//! @return  If the request has to be issued captcha, returns STATUS_ERROR and
//!          ao_issue_captcha is set to true.
//!          If the request passed captcha, returns STATUS_OK and
//!          ao_has_resp_token is set to true or just returns STATUS_OK without
//!          response token if it's a already verified client.   
//! ----------------------------------------------------------------------------
int32_t captcha::verify(rqst_ctx* a_ctx,
                        uint32_t a_valid_for_s,
                        waflz_pb::event* ao_event,
                        const waflz_pb::enforcement* a_enf,
                        bool& ao_issue_captcha)
{
        int32_t l_s;
        data_t l_ck_k;
        data_map_t::const_iterator i_h;
        // -------------------------------------------------
        // Check if there ec token in cookies or in rqst_ctx.
        // If there is ec token, verify the ec token and return.
        // if there is no ec token, check for google token.
        // Fresh request coming from client will have ec token
        // in cookies.
        // Second process call that is made after getting the
        // subrequest response will have ec token in ctx.
        // -------------------------------------------------
        bool l_is_ec_token = false;
        data_t l_ec_token;
        // -------------------------------------------------
        // check in cookie map and ctx
        // -------------------------------------------------
        l_ck_k.m_data = CAPTCHA_VERIFIED_TOKEN;
        l_ck_k.m_len = strlen(CAPTCHA_VERIFIED_TOKEN);
        i_h = a_ctx->m_cookie_map.find(l_ck_k);
        if(i_h != a_ctx->m_cookie_map.end())
        {
                l_is_ec_token = true;
                l_ec_token = i_h->second;
        }
        else 
        {
                if(a_ctx->m_resp_token && 
                   !(a_ctx->m_ec_resp_token.empty()))
                {
                        l_is_ec_token = true;
                        l_ec_token.m_data = a_ctx->m_ec_resp_token.c_str();
                        l_ec_token.m_len = a_ctx->m_ec_resp_token.length();
                }
        }
        // -------------------------------------------------
        // no ec token, check if there is google token
        // and make sub request
        // -------------------------------------------------
        if (!l_is_ec_token)
        {
                l_s = check_google_token(a_ctx, 
                                         ao_event,
                                         a_enf,
                                         ao_issue_captcha);
                return l_s;
        }
        // -------------------------------------------------
        // verify captcha ectoken
        // -------------------------------------------------
        l_s = verify_ec_token(&l_ec_token,
                              a_valid_for_s,
                              a_ctx,
                              ao_issue_captcha,
                              ao_event);
        return l_s;
}
}