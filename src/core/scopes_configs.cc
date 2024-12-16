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
#include "waflz/scopes_configs.h"
#include "waflz/scopes.h"
#include "waflz/rules.h"
#include "waflz/bots.h"
#include "waflz/bot_manager.h"
#include "waflz/api_gw.h"
#include "waflz/schema.h"
#include "waflz/client_waf.h"
#include "waflz/acl.h"
#include "waflz/engine.h"
#include "waflz/trace.h"
#include "waflz/string_util.h"
#include "waflz/geoip2_mmdb.h"
#include <rapidjson/document.h>
#include <rapidjson/error/error.h>
#include <rapidjson/error/en.h>
#include "support/file_util.h"
#include "support/time_util.h"
#include "support/ndebug.h"
#include <dirent.h>
#include "scope.pb.h"
#include "limit.pb.h"
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
scopes_configs::scopes_configs(engine &a_engine,
                               kv_db& a_db,
                               kv_db& a_bot_db,
                               challenge& a_challenge,
                               captcha& a_captcha,
                               bool a_enable_locking):
        m_cust_id_scopes_map(),
        m_team_id_scopes_map(),
        m_err_msg(),
        m_engine(a_engine),
        m_db(a_db),
        m_bot_db(a_bot_db),
        m_mutex(),
        m_enable_locking(a_enable_locking),
        m_conf_dir(),
        m_challenge(a_challenge),
        m_captcha(a_captcha)
{
        // -------------------------------------------------
        // Initialize the mutex
        // -------------------------------------------------
        if (m_enable_locking)
        {
                pthread_mutex_init(&m_mutex, NULL);
        }
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
scopes_configs::~scopes_configs()
{
        for (cust_id_scopes_map_t::iterator  it = m_cust_id_scopes_map.begin();
             it != m_cust_id_scopes_map.end();
             ++it)
        {
                delete it->second;
                it->second = NULL;
        }
        for (team_id_scopes_map_t::iterator  it = m_team_id_scopes_map.begin();
             it != m_team_id_scopes_map.end();
             ++it)
        {
                delete it->second;
                it->second = NULL;
        }
        // -------------------------------------------------
        // destroy mutex
        // -------------------------------------------------
        if (m_enable_locking)
        {
                pthread_mutex_destroy(&m_mutex);
        }
}
//! ----------------------------------------------------------------------------
//! \details: loads scopes.json config files in the path specified.
//  The file name is of the format <an>.scopes.json. This function is called
//  on startup
//  If a scopes file is loaded only then the m_cust_id_scopes_map is updated.
//  Hence we do not need a double check in other functions.
//! \return  0: success
//! \param   a_dir_path: path of directorry which contains scopes configs
//           a_dir_path_len: strlen of a_dir_path
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_dir(const char* a_dir_path, uint32_t a_dir_path_len)
{
        // -------------------------------------------------
        // look through the given directory and find
        // scopes.json files, call load_file()
        // -------------------------------------------------
        class is_conf_file
        {
        public:
                static int compare(const struct dirent* a_dirent)
                {
                        switch (a_dirent->d_name[0])
                        {
                        case 'a' ... 'z':
                        case 'A' ... 'Z':
                        case '0' ... '9':
                        case '_':
                        {
                                // -------------------------
                                // valid path name to 
                                // consider
                                // -------------------------
                                const char* l_found = NULL;
                                l_found = ::strcasestr(a_dirent->d_name, ".scopes.json");
                                // -------------------------
                                // look for the .conf suffix
                                // -------------------------
                                if (l_found == NULL)
                                {
                                        // -----------------
                                        // look for the 
                                        // .conf suffix
                                        // -----------------
                                        //NDBG_PRINT("Failed to find .scopes.json suffix\n");
                                        goto done;
                                }
                                if (::strlen(l_found) != 12)
                                {
                                        // -----------------
                                        // failed to find 
                                        // .scopes.json
                                        // right at the end
                                        // -----------------
                                       // NDBG_PRINT("found in the wrong place. %zu", ::strlen(l_found));
                                        goto done;
                                }
                                // -------------------------
                                // we want this file
                                // -------------------------
                                return 1;
                                break;
                        }
                        default:
                                //NDBG_PRINT("Found invalid first char: '%c'", a_dirent->d_name[0]);
                                goto done;
                        }
                done:
                        return 0;
                }
        };
        // -------------------------------------------------
        // scandir
        // -------------------------------------------------
        struct dirent** l_conf_list;
        int l_num_files = -1;
        l_num_files = ::scandir(a_dir_path,
                                &l_conf_list,
                                is_conf_file::compare,
                                alphasort);
        if (l_num_files < 0)
        {
                WAFLZ_PERROR(m_err_msg, "Failed to load scope config  Reason: failed to scan profile directory: %s: %s",
                             a_dir_path,
                             (errno == 0 ? "unknown" : strerror(errno)));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // for each file
        // -------------------------------------------------
        for (int i_f = 0; i_f < l_num_files; ++i_f)
        {
                int32_t l_s;
                std::string l_file_name(l_conf_list[i_f]->d_name);
                // -----------------------------------------
                // find first
                // -----------------------------------------
                size_t l_pos = l_file_name.find_first_of('.');
                if (l_pos == std::string::npos)
                {
                        WAFLZ_PERROR(m_err_msg,"Invalid filename %s\n", l_file_name.c_str());
                        for (int i_f2 = 0; i_f2 < l_num_files; ++i_f2) free(l_conf_list[i_f2]);
                        free(l_conf_list);
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // TODO log?
                // -----------------------------------------
                //NDBG_PRINT("Found scope config file: %s", l_conf_list[i_f]->d_name );
                std::string l_full_path(a_dir_path);
                l_full_path.append("/");
                l_full_path.append(l_conf_list[i_f]->d_name);
                l_s = load_file(l_full_path.c_str(),l_full_path.length());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        for (int i_f2 = 0; i_f2 < l_num_files; ++i_f2) free(l_conf_list[i_f2]);
                        free(l_conf_list);
                        return WAFLZ_STATUS_ERROR;
                }
        }
        for (int i_f = 0; i_f < l_num_files; ++i_f) free(l_conf_list[i_f]);
        free(l_conf_list);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_file(const char* a_file_path,
                                         uint32_t a_file_path_len)
{
        int32_t l_s;
        char *l_buf = NULL;
        uint32_t l_buf_len;
        l_s = read_file(a_file_path, &l_buf, l_buf_len);
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, ":read_file[%s]: %s",
                             a_file_path,
                             ns_waflz::get_err_msg());
                if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                return WAFLZ_STATUS_ERROR;
        }
        l_s = load(l_buf, l_buf_len);
        if (l_s != WAFLZ_STATUS_OK)
        {
                if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                return WAFLZ_STATUS_ERROR;
        }
        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load(const char *a_buf, uint32_t a_buf_len, bool a_update)
{
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        rapidjson::Document *l_js = new rapidjson::Document();
        rapidjson::ParseResult l_ok;
        l_ok = l_js->Parse(a_buf, a_buf_len);
        if (!l_ok)
        {
                WAFLZ_PERROR(m_err_msg, "JSON parse error: %s (%d)\n",
                             rapidjson::GetParseError_En(l_ok.Code()), (int)l_ok.Offset());
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if (!l_js->IsObject() &&
           !l_js->IsArray())
        {
                WAFLZ_PERROR(m_err_msg, "error parsing json");
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // object
        // -------------------------------------------------
        if (m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        if (l_js->IsObject())
        {
                int32_t l_s;
                l_s = load((void *)l_js, a_update);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_js) { delete l_js; l_js = NULL; }
                        if (m_enable_locking)
                        {
                                pthread_mutex_unlock(&m_mutex);
                        }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // array
        // -------------------------------------------------
        else if (l_js->IsArray())
        {
                for (uint32_t i_e = 0; i_e < l_js->Size(); ++i_e)
                {
                        rapidjson::Value &l_e = (*l_js)[i_e];
                        int32_t l_s;
                        l_s = load((void *)&l_e, a_update);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                if (l_js) { delete l_js; l_js = NULL; }
                                if (m_enable_locking)
                                {
                                       pthread_mutex_unlock(&m_mutex);
                                }
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        if (l_js) { delete l_js; l_js = NULL; }
        if (m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load(void* a_js, bool a_update)
{
        if (!a_js)
        {
                WAFLZ_PERROR(m_err_msg, "a_js == NULL");
                return WAFLZ_STATUS_ERROR;                
        }
        bool l_use_team_id = false;
        scopes *l_scopes = new scopes(m_engine, m_db, m_bot_db, m_challenge, m_captcha);
        int32_t l_s;
        l_s = l_scopes->load(a_js, m_conf_dir);
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", l_scopes->get_err_msg());
                if (l_scopes) { delete l_scopes; l_scopes = NULL;}
                return WAFLZ_STATUS_ERROR;                
        }
        uint64_t l_cust_id = 0;
        std::string& l_id_str = l_scopes->get_cust_id();
        if(l_scopes->get_pb()->has_team_config())
        {
                l_use_team_id = l_scopes->get_pb()->team_config();
        }
        // -------------------------------------------------
        // Handle team id first
        // -------------------------------------------------
        if (l_use_team_id)
        {
                // -------------------------------------------------
                // check for exist in map
                // -------------------------------------------------
                team_id_scopes_map_t::iterator i_scopes;
                i_scopes = m_team_id_scopes_map.find(l_id_str);
                // -------------------------------------------------
                // found existing scope
                // -------------------------------------------------
                if ((i_scopes != m_team_id_scopes_map.end()) &&
                    i_scopes->second != NULL)
                {
                        const waflz_pb::scope_config* l_new_pb = l_scopes->get_pb();
                        const waflz_pb::scope_config* l_old_pb = i_scopes->second->get_pb();
                        if ((l_old_pb != NULL) &&
                           (l_new_pb != NULL) &&
                           (l_old_pb->has_last_modified_date()) &&
                           (l_new_pb->has_last_modified_date()))
                        {
                                uint64_t l_loaded_epoch = get_epoch_seconds(l_old_pb->last_modified_date().c_str(),
                                                                            CONFIG_DATE_FORMAT);
                                uint64_t l_config_epoch = get_epoch_seconds(l_new_pb->last_modified_date().c_str(),
                                                                            CONFIG_DATE_FORMAT);
                                if (l_loaded_epoch >= l_config_epoch)
                                {
                                        // Delete the newly created scope
                                        delete l_scopes;
                                        l_scopes = NULL;
                                        return WAFLZ_STATUS_OK;
                                }
                        }
                        delete i_scopes->second;
                        i_scopes->second = NULL;
                        i_scopes->second = l_scopes;
                        return WAFLZ_STATUS_OK;
                }
                // -------------------------------------------------
                // if update
                // -------------------------------------------------
                if (a_update)
                {
                        // -----------------------------------------
                        // skip updating scope that haven't
                        // already been loaded.
                        // -----------------------------------------
                        if (l_scopes)
                        {
                                delete l_scopes;
                                l_scopes = NULL;
                        }
                        return WAFLZ_STATUS_OK;
                }
                // -------------------------------------------------
                // add to map
                // -------------------------------------------------
                m_team_id_scopes_map[l_id_str] = l_scopes;
        }
        else
        {
                l_s = convert_hex_to_uint(l_cust_id, l_id_str.c_str());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing convert_hex_to_uint for %s\n", l_id_str.c_str());
                        return WAFLZ_STATUS_ERROR;
                }
                // -------------------------------------------------
                // check for exist in map
                // -------------------------------------------------
                cust_id_scopes_map_t::iterator i_scopes;
                i_scopes = m_cust_id_scopes_map.find(l_cust_id);
                // -------------------------------------------------
                // found existing scope
                // -------------------------------------------------
                if ((i_scopes != m_cust_id_scopes_map.end()) &&
                    i_scopes->second != NULL)
                {
                        const waflz_pb::scope_config* l_new_pb = l_scopes->get_pb();
                        const waflz_pb::scope_config* l_old_pb = i_scopes->second->get_pb();
                        if ((l_old_pb != NULL) &&
                           (l_new_pb != NULL) &&
                           (l_old_pb->has_last_modified_date()) &&
                           (l_new_pb->has_last_modified_date()))
                        {
                                uint64_t l_loaded_epoch = get_epoch_seconds(l_old_pb->last_modified_date().c_str(),
                                                                            CONFIG_DATE_FORMAT);
                                uint64_t l_config_epoch = get_epoch_seconds(l_new_pb->last_modified_date().c_str(),
                                                                            CONFIG_DATE_FORMAT);
                                if (l_loaded_epoch >= l_config_epoch)
                                {
                                        // Delete the newly created scope
                                        delete l_scopes;
                                        l_scopes = NULL;
                                        return WAFLZ_STATUS_OK;
                                }
                        }
                        delete i_scopes->second;
                        i_scopes->second = NULL;
                        i_scopes->second = l_scopes;
                        return WAFLZ_STATUS_OK;
                }
                // -------------------------------------------------
                // if update
                // -------------------------------------------------
                if (a_update)
                {
                        // -----------------------------------------
                        // skip updating scope that haven't
                        // already been loaded.
                        // -----------------------------------------
                        if (l_scopes)
                        {
                                delete l_scopes;
                                l_scopes = NULL;
                        }
                        return WAFLZ_STATUS_OK;
                }
                // -------------------------------------------------
                // add to map
                // -------------------------------------------------
                m_cust_id_scopes_map[l_cust_id] = l_scopes;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::process(waflz_pb::enforcement **ao_enf,
                                waflz_pb::event **ao_audit_event,
                                waflz_pb::event **ao_prod_event,
                                waflz_pb::event** ao_bot_event,
                                void *a_ctx,
                                uint64_t a_id,
                                std::string& a_team_id,
                                part_mk_t a_part_mk,
                                const rqst_ctx_callbacks *a_callbacks,
                                rqst_ctx **ao_rqst_ctx,
                                void* a_srv,
                                int32_t a_module_id)
{
        if (m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // get scopes for id
        // -------------------------------------------------
        ns_waflz::scopes *l_scopes = NULL;
        if (!a_team_id.empty())
        {
                l_scopes = get_teamid_scopes(a_team_id);
        }
        else
        {
                 l_scopes = get_scopes(a_id);
        }
        if (!l_scopes)
        {
                if (m_enable_locking)
                {
                        pthread_mutex_unlock(&m_mutex);
                }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // process
        // -------------------------------------------------
        const waflz_pb::enforcement *l_enf = NULL;
        int32_t l_s;
        l_s = l_scopes->process(&l_enf,
                                ao_audit_event,
                                ao_prod_event,
                                ao_bot_event,
                                a_ctx,
                                a_part_mk,
                                a_callbacks,
                                ao_rqst_ctx,
                                a_srv,
                                a_module_id);
        if (l_s != WAFLZ_STATUS_OK)
        {
                if (m_enable_locking)
                {
                        pthread_mutex_unlock(&m_mutex);
                }
                WAFLZ_PERROR(m_err_msg, "error processing scope: %.*s",
                             WAFLZ_ERR_REASON_LEN,
                             l_scopes->get_err_msg());

                return l_s;
        }
        // -------------------------------------------------
        // create enforcement copy...
        // -------------------------------------------------
        if (l_enf)
        {
                *ao_enf = new waflz_pb::enforcement();
                (*ao_enf)->CopyFrom(*l_enf);
        }
        if (m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
ns_waflz::header_map_t* scopes_configs::get_client_waf_headers(uint64_t a_id,
                                                        std::string& a_team_id,
                                                        const char* a_host,
                                                        uint32_t a_host_len,
                                                        const char* a_path,
                                                        uint32_t a_path_len)
{
        // -------------------------------------------------
        // get mutex lock
        // -------------------------------------------------
        if(m_enable_locking) { pthread_mutex_lock(&m_mutex); }
        // -------------------------------------------------
        // find scope for given team_id / an
        // -------------------------------------------------
        ns_waflz::scopes *l_scopes = NULL;
        if (!a_team_id.empty())
        {
                l_scopes = get_teamid_scopes(a_team_id);
        }
        else
        {
                 l_scopes = get_scopes(a_id);
        }
        // -------------------------------------------------
        // quick return for no scopes
        // -------------------------------------------------
        if(!l_scopes)
        {
                if(m_enable_locking)
                {
                        pthread_mutex_unlock(&m_mutex);
                }
                return nullptr;
        }
        // -------------------------------------------------
        // get headers from scopes
        // -------------------------------------------------
        ns_waflz::header_map_t* l_headers_to_add = l_scopes->get_client_waf_headers(a_host,
                                                                        a_host_len,
                                                                        a_path,
                                                                        a_path_len);
        // -------------------------------------------------
        // remove mutex lock and return headers
        // -------------------------------------------------
        if (m_enable_locking) { pthread_mutex_unlock(&m_mutex); }
        return l_headers_to_add;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::process_response(waflz_pb::enforcement **ao_enf,
                                waflz_pb::event **ao_audit_event,
                                waflz_pb::event **ao_prod_event,
                                void *a_ctx,
                                uint64_t a_id,
                                std::string& a_team_id,
                                part_mk_t a_part_mk,
                                const resp_ctx_callbacks *a_callbacks,
                                resp_ctx **ao_resp_ctx,
                                void* a_srv,
                                int32_t a_content_length)
{
        if(m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        ns_waflz::scopes *l_scopes = NULL;
        if (!a_team_id.empty())
        {
                l_scopes = get_teamid_scopes(a_team_id);
        }
        else
        {
                 l_scopes = get_scopes(a_id);
        }
        if(!l_scopes)
        {
                if(m_enable_locking)
                {
                        pthread_mutex_unlock(&m_mutex);
                }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // process response
        // -------------------------------------------------
        const waflz_pb::enforcement *l_enf = NULL;
        int32_t l_s;
        if(a_callbacks && a_callbacks->m_get_resp_status_cb)
        {
                uint32_t l_status = 0;
                a_callbacks->m_get_resp_status_cb(&l_status, a_ctx);
                if(l_status != 200)
                {
                        a_part_mk = ns_waflz::part_mk_t::PART_MK_API_GW;
                }
        }
        l_s = l_scopes->process_response(&l_enf, ao_audit_event, ao_prod_event, a_ctx, a_part_mk, a_callbacks, ao_resp_ctx, a_srv, a_content_length);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(m_enable_locking)
                {
                        pthread_mutex_unlock(&m_mutex);
                }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create enforcement copy...
        // -------------------------------------------------
        if(l_enf)
        {
                *ao_enf = new waflz_pb::enforcement();
                (*ao_enf)->CopyFrom(*l_enf);
        }
        if(m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::process_response_phase_3(waflz_pb::enforcement **ao_enf,
                                waflz_pb::event **ao_audit_event,
                                waflz_pb::event **ao_prod_event,
                                void *a_ctx,
                                uint64_t a_id,
                                std::string& a_team_id,
                                part_mk_t a_part_mk,
                                const resp_ctx_callbacks *a_callbacks,
                                resp_ctx **ao_resp_ctx,
                                void* a_srv)
{
        if(m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        ns_waflz::scopes *l_scopes = NULL;
        if (!a_team_id.empty())
        {
                l_scopes = get_teamid_scopes(a_team_id);
        }
        else
        {
                 l_scopes = get_scopes(a_id);
        }

        if(!l_scopes)
        {
                if(m_enable_locking)
                {
                        pthread_mutex_unlock(&m_mutex);
                }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // process response
        // -------------------------------------------------
        const waflz_pb::enforcement *l_enf = NULL;
        int32_t l_s = l_scopes->process_response_phase_3(&l_enf, ao_audit_event, ao_prod_event, a_ctx, a_part_mk, a_callbacks, ao_resp_ctx, a_srv);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(m_enable_locking)
                {
                        pthread_mutex_unlock(&m_mutex);
                }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create enforcement copy...
        // -------------------------------------------------
        if(l_enf)
        {
                *ao_enf = new waflz_pb::enforcement();
                (*ao_enf)->CopyFrom(*l_enf);
        }
        if(m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
void scopes_configs::get_first_id(uint64_t &ao_id)
{
        if (m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        ao_id = 0;
        if (m_cust_id_scopes_map.size())
        {
                ao_id = m_cust_id_scopes_map.begin()->first;
        }
        if (m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
void scopes_configs::get_rand_id(uint64_t &ao_id)
{
        if (m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        ao_id = 0;
        uint32_t l_len = (uint32_t)m_cust_id_scopes_map.size();
        uint32_t l_idx = 0;
        l_idx = ((uint32_t)rand()) % (l_len + 1);
        cust_id_scopes_map_t::const_iterator i_i = m_cust_id_scopes_map.begin();
        std::advance(i_i, l_idx);
        ao_id = i_i->first;
        if (m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
scopes* scopes_configs::get_scopes(uint64_t a_id)
{
        cust_id_scopes_map_t::iterator i_i;
        i_i = m_cust_id_scopes_map.find(a_id);
        if (i_i != m_cust_id_scopes_map.end())
        {
                return i_i->second;
        }
        return NULL;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
scopes* scopes_configs::get_teamid_scopes(std::string& a_id)
{
        team_id_scopes_map_t::iterator i_i;
        i_i = m_team_id_scopes_map.find(a_id);
        if (i_i != m_team_id_scopes_map.end())
        {
                return i_i->second;
        }
        return NULL;
}
//! ----------------------------------------------------------------------------
//! \details creates an alert object for rate limiting
//! \return  int32_t status code
//! \param   ao_alert = the pointer to populate
//! \param   a_ctx = the request context
//! \param   a_cust_id = the customer id
//! \param   a_team_id = the team id
//! \param   a_is_audit = flag to generate audit alert
//! ----------------------------------------------------------------------------
int32_t scopes_configs::generate_alert(waflz_pb::alert** ao_alert,
                                             rqst_ctx* a_ctx,
                                             uint64_t a_cust_id,
                                             std::string& a_team_id,
                                             bool a_is_audit)
{
        // -------------------------------------------------
        // quick exit if no context
        // -------------------------------------------------
        if (!a_ctx) { return WAFLZ_STATUS_OK; }
        // -------------------------------------------------
        // create alert
        // -------------------------------------------------
        waflz_pb::alert* l_at = new waflz_pb::alert();
        // -------------------------------------------------
        // Get the matched limit
        // -------------------------------------------------
        const waflz_pb::limit* l_limit = (a_is_audit) ? a_ctx->m_audit_limit : a_ctx->m_limit;
        // -------------------------------------------------
        // add limit to alert if it exists
        // -------------------------------------------------
        if (l_limit)
        {
                waflz_pb::limit *l_ev_limit = l_at->mutable_limit();
                l_ev_limit->CopyFrom(*(l_limit));
                // -----------------------------------------
                // copy action if available
                // -----------------------------------------
                if (l_limit->has_action())
                {
                        l_at->mutable_action()->CopyFrom(l_limit->action());
                }
                // -----------------------------------------
                // copy last modified date if available
                // -----------------------------------------
                if (l_limit->has_last_modified_date())
                {
                        l_at->set_config_last_modified(l_limit->last_modified_date());
                }
                // -----------------------------------------
                // set rl key used for match
                // -----------------------------------------
                if (l_limit->has__reserved_matched_key_log())
                {
                        l_at->set_matched_rl_values(l_limit->_reserved_matched_key_log());
                }
                l_at->set_matched_rl_key(l_limit->_reserved_match());
                // -----------------------------------------
                // set account type
                // -----------------------------------------
                if ( l_ev_limit->team_config() )
                {
                        team_id_scopes_map_t::iterator i_t_scopes;
                        i_t_scopes = m_team_id_scopes_map.find(a_team_id);
                        if (i_t_scopes != m_team_id_scopes_map.end() &&
                            i_t_scopes->second != NULL)
                        {
                                l_ev_limit->set_account_type(i_t_scopes->second->get_account_type());
                                l_ev_limit->set_partner_id(i_t_scopes->second->get_partner_id());
                        }
                }
                else
                {
                        cust_id_scopes_map_t::iterator i_scopes;
                        i_scopes = m_cust_id_scopes_map.find(a_cust_id);
                        if (i_scopes != m_cust_id_scopes_map.end() &&
                        i_scopes->second != NULL)
                        {
                                l_ev_limit->set_account_type(i_scopes->second->get_account_type());
                                l_ev_limit->set_partner_id(i_scopes->second->get_partner_id());
                        }
                }
        }
        // -------------------------------------------------
        // Get request specific info
        // -------------------------------------------------
        waflz_pb::request_info *l_request_info = l_at->mutable_req_info();
        // -------------------------------------------------
        // Epoch time
        // -------------------------------------------------
        waflz_pb::request_info_timespec_t *l_epoch = l_request_info->mutable_epoch_time();
        l_epoch->set_sec(get_time_s());
        l_epoch->set_nsec(get_time_us() * 1000);
        // -------------------------------------------------
        // headers...
        // -------------------------------------------------
        waflz_pb::request_info::common_header_t* l_headers = l_request_info->mutable_common_header();
        const data_unordered_map_t &l_hm = a_ctx->m_header_map;
        data_t l_d;
#define _SET_HEADER(_header, _val) do { \
        l_d.m_data = _header; \
        l_d.m_len = sizeof(_header) - 1; \
        data_unordered_map_t::const_iterator i_h = l_hm.find(l_d); \
        if (i_h != l_hm.end()) \
        { \
                l_headers->set_##_val(i_h->second.m_data, i_h->second.m_len); \
        } \
} while (0)
#define _SET_IF_EXIST_STR(_field, _proto) do { \
        if (a_ctx->_field.m_data && \
                a_ctx->_field.m_len) { \
                l_request_info->set_##_proto(a_ctx->_field.m_data, a_ctx->_field.m_len); \
} } while (0)
#define _SET_IF_EXIST_INT(_field, _proto) do { \
        l_request_info->set_##_proto(a_ctx->_field); \
} while (0)
#define _SET_IF_EXIST_STD_STR(_field, _proto) do { \
        if (!_field.empty()) { \
                l_request_info->set_##_proto(_field.c_str(), _field.length()); \
} } while (0)
        _SET_HEADER("Referer", referer);
        _SET_HEADER("User-Agent", user_agent);
        _SET_HEADER("Host", host);
        _SET_HEADER("X-Forwarded-For", x_forwarded_for);
        // -------------------------------------------------
        // others...
        // -------------------------------------------------
        _SET_IF_EXIST_STR(m_src_addr, virt_remote_host);
        _SET_IF_EXIST_STR(m_local_addr, local_addr);
        _SET_IF_EXIST_INT(m_port, server_canonical_port);
        _SET_IF_EXIST_STR(m_uri, orig_url);
        _SET_IF_EXIST_STR(m_url, url);
        _SET_IF_EXIST_STR(m_query_str, query_string);
        _SET_IF_EXIST_STR(m_method, request_method);
        _SET_IF_EXIST_STR(m_req_uuid, req_uuid);
        _SET_IF_EXIST_INT(m_bytes_out, bytes_out);
        _SET_IF_EXIST_INT(m_bytes_in, bytes_in);
        _SET_IF_EXIST_STR(m_virt_ssl_client_ja3_md5, virt_ssl_client_ja3_md5);
        _SET_IF_EXIST_INT(m_backend_port, backend_server_port);
        _SET_IF_EXIST_STR(m_virt_ssl_client_ja4, virt_ssl_client_ja4);
        _SET_IF_EXIST_STR(m_virt_ssl_client_ja4_a, virt_ssl_client_ja4_a);
        _SET_IF_EXIST_STR(m_virt_ssl_client_ja4_b, virt_ssl_client_ja4_b);
        _SET_IF_EXIST_STR(m_virt_ssl_client_ja4_c, virt_ssl_client_ja4_c);
	_SET_IF_EXIST_STD_STR(a_ctx->m_virt_ssl_client_ja4h, virt_ssl_client_ja4h);
        // -------------------------------------------------
        // set apparent cache log status
        // -------------------------------------------------
        l_request_info->set_apparent_cache_log_status(
                static_cast<waflz_pb::request_info::log_status_t>(a_ctx->m_apparent_cache_status));
        // -------------------------------------------------
        // set customer id
        // -------------------------------------------------
        l_at->mutable_req_info()->set_customer_id(a_cust_id);
        // -------------------------------------------------
        // set team id...
        // -------------------------------------------------
        if (!a_ctx->m_team_id.empty())
        {
                l_at->mutable_req_info()->set_team_id(a_ctx->m_team_id);
        }
        // -------------------------------------------------
        // set geo fields in alert
        // -------------------------------------------------
        if ( DATA_T_EXIST( a_ctx->m_geo_data.m_geo_cn2 ) )
        {
                l_at->set_geoip_country_code2(
                        a_ctx->m_geo_data.m_geo_cn2.m_data,
                        a_ctx->m_geo_data.m_geo_cn2.m_len
                );
        }
        l_at->set_geoip_country_name(a_ctx->m_geo_data.m_cn_name.m_data, a_ctx->m_geo_data.m_cn_name.m_len);
        l_at->set_geoip_city_name(a_ctx->m_geo_data.m_city_name.m_data, a_ctx->m_geo_data.m_city_name.m_len);
        l_at->set_geoip_latitude(a_ctx->m_geo_data.m_lat);
        l_at->set_geoip_longitude(a_ctx->m_geo_data.m_long);
        l_at->set_geoip_asn(a_ctx->m_geo_data.m_src_asn);
        // -------------------------------------------------
        // done
        // -------------------------------------------------
        *ao_alert = l_at;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details creates an alert object for rate limiting
//! \return  int32_t status code
//! \param   ao_alert = the pointer to populate
//! \param   a_ctx = the request context
//! \param   a_cust_id = the customer id
//! \param   a_team_id = the team id
//! \param   a_is_audit = flag to generate audit alert
//! ----------------------------------------------------------------------------
int32_t scopes_configs::generate_alert_for_response(waflz_pb::alert** ao_alert,
                                             resp_ctx* a_ctx,
                                             uint64_t a_cust_id,
                                             std::string& a_team_id,
                                             bool a_is_audit)
{
        // -------------------------------------------------
        // quick exit if no context
        // -------------------------------------------------
        if (!a_ctx) { return WAFLZ_STATUS_OK; }
        // -------------------------------------------------
        // create alert
        // -------------------------------------------------
        waflz_pb::alert* l_at = new waflz_pb::alert();
        // -------------------------------------------------
        // Get the matched limit
        // -------------------------------------------------
        const waflz_pb::limit* l_limit = (a_is_audit) ? a_ctx->m_audit_limit : a_ctx->m_limit;
        // -------------------------------------------------
        // add limit to alert if it exists
        // -------------------------------------------------
        if (l_limit)
        {
                waflz_pb::limit *l_ev_limit = l_at->mutable_limit();
                l_ev_limit->CopyFrom(*(l_limit));
                // -----------------------------------------
                // copy action if available
                // -----------------------------------------
                if (l_limit->has_action())
                {
                        l_at->mutable_action()->CopyFrom(l_limit->action());
                }
                // -----------------------------------------
                // copy last modified date if available
                // -----------------------------------------
                if (l_limit->has_last_modified_date())
                {
                        l_at->set_config_last_modified(l_limit->last_modified_date());
                }
                // -----------------------------------------
                // set rl key used for match
                // -----------------------------------------
                if (l_limit->has__reserved_matched_key_log())
                {
                        l_at->set_matched_rl_values(l_limit->_reserved_matched_key_log());
                }
                l_at->set_matched_rl_key(l_limit->_reserved_match());
                // -----------------------------------------
                // set account type
                // -----------------------------------------
                if ( l_ev_limit->team_config() )
                {
                        team_id_scopes_map_t::iterator i_t_scopes;
                        i_t_scopes = m_team_id_scopes_map.find(a_team_id);
                        if (i_t_scopes != m_team_id_scopes_map.end() &&
                            i_t_scopes->second != NULL)
                        {
                                l_ev_limit->set_account_type(i_t_scopes->second->get_account_type());
                                l_ev_limit->set_partner_id(i_t_scopes->second->get_partner_id());
                        }
                }
                else
                {
                        cust_id_scopes_map_t::iterator i_scopes;
                        i_scopes = m_cust_id_scopes_map.find(a_cust_id);
                        if (i_scopes != m_cust_id_scopes_map.end() &&
                        i_scopes->second != NULL)
                        {
                                l_ev_limit->set_account_type(i_scopes->second->get_account_type());
                                l_ev_limit->set_partner_id(i_scopes->second->get_partner_id());
                        }
                }
        }
        // -------------------------------------------------
        // Get request specific info
        // -------------------------------------------------
        waflz_pb::request_info *l_request_info = l_at->mutable_req_info();
        // -------------------------------------------------
        // Epoch time
        // -------------------------------------------------
        waflz_pb::request_info_timespec_t *l_epoch = l_request_info->mutable_epoch_time();
        l_epoch->set_sec(get_time_s());
        l_epoch->set_nsec(get_time_us() * 1000);
        // -------------------------------------------------
        // headers...
        // -------------------------------------------------
        waflz_pb::request_info::common_header_t* l_headers = l_request_info->mutable_common_header();
        const data_unordered_map_t &l_hm = a_ctx->m_header_map;
        data_t l_d;
        _SET_HEADER("Referer", referer);
        _SET_HEADER("User-Agent", user_agent);
        _SET_HEADER("Host", host);
        _SET_HEADER("X-Forwarded-For", x_forwarded_for);
        // -------------------------------------------------
        // others...
        // -------------------------------------------------
        _SET_IF_EXIST_STR(m_src_addr, virt_remote_host);
        _SET_IF_EXIST_INT(m_port, server_canonical_port);
        _SET_IF_EXIST_STR(m_uri, orig_url);
        _SET_IF_EXIST_STR(m_url, url);
        _SET_IF_EXIST_STR(m_method, request_method);
        _SET_IF_EXIST_STR(m_req_uuid, req_uuid);
        _SET_IF_EXIST_INT(m_backend_port, backend_server_port);
        // -------------------------------------------------
        // set customer id
        // -------------------------------------------------
        l_at->mutable_req_info()->set_customer_id(a_cust_id);
        // -------------------------------------------------
        // set team id...
        // -------------------------------------------------
        if (!a_ctx->m_team_id.empty())
        {
                l_at->mutable_req_info()->set_team_id(a_ctx->m_team_id);
        }
        // -------------------------------------------------
        // set geo fields in alert - keep
        // -------------------------------------------------
        if ( DATA_T_EXIST( a_ctx->m_geo_data.m_geo_cn2 ) )
        {
                l_at->set_geoip_country_code2(
                        a_ctx->m_geo_data.m_geo_cn2.m_data,
                        a_ctx->m_geo_data.m_geo_cn2.m_len
                );
        }
        l_at->set_geoip_country_name(a_ctx->m_geo_data.m_cn_name.m_data, a_ctx->m_geo_data.m_cn_name.m_len);
        l_at->set_geoip_city_name(a_ctx->m_geo_data.m_city_name.m_data, a_ctx->m_geo_data.m_city_name.m_len);
        l_at->set_geoip_latitude(a_ctx->m_geo_data.m_lat);
        l_at->set_geoip_longitude(a_ctx->m_geo_data.m_long);
        l_at->set_geoip_asn(a_ctx->m_geo_data.m_src_asn);
        // -------------------------------------------------
        // done
        // -------------------------------------------------
        *ao_alert = l_at;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details check if customer has scopes.
//! \return  true: if id exists in map
//!          false: if id is missing in either map
//! \param   a_cust_id: unsigned integer customer id.
//! ----------------------------------------------------------------------------
bool scopes_configs::check_id(uint64_t a_cust_id)
{
        cust_id_scopes_map_t::iterator i_scopes;
        bool l_ret = false;
        if (m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        i_scopes = m_cust_id_scopes_map.find(a_cust_id);
        if (i_scopes != m_cust_id_scopes_map.end())
        {
                l_ret = true;
        }
        if (m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return l_ret;
}
//! ----------------------------------------------------------------------------
//! \details check if customer has team id scopes.
//! \return  true: if id exists in map
//!          false: if id is missing in either map
//! \param   a_team_id: string team id.
//! ----------------------------------------------------------------------------
bool scopes_configs::check_team_id(std::string& a_team_id)
{
        team_id_scopes_map_t::iterator i_t_scopes;
        bool l_ret = false;
        if (m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        i_t_scopes = m_team_id_scopes_map.find(a_team_id);
        if (i_t_scopes != m_team_id_scopes_map.end())
        {
                l_ret = true;
        }
        if (m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return l_ret;
}
//! ----------------------------------------------------------------------------
//! \details update scopes limit config
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_limit(void* a_js)
{
        int32_t l_s;
        ns_waflz::limit* l_limit = new limit(m_db);
        l_s = l_limit->load(a_js);
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "limit loading failed");
                if (l_limit) { delete l_limit;l_limit = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // add the pop count flag if missing in config
        // -------------------------------------------------
        if (!l_limit->get_pb()->has_enable_pop_count())
        {
                l_limit->set_enable_pop_count(m_engine.get_use_pop_count());
        }
        // -------------------------------------------------
        // check for customer scope in team configs
        // -------------------------------------------------
        const std::string& l_cust_id = l_limit->get_cust_id();
        if (l_limit->is_team_config())
        {
                team_id_scopes_map_t::iterator i_t_scopes;
                i_t_scopes = m_team_id_scopes_map.find(l_cust_id);
                if (i_t_scopes == m_team_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        if (l_limit) { delete l_limit; l_limit = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_t_scopes->second->load_limit(l_limit);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_t_scopes->second->get_err_msg());
                        if (l_limit) { delete l_limit; l_limit = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        else
        {
                uint64_t l_id;
                l_s = ns_waflz::convert_hex_to_uint(l_id, l_cust_id.c_str());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg,"conversion to uint failed for %s\n", l_cust_id.c_str());
                        if (l_limit) { delete l_limit;l_limit = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                cust_id_scopes_map_t::iterator i_scopes;
                i_scopes = m_cust_id_scopes_map.find(l_id);
                if (i_scopes == m_cust_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        if (l_limit) { delete l_limit; l_limit = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_scopes->second->load_limit(l_limit);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_scopes->second->get_err_msg());
                        if (l_limit) { delete l_limit; l_limit = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details update limit config
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_limit(const char* a_buf, uint32_t a_buf_len)
{
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
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if (!l_js->IsObject() &&
           !l_js->IsArray())
        {
                WAFLZ_PERROR(m_err_msg, "error parsing json");
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        int32_t l_s;
       if (m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // object
        // -------------------------------------------------
        if (l_js->IsObject())
        {
                l_s = load_limit(l_js);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (m_enable_locking)
                        {
                                pthread_mutex_unlock(&m_mutex);
                        }
                        if (l_js) { delete l_js; l_js = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // array
        // -------------------------------------------------
        else if (l_js->IsArray())
        {
                for (uint32_t i_e = 0; i_e < l_js->Size(); ++i_e)
                {
                        rapidjson::Value &l_e = (*l_js)[i_e];
                        l_s = load_limit((void*)&l_e);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                if (m_enable_locking)
                                {
                                        pthread_mutex_unlock(&m_mutex);
                                }
                                if (l_js) { delete l_js; l_js = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        if (l_js) { delete l_js; l_js = NULL;}
        if (m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details update scopes api-security config
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_api_gw(void* a_js)
{
        int32_t l_s;
        ns_waflz::api_gw* l_api_gw = new ns_waflz::api_gw(m_engine);
        l_s = l_api_gw->load(a_js, m_conf_dir);
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "api_gw loading failed");
                if (l_api_gw) { delete l_api_gw;l_api_gw = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_cust_id = l_api_gw->get_cust_id();
        if (l_api_gw->is_team_config())
        {
                team_id_scopes_map_t::iterator i_t_scopes;
                i_t_scopes = m_team_id_scopes_map.find(l_cust_id);
                if (i_t_scopes == m_team_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        if (l_api_gw) { delete l_api_gw; l_api_gw = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_t_scopes->second->load_api_gw(l_api_gw);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_t_scopes->second->get_err_msg());
                        if (l_api_gw) { delete l_api_gw; l_api_gw = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        else
        {
                uint64_t l_id;
                l_s = ns_waflz::convert_hex_to_uint(l_id, l_cust_id.c_str());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg,"conversion to uint failed for %s\n", l_cust_id.c_str());
                        if (l_api_gw) { delete l_api_gw;l_api_gw = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                cust_id_scopes_map_t::iterator i_scopes;
                i_scopes = m_cust_id_scopes_map.find(l_id);
                if (i_scopes == m_cust_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        if (l_api_gw) { delete l_api_gw; l_api_gw = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_scopes->second->load_api_gw(l_api_gw);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_scopes->second->get_err_msg());
                        if (l_api_gw) { delete l_api_gw; l_api_gw = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details update api_gw config
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_api_gw(const char* a_buf, uint32_t a_buf_len)
{
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
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if (!l_js->IsObject() &&
           !l_js->IsArray())
        {
                WAFLZ_PERROR(m_err_msg, "error parsing json");
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        int32_t l_s;
        if (m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // object
        // -------------------------------------------------
        if (l_js->IsObject())
        {
                l_s = load_api_gw(l_js);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (m_enable_locking)
                        {
                                pthread_mutex_unlock(&m_mutex);
                        }
                        if (l_js) { delete l_js; l_js = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // array
        // -------------------------------------------------
        else if (l_js->IsArray())
        {
                for (uint32_t i_e = 0; i_e < l_js->Size(); ++i_e)
                {
                        rapidjson::Value &l_e = (*l_js)[i_e];
                        l_s = load_api_gw((void*)&l_e);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                if (m_enable_locking)
                                {
                                        pthread_mutex_unlock(&m_mutex);
                                }
                                if (l_js) { delete l_js; l_js = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        if (l_js) { delete l_js; l_js = NULL;}
        if (m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details update scopes acl config
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_acl(void* a_js)
{
        int32_t l_s;
        ns_waflz::acl* l_acl = new acl(m_engine);
        l_s = l_acl->load(a_js);
         if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "acl loading failed");
                if (l_acl) { delete l_acl;l_acl = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_cust_id = l_acl->get_cust_id();
        if (l_acl->is_team_config())
        {
                team_id_scopes_map_t::iterator i_t_scopes;
                i_t_scopes = m_team_id_scopes_map.find(l_cust_id);
                if (i_t_scopes == m_team_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        if (l_acl) { delete l_acl; l_acl = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_t_scopes->second->load_acl(l_acl);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_t_scopes->second->get_err_msg());
                        if (l_acl) { delete l_acl; l_acl = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        else
        {
                uint64_t l_id;
                l_s = ns_waflz::convert_hex_to_uint(l_id, l_cust_id.c_str());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg,"conversion to uint failed for %s\n", l_cust_id.c_str());
                        if (l_acl) { delete l_acl;l_acl = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                cust_id_scopes_map_t::iterator i_scopes;
                i_scopes = m_cust_id_scopes_map.find(l_id);
                if (i_scopes == m_cust_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        if (l_acl) { delete l_acl; l_acl = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_scopes->second->load_acl(l_acl);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_scopes->second->get_err_msg());
                        if (l_acl) { delete l_acl; l_acl = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details update scopes schema config
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_schema(void* a_js)
{
        int32_t l_s;
        ns_waflz::schema* l_schema = new schema(m_engine);
        l_s = l_schema->load(a_js);
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "schema loading failed");
                if (l_schema) { delete l_schema;l_schema = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_cust_id = l_schema->get_cust_id();
        if (l_schema->is_team_config())
        {
                team_id_scopes_map_t::iterator i_t_scopes;
                i_t_scopes = m_team_id_scopes_map.find(l_cust_id);
                if (i_t_scopes == m_team_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        if (l_schema) { delete l_schema; l_schema = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_t_scopes->second->load_schema(l_schema);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_t_scopes->second->get_err_msg());
                        if (l_schema) { delete l_schema; l_schema = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        else
        {
                uint64_t l_id;
                l_s = ns_waflz::convert_hex_to_uint(l_id, l_cust_id.c_str());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg,"conversion to uint failed for %s\n", l_cust_id.c_str());
                        if (l_schema) { delete l_schema;l_schema = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                cust_id_scopes_map_t::iterator i_scopes;
                i_scopes = m_cust_id_scopes_map.find(l_id);
                if (i_scopes == m_cust_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        if (l_schema) { delete l_schema; l_schema = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_scopes->second->load_schema(l_schema);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_scopes->second->get_err_msg());
                        if (l_schema) { delete l_schema; l_schema = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details update schema config
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_schema(const char* a_buf, uint32_t a_buf_len)
{
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
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if (!l_js->IsObject() &&
           !l_js->IsArray())
        {
                WAFLZ_PERROR(m_err_msg, "error parsing json");
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        int32_t l_s;
        if (m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // object
        // -------------------------------------------------
        if (l_js->IsObject())
        {
                l_s = load_schema(l_js);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (m_enable_locking)
                        {
                                pthread_mutex_unlock(&m_mutex);
                        }
                        if (l_js) { delete l_js; l_js = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // array
        // -------------------------------------------------
        else if (l_js->IsArray())
        {
                for (uint32_t i_e = 0; i_e < l_js->Size(); ++i_e)
                {
                        rapidjson::Value &l_e = (*l_js)[i_e];
                        l_s = load_schema((void*)&l_e);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                if (m_enable_locking)
                                {
                                        pthread_mutex_unlock(&m_mutex);
                                }
                                if (l_js) { delete l_js; l_js = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        if (l_js) { delete l_js; l_js = NULL; }
        if (m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details update scopes client waf config
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_client_waf(void* a_js)
{
        // -------------------------------------------------
        // create new client waf & load
        // -------------------------------------------------
        ns_waflz::client_waf* l_client_waf = new client_waf(m_engine);
        int32_t l_s = l_client_waf->load(a_js);
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "client waf config loading failed");
                if (l_client_waf) { delete l_client_waf;l_client_waf = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get the customer id for this config
        // -------------------------------------------------
        const std::string& l_cust_id = l_client_waf->get_cust_id();
        if (l_client_waf->is_team_config())
        {
                team_id_scopes_map_t::iterator i_t_scopes;
                i_t_scopes = m_team_id_scopes_map.find(l_cust_id);
                if (i_t_scopes == m_team_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        if (l_client_waf) { delete l_client_waf; l_client_waf = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_t_scopes->second->load_client_waf(l_client_waf);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_t_scopes->second->get_err_msg());
                        if (l_client_waf) { delete l_client_waf; l_client_waf = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        else
        {
                uint64_t l_id;
                l_s = ns_waflz::convert_hex_to_uint(l_id, l_cust_id.c_str());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg,"conversion to uint failed for %s\n", l_cust_id.c_str());
                        if (l_client_waf) { delete l_client_waf;l_client_waf = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                cust_id_scopes_map_t::iterator i_scopes;
                i_scopes = m_cust_id_scopes_map.find(l_id);
                if (i_scopes == m_cust_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        if (l_client_waf) { delete l_client_waf; l_client_waf = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_scopes->second->load_client_waf(l_client_waf);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_scopes->second->get_err_msg());
                        if (l_client_waf) { delete l_client_waf; l_client_waf = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details update client_waf config
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_client_waf(const char* a_buf, uint32_t a_buf_len)
{
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
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // exit if the response is malformed
        // -------------------------------------------------
        if (!l_js->IsObject() && !l_js->IsArray())
        {
                WAFLZ_PERROR(m_err_msg, "error parsing json");
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        int32_t l_s;
        // -------------------------------------------------
        // get mutex lock
        // -------------------------------------------------
        if (m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // single client_waf object
        // -------------------------------------------------
        if (l_js->IsObject())
        {
                l_s = load_client_waf(l_js);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (m_enable_locking)
                        {
                                pthread_mutex_unlock(&m_mutex);
                        }
                        if (l_js) { delete l_js; l_js = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // array
        // -------------------------------------------------
        else if (l_js->IsArray())
        {
                for (uint32_t i_e = 0; i_e < l_js->Size(); ++i_e)
                {
                        rapidjson::Value &l_e = (*l_js)[i_e];
                        l_s = load_client_waf((void*)&l_e);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                if (m_enable_locking)
                                {
                                        pthread_mutex_unlock(&m_mutex);
                                }
                                if (l_js) { delete l_js; l_js = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        // -------------------------------------------------
        // clean up json object
        // -------------------------------------------------
        if (l_js) { delete l_js; l_js = NULL; }
        // -------------------------------------------------
        // remove mutex lock and return
        // -------------------------------------------------
        if (m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details update acl config
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_acl(const char* a_buf, uint32_t a_buf_len)
{
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
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if (!l_js->IsObject() &&
           !l_js->IsArray())
        {
                WAFLZ_PERROR(m_err_msg, "error parsing json");
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        int32_t l_s;
        if (m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // object
        // -------------------------------------------------
        if (l_js->IsObject())
        {
                l_s = load_acl(l_js);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (m_enable_locking)
                        {
                                pthread_mutex_unlock(&m_mutex);
                        }
                        if (l_js) { delete l_js; l_js = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // array
        // -------------------------------------------------
        else if (l_js->IsArray())
        {
                for (uint32_t i_e = 0; i_e < l_js->Size(); ++i_e)
                {
                        rapidjson::Value &l_e = (*l_js)[i_e];
                        l_s = load_acl((void*)&l_e);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                if (m_enable_locking)
                                {
                                        pthread_mutex_unlock(&m_mutex);
                                }
                                if (l_js) { delete l_js; l_js = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        if (l_js) { delete l_js; l_js = NULL; }
        if (m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details update custom rules config
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_rules(void* a_js)
{
        int32_t l_s;
        ns_waflz::rules* l_rules = new rules(m_engine);
        l_s = l_rules->load(a_js);
        if (l_s != WAFLZ_STATUS_OK)
        {
                if (l_rules) { delete l_rules; l_rules = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_cust_id = l_rules->get_cust_id();
        if (l_rules->is_team_config())
        {
                team_id_scopes_map_t::iterator i_t_scopes;
                i_t_scopes = m_team_id_scopes_map.find(l_cust_id);
                if (i_t_scopes == m_team_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        if (l_rules) { delete l_rules; l_rules = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_t_scopes->second->load_rules(l_rules);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_t_scopes->second->get_err_msg());
                        if (l_rules) { delete l_rules; l_rules = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        else
        {
                uint64_t l_id;
                l_s = ns_waflz::convert_hex_to_uint(l_id, l_cust_id.c_str());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg,"conversion to uint failed for %s\n", l_cust_id.c_str());
                        if (l_rules) { delete l_rules;l_rules = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                cust_id_scopes_map_t::iterator i_scopes;
                i_scopes = m_cust_id_scopes_map.find(l_id);
                if (i_scopes == m_cust_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        if (l_rules) { delete l_rules; l_rules = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_scopes->second->load_rules(l_rules);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_scopes->second->get_err_msg());
                        if (l_rules) { delete l_rules; l_rules = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details update custom rules config
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_rules(const char* a_buf, uint32_t a_buf_len)
{
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
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if (!l_js->IsObject() &&
           !l_js->IsArray())
        {
                WAFLZ_PERROR(m_err_msg, "error parsing json");
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        int32_t l_s;
       if (m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // object
        // -------------------------------------------------
        if (l_js->IsObject())
        {
                l_s = load_rules(l_js);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (m_enable_locking)
                        {
                                pthread_mutex_unlock(&m_mutex);
                        }
                        if (l_js) { delete l_js; l_js = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // array
        // -------------------------------------------------
        else if (l_js->IsArray())
        {
                for (uint32_t i_e = 0; i_e < l_js->Size(); ++i_e)
                {
                        rapidjson::Value &l_e = (*l_js)[i_e];
                        l_s = load_rules((void*)&l_e);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                if (m_enable_locking)
                                {
                                        pthread_mutex_unlock(&m_mutex);
                                }
                                if (l_js) { delete l_js; l_js = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        if (l_js) { delete l_js; l_js = NULL;}
        if (m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details update custom bots config
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_bots(void* a_js)
{
        // -------------------------------------------------
        // status
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // get customer id from config
        // -------------------------------------------------
        const rapidjson::Document &l_js = *((rapidjson::Document *)a_js);
        if(!l_js.HasMember("customer_id") || !l_js["customer_id"].IsString()) 
        {
                WAFLZ_PERROR(m_err_msg, "missing customer_id");
                return WAFLZ_STATUS_ERROR;
        }
        const std::string l_customer_id = l_js["customer_id"].GetString();
        // -------------------------------------------------
        // check if this is a team config
        // -------------------------------------------------
        const bool contains_team_config = l_js.HasMember("team_config") && l_js["team_config"].IsBool();
        const bool l_bot_for_team_config = (contains_team_config) ? l_js["team_config"].GetBool() : false;
        // -------------------------------------------------
        // loop through the teams id list if this is a team
        // config
        // -------------------------------------------------
        if (l_bot_for_team_config)
        {
                team_id_scopes_map_t::iterator i_t_scopes;
                i_t_scopes = m_team_id_scopes_map.find(l_customer_id);
                if (i_t_scopes == m_team_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_t_scopes->second->load_bots(a_js);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "failed to load bots: %.*s",
                                     WAFLZ_ERR_REASON_LEN,
                                     i_t_scopes->second->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // loop through the an list if this is a team config
        // -------------------------------------------------
        else
        {
                uint64_t l_id;
                l_s = ns_waflz::convert_hex_to_uint(l_id, l_customer_id.c_str());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg,"conversion to uint failed for %s\n", l_customer_id.c_str());
                        return WAFLZ_STATUS_ERROR;
                }
                cust_id_scopes_map_t::iterator i_scopes;
                i_scopes = m_cust_id_scopes_map.find(l_id);
                if (i_scopes == m_cust_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_scopes->second->load_bots(a_js);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_scopes->second->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details update custom bots config
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_bots(const char* a_buf, uint32_t a_buf_len)
{
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
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if (!l_js->IsObject() &&
           !l_js->IsArray())
        {
                WAFLZ_PERROR(m_err_msg, "error parsing json");
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        int32_t l_s;
        if (m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // object
        // -------------------------------------------------
        if (l_js->IsObject())
        {
                l_s = load_bots(l_js);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (m_enable_locking)
                        {
                                pthread_mutex_unlock(&m_mutex);
                        }
                        if (l_js) { delete l_js; l_js = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // array
        // -------------------------------------------------
        else if (l_js->IsArray())
        {
                for (uint32_t i_e = 0; i_e < l_js->Size(); ++i_e)
                {
                        rapidjson::Value &l_e = (*l_js)[i_e];
                        l_s = load_bots((void*)&l_e);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                if (m_enable_locking)
                                {
                                        pthread_mutex_unlock(&m_mutex);
                                }
                                if (l_js) { delete l_js; l_js = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        if (l_js) { delete l_js; l_js = NULL;}
        if (m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details update bot manager config
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_bot_manager(void* a_js)
{
        int32_t l_s;
        ns_waflz::bot_manager* l_bot_manager = new bot_manager(m_engine,
                                                               m_challenge,
                                                               m_captcha);
        l_s = l_bot_manager->load(a_js, m_conf_dir);
        if (l_s != WAFLZ_STATUS_OK)
        {
                if (l_bot_manager) { delete l_bot_manager; l_bot_manager = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_cust_id = l_bot_manager->get_cust_id();
        if (l_bot_manager->is_team_config())
        {
                team_id_scopes_map_t::iterator i_t_scopes;
                i_t_scopes = m_team_id_scopes_map.find(l_cust_id);
                if (i_t_scopes == m_team_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        if (l_bot_manager) { delete l_bot_manager; l_bot_manager = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_t_scopes->second->load_bot_manager(l_bot_manager);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_t_scopes->second->get_err_msg());
                        if (l_bot_manager) { delete l_bot_manager; l_bot_manager = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        else
        {
                uint64_t l_id;
                l_s = ns_waflz::convert_hex_to_uint(l_id, l_cust_id.c_str());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg,"conversion to uint failed for %s\n", l_cust_id.c_str());
                        if (l_bot_manager) { delete l_bot_manager;l_bot_manager = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                cust_id_scopes_map_t::iterator i_scopes;
                i_scopes = m_cust_id_scopes_map.find(l_id);
                if (i_scopes == m_cust_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        if (l_bot_manager) { delete l_bot_manager; l_bot_manager = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_scopes->second->load_bot_manager(l_bot_manager);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_scopes->second->get_err_msg());
                        if (l_bot_manager) { delete l_bot_manager; l_bot_manager = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details update custom bots config
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes_configs::load_bot_manager(const char* a_buf, uint32_t a_buf_len)
{
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
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if (!l_js->IsObject() &&
           !l_js->IsArray())
        {
                WAFLZ_PERROR(m_err_msg, "error parsing json");
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        int32_t l_s;
        if (m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // object
        // -------------------------------------------------
        if (l_js->IsObject())
        {
                l_s = load_bot_manager(l_js);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (m_enable_locking)
                        {
                                pthread_mutex_unlock(&m_mutex);
                        }
                        if (l_js) { delete l_js; l_js = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // array
        // -------------------------------------------------
        else if (l_js->IsArray())
        {
                for (uint32_t i_e = 0; i_e < l_js->Size(); ++i_e)
                {
                        rapidjson::Value &l_e = (*l_js)[i_e];
                        l_s = load_bot_manager((void*)&l_e);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                if (m_enable_locking)
                                {
                                        pthread_mutex_unlock(&m_mutex);
                                }
                                if (l_js) { delete l_js; l_js = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        if (l_js) { delete l_js; l_js = NULL;}
        if (m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
//! -----------------------------------------------------------------------------
//! \details update profile config
//! \return  TODO
//! \param   TODO
//! -----------------------------------------------------------------------------
int32_t scopes_configs::load_profile(void* a_js)
{
        int32_t l_s;
        ns_waflz::profile* l_profile = new profile(m_engine);
        l_s = l_profile->load(a_js);
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "profile loading failed");
                if (l_profile) { delete l_profile;l_profile = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_cust_id = l_profile->get_cust_id();
        if (l_profile->is_team_config())
        {
                team_id_scopes_map_t::iterator i_t_scopes;
                i_t_scopes = m_team_id_scopes_map.find(l_cust_id);
                if (i_t_scopes == m_team_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        if (l_profile) { delete l_profile; l_profile = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_t_scopes->second->load_profile(l_profile);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_t_scopes->second->get_err_msg());
                        if (l_profile) { delete l_profile; l_profile = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        else
        {
                uint64_t l_id;
                l_s = ns_waflz::convert_hex_to_uint(l_id, l_cust_id.c_str());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg,"conversion to uint failed for %s\n", l_cust_id.c_str());
                        if (l_profile) { delete l_profile;l_profile = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                cust_id_scopes_map_t::iterator i_scopes;
                i_scopes = m_cust_id_scopes_map.find(l_id);
                if (i_scopes == m_cust_id_scopes_map.end())
                {
                        // -----------------------------------------
                        // Not linked to scopes, no need to load
                        // -----------------------------------------
                        if (l_profile) { delete l_profile; l_profile = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_s = i_scopes->second->load_profile(l_profile);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", i_scopes->second->get_err_msg());
                        if (l_profile) { delete l_profile; l_profile = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! -----------------------------------------------------------------------------
//! \details update profile config
//! \return  TODO
//! \param   TODO
//! -----------------------------------------------------------------------------
int32_t scopes_configs::load_profile(const char* a_buf, uint32_t a_buf_len)
{
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
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if (!l_js->IsObject() &&
           !l_js->IsArray())
        {
                WAFLZ_PERROR(m_err_msg, "error parsing json");
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        int32_t l_s;
        if (m_enable_locking)
        {
                pthread_mutex_lock(&m_mutex);
        }
        // -------------------------------------------------
        // object
        // -------------------------------------------------
        if (l_js->IsObject())
        {
                l_s = load_profile(l_js);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (m_enable_locking)
                        {
                                pthread_mutex_unlock(&m_mutex);
                        }
                        if (l_js) { delete l_js; l_js = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // array
        // -------------------------------------------------
        else if (l_js->IsArray())
        {
                for (uint32_t i_e = 0; i_e < l_js->Size(); ++i_e)
                {
                        rapidjson::Value &l_e = (*l_js)[i_e];
                        l_s = load_profile((void*)&l_e);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                if (m_enable_locking)
                                {
                                        pthread_mutex_unlock(&m_mutex);
                                }
                                if (l_js) { delete l_js; l_js = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        if (l_js) { delete l_js; l_js = NULL;}
        if (m_enable_locking)
        {
                pthread_mutex_unlock(&m_mutex);
        }
        return WAFLZ_STATUS_OK;
}
}
