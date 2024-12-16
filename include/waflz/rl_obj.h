//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _RL_OBJ_H_
#define _RL_OBJ_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include "string.h"
#include <string>
#include <map>
#include <list>
#include <unordered_set>
#include <inttypes.h>
//! ----------------------------------------------------------------------------
//! fwd Decl's
//! ----------------------------------------------------------------------------
namespace waflz_pb
{
class enforcer;
class condition_group;
class match;
class op_t;
class limit;
class config;
class condition_target_t;
class scope;
}
namespace ns_waflz
{
//! ----------------------------------------------------------------------------
//! fwd Decl's
//! ----------------------------------------------------------------------------
class regex;
class rqst_ctx;
class nms;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::unordered_set<data_t, data_t_hash, data_comp_unordered> data_set_t;
typedef std::unordered_set<data_t, data_t_case_hash, data_case_i_comp_unordered> data_case_i_set_t;
//! ----------------------------------------------------------------------------
//! compiled operators
//! ----------------------------------------------------------------------------
typedef std::list<regex *> regex_list_t;
typedef std::list<nms *> nms_list_t;
typedef std::list<data_set_t *> data_set_list_t;
typedef std::list<data_case_i_set_t *> data_case_i_set_list_t;
//! ----------------------------------------------------------------------------
//! rl_obj
//! ----------------------------------------------------------------------------
class rl_obj
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        rl_obj(bool a_case_insensitive_headers);
        virtual ~rl_obj();
        //: ------------------------------------------------
        //:               G E T T E R S
        //: ------------------------------------------------
        //: ------------------------------------------------
        //: \details Get last error message string
        //: \return  last error message (in buffer)
        //: ------------------------------------------------
        const char *get_err_msg(void)
        {
                return m_err_msg;
        }
        waflz_pb::config* get_pb(void) { return m_pb; }
        waflz_pb::config* get_mutable_pb(void) { return m_pb; }
        const std::string &get_customer_id(void);
protected:
        // -------------------------------------------------
        // Protected members
        // -------------------------------------------------
        bool m_init;
        waflz_pb::config *m_pb;
        char m_err_msg[WAFLZ_ERR_LEN];
        // -------------------------------------------------
        // TODO TEMPORARY HACK to support case insensitive
        // comparisons SECC-445.
        // Really need new operators or something
        // -------------------------------------------------
        bool m_lowercase_headers;
        // -------------------------------------------------
        // protected methods
        // -------------------------------------------------
        int32_t compile(void);
        int32_t compile_limit(waflz_pb::limit &ao_limit);
        int32_t process_condition_group(bool &ao_matched,
                                        const waflz_pb::condition_group &a_cg,
                                        rqst_ctx *a_ctx);
        int32_t process_condition_group_for_response(bool &ao_matched,
                                        const waflz_pb::condition_group &a_cg,
                                        resp_ctx *a_ctx);

        int32_t convertv1(waflz_pb::config& ao_config,
                          const waflz_pb::enforcer& a_enfcr);
        // -------------------------------------------------
        // protected members
        // -------------------------------------------------
        regex_list_t m_regex_list;
        nms_list_t m_nms_list;
        data_set_list_t m_data_set_list;
        data_case_i_set_list_t m_data_case_i_set_list;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        rl_obj(const rl_obj &);
        rl_obj& operator=(const rl_obj &);
        int32_t extract(const char **ao_data,
                        uint32_t &ao_data_len,
                        std::string &ao_buf,
                        const waflz_pb::condition_target_t &a_tgt,
                        rqst_ctx *a_ctx);
        int32_t extract_from_response(const char **ao_data,
                        uint32_t &ao_data_len,
                        std::string &ao_buf,
                        const waflz_pb::condition_target_t &a_tgt,
                        resp_ctx *a_ctx);
        int32_t compile_op(::waflz_pb::op_t& ao_op);
};
//! ----------------------------------------------------------------------------
//! utils
//! ----------------------------------------------------------------------------
int32_t limit_remove(waflz_pb::config &ao_cfg, uint32_t a_off);
int32_t limit_sweep(waflz_pb::config &ao_cfg);
}
#endif
