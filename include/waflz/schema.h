//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    schema.h
//! \details: Holds rapidjson schema and validator, processes request against
//!           schema
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _SCHEMA_H_
#define _SCHEMA_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <strings.h>
#include <set>
#include <string>
#include "rapidjson/error/en.h"
#include "rapidjson/schema.h"
#include "waflz/def.h"
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
namespace waflz_pb {
class event;
}  // namespace waflz_pb
namespace ns_waflz {
class engine;
class rqst_ctx;
//! ----------------------------------------------------------------------------
//! acl
//! ----------------------------------------------------------------------------
class schema
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        schema(engine& a_engine);
        ~schema();
        int32_t load(const char* a_buf, uint32_t a_buf_len);
        int32_t load(void* a_js);
        int32_t process(waflz_pb::event** ao_event,
                        void* a_ctx,
                        const char* a_data_buf,
                        uint32_t a_data_buf_len);
        int32_t import_fields(const rapidjson::Document& a_doc);
        //: ------------------------------------------------
        //:               S E T T E R S
        //: ------------------------------------------------
        void set_schema_document(rapidjson::SchemaDocument* a_schema_doc);
        //: ------------------------------------------------
        //:               G E T T E R S
        //: ------------------------------------------------
        const std::string& get_id(void) { return m_id; }
        const std::string& get_api_gw_id(void) { return m_api_gw_id; }
        const std::string& get_cust_id(void) { return m_cust_id; }
        bool is_team_config(void) { return m_team_config; }
        const std::string& get_name(void) { return m_name; }
        const std::string& get_last_modified_date(void) { return m_last_modified_date; }
        //: ------------------------------------------------
        //: \details Get last error message string
        //: \return  last error message (in buffer)
        //: ------------------------------------------------
        const char* get_err_msg(void) { return m_err_msg; }

private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        int32_t init();
        // -------------------------------------------------
        // disallow copy/assign
        // -------------------------------------------------
        schema(const schema&);
        schema& operator=(const schema&);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        char m_err_msg[WAFLZ_ERR_LEN];
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        std::string m_id;
        std::string m_api_gw_id;
        std::string m_cust_id;
        bool m_team_config;
        std::string m_name;
        std::string m_last_modified_date;
        engine& m_engine;
        rapidjson::SchemaDocument* m_schema;
        rapidjson::SchemaValidator* m_validator;
};
}  // namespace ns_waflz
#endif
