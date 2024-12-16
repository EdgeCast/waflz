//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    client_waf.cc
//!
//! \details: this file defines the client_waf object in waflz. this object is
//!           responsible for adding/injecting csp headers to the response of
//!           the origin.
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/client_waf.h"
#include "event.pb.h"
#include "client_waf.pb.h"
#include "waflz/engine.h"
#include "jspb/jspb.h"
#include "support/ndebug.h"
#include <rapidjson/document.h>
#include <rapidjson/error/error.h>
#include <rapidjson/error/en.h>
//! ----------------------------------------------------------------------------
//! waflz namespace
//! ----------------------------------------------------------------------------
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details constructor
//! \return  None
//! \param   None
//! ----------------------------------------------------------------------------
client_waf::client_waf(engine &a_engine)
    : m_pb(nullptr),
      m_init(false),
      m_err_msg(),
      m_engine(a_engine),
      m_id(),
      m_cust_id(),
      m_team_config(false),
      m_name(),
      m_last_modified_date(),
      m_headers(),
      m_csp_script_nonce()
{
        m_pb = new waflz_pb::client_waf();
}
//! ----------------------------------------------------------------------------
//! \details dtor
//! \return  None
//! \param   None
//! ----------------------------------------------------------------------------
client_waf::~client_waf()
{
        if(m_pb) { delete m_pb; m_pb = NULL; }
}
//! ----------------------------------------------------------------------------
//! \details parses the buffer and loads the waflz client_waf proto
//! \return  waflz status code
//! \param   a_pb: a client_waf protobuf
//! ----------------------------------------------------------------------------
int32_t client_waf::load(waflz_pb::client_waf* a_pb)
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
        m_pb = new waflz_pb::client_waf();
        m_pb->CopyFrom(*a_pb);
        // -------------------------------------------------
        // initalize the object
        // -------------------------------------------------
        m_init = false;
        return init();
}
//! ----------------------------------------------------------------------------
//! \details parses the buffer and loads the waflz client_waf proto
//! \return  waflz status code
//! \param   a_buf: the config buffer
//! \param   a_buf_len: the config buffer length
//! ----------------------------------------------------------------------------
int32_t client_waf::load(const char *a_buf, uint32_t a_buf_len)
{
        // -------------------------------------------------
        // parse buffer into json object
        // -------------------------------------------------
        rapidjson::Document *l_js = new rapidjson::Document();
        rapidjson::ParseResult l_ok;
        l_ok = l_js->Parse(a_buf, a_buf_len);
        // -------------------------------------------------
        // exit if failed to parse
        // -------------------------------------------------
        if (!l_ok)
        {
                WAFLZ_PERROR(m_err_msg, "JSON parse error: %s (%d)",
                             rapidjson::GetParseError_En(l_ok.Code()), (int)l_ok.Offset());
                if (l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // call load for json object
        // -------------------------------------------------
        int32_t l_s = load((void*) l_js);
        // -------------------------------------------------
        // clean up json object and return
        // -------------------------------------------------
        if (l_js) { delete l_js; l_js = nullptr; }
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details loads the waflz client_waf proto
//! \return  waflz status code
//! \param   a_js: a rapidjson object
//! ----------------------------------------------------------------------------
int32_t client_waf::load(void *a_js)
{
        // -------------------------------------------------
        // cast void pointer to json object
        // -------------------------------------------------
        const rapidjson::Document &l_js = *((rapidjson::Document *)a_js);
        // -------------------------------------------------
        // remove the old protobuf if present
        // -------------------------------------------------
        if(m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        // -------------------------------------------------
        // create a new protobuf and load values from json
        // -------------------------------------------------
        m_pb = new waflz_pb::client_waf();
        int32_t l_s = update_from_json(*m_pb, l_js);
        if(l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // DEBUG: print proto
        // -------------------------------------------------
        // NDBG_PRINT("%s", m_pb->DebugString().c_str());
        // -------------------------------------------------
        // initalize the object
        // -------------------------------------------------
        m_init = false;
        return init();
}
//! ----------------------------------------------------------------------------
//! \details reads the proto object and populates relevant values
//! \return  waflz status code
//! ----------------------------------------------------------------------------
int32_t client_waf::init()
{
        // -------------------------------------------------
        // quick exit if we have already init'd
        // -------------------------------------------------
        if ( m_init ) { return WAFLZ_STATUS_OK; }
        // -------------------------------------------------
        // set standard config values
        // -------------------------------------------------
        m_id = m_pb->id();
        m_cust_id = m_pb->customer_id();
        m_name = m_pb->name();
        m_last_modified_date = m_pb->last_modified_date();
        m_team_config = m_pb->team_config();
        // -------------------------------------------------
        // get csp endpoint from engine
        // -------------------------------------------------
        std::string &l_csp_endpoint = m_engine.get_csp_endpoint_uri();
        // -------------------------------------------------
        // create header map data
        // -------------------------------------------------
        m_headers.clear();
        for ( int32_t i = 0; i < m_pb->headers_size(); i++ )
        {
                // -----------------------------------------
                // get entry from proto
                // -----------------------------------------
                const waflz_pb::enforcement_header_t l_entry = m_pb->headers(i);
                if (!l_entry.enforce()) { continue; }
                // -----------------------------------------
                // pluck out values
                // -----------------------------------------
                const std::string& l_key = l_entry.key();
                std::string l_val(l_entry.value());
                // -----------------------------------------
                // add the report-uri endpoint if this is an
                // csp header and we have an endpoint
                // -----------------------------------------
                bool l_is_csp = ( strcasecmp(l_key.c_str(), "content-security-policy") == 0 ||
                                  strcasecmp(l_key.c_str(), "content-security-policy-report-only") == 0 );
                if ( l_csp_endpoint.length() && l_is_csp )
                {
                        if (l_val.length())
                        {
                                l_val += (l_val.at(l_val.length() - 1) == ';' ? " " : "; ");
                        }
                        l_val += "report-uri " + l_csp_endpoint + m_cust_id;
                }
                // -----------------------------------------
                // add header to map
                // -----------------------------------------
                m_headers.insert(std::make_pair(l_key, header_t(l_val, l_entry.overwrite())));
        }
        // -------------------------------------------------
        // grab the script-src nonce if defined in the
        // protobuf. we will need to attach this to any
        // script we plan to inject onto the response.
        // -------------------------------------------------
        if (m_pb->has_csp_script_nonce())
        {
                m_csp_script_nonce = m_pb->csp_script_nonce();
        }
        // -------------------------------------------------
        // done initializing
        // -------------------------------------------------
        m_init = true;
        return WAFLZ_STATUS_OK;
}
}
