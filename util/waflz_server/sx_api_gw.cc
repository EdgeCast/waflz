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
#include "sx_api_gw.h"
#include "waflz/api_gw.h"
#include "waflz/engine.h"
#include "waflz/rqst_ctx.h"
#include "is2/support/trace.h"
#include "is2/support/nbq.h"
#include "is2/support/ndebug.h"
#include "is2/srvr/api_resp.h"
#include "is2/srvr/srvr.h"
#include "jspb/jspb.h"
#include "support/file_util.h"
#include "event.pb.h"
#include "action.pb.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef STATUS_OK
#define STATUS_OK 0
#endif
#ifndef STATUS_ERROR
#define STATUS_ERROR -1
#endif
#define _DEFAULT_RESP_BODY_B64                                                 \
        "PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+"                                 \
        "IDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4gPHRpdGxlPjwvdGl0bGU+"                 \
        "PC9oZWFkPjxib2R5PiA8c3R5bGU+"                                         \
        "Knstd2Via2l0LWJveC1zaXppbmc6IGJvcmRlci1ib3g7IC1tb3otYm94LXNpemluZzog" \
        "Ym9yZGVyLWJveDsgYm94LXNpemluZzogYm9yZGVyLWJveDt9ZGl2e2Rpc3BsYXk6IGJs" \
        "b2NrO31ib2R5e2ZvbnQtZmFtaWx5OiAiSGVsdmV0aWNhIE5ldWUiLCBIZWx2ZXRpY2Es" \
        "IEFyaWFsLCBzYW5zLXNlcmlmOyBmb250LXNpemU6IDE0cHg7IGxpbmUtaGVpZ2h0OiAx" \
        "LjQyODU3MTQzOyBjb2xvcjogIzMzMzsgYmFja2dyb3VuZC1jb2xvcjogI2ZmZjt9aHRt" \
        "bHtmb250LXNpemU6IDEwcHg7IC13ZWJraXQtdGFwLWhpZ2hsaWdodC1jb2xvcjogcmdi" \
        "YSgwLCAwLCAwLCAwKTsgZm9udC1mYW1pbHk6IHNhbnMtc2VyaWY7IC13ZWJraXQtdGV4" \
        "dC1zaXplLWFkanVzdDogMTAwJTsgLW1zLXRleHQtc2l6ZS1hZGp1c3Q6IDEwMCU7fTpi" \
        "ZWZvcmUsIDphZnRlcnstd2Via2l0LWJveC1zaXppbmc6IGJvcmRlci1ib3g7IC1tb3ot" \
        "Ym94LXNpemluZzogYm9yZGVyLWJveDsgYm94LXNpemluZzogYm9yZGVyLWJveDt9LmNv" \
        "bnRhaW5lcntwYWRkaW5nLXJpZ2h0OiAxNXB4OyBwYWRkaW5nLWxlZnQ6IDE1cHg7IG1h" \
        "cmdpbi1yaWdodDogYXV0bzsgbWFyZ2luLWxlZnQ6IGF1dG87fUBtZWRpYSAobWluLXdp" \
        "ZHRoOiA3NjhweCl7LmNvbnRhaW5lcnt3aWR0aDogNzUwcHg7fX0uY2FsbG91dCsuY2Fs" \
        "bG91dHttYXJnaW4tdG9wOiAtNXB4O30uY2FsbG91dHtwYWRkaW5nOiAyMHB4OyBtYXJn" \
        "aW46IDIwcHggMDsgYm9yZGVyOiAxcHggc29saWQgI2VlZTsgYm9yZGVyLWxlZnQtd2lk" \
        "dGg6IDVweDsgYm9yZGVyLXJhZGl1czogM3B4O30uY2FsbG91dC1kYW5nZXJ7Ym9yZGVy" \
        "LWxlZnQtY29sb3I6ICNmYTBlMWM7fS5jYWxsb3V0LWRhbmdlciBoNHtjb2xvcjogI2Zh" \
        "MGUxYzt9LmNhbGxvdXQgaDR7bWFyZ2luLXRvcDogMDsgbWFyZ2luLWJvdHRvbTogNXB4" \
        "O31oNCwgLmg0e2ZvbnQtc2l6ZTogMThweDt9aDQsIC5oNCwgaDUsIC5oNSwgaDYsIC5o" \
        "NnttYXJnaW4tdG9wOiAxMHB4OyBtYXJnaW4tYm90dG9tOiAxMHB4O31oMSwgaDIsIGgz" \
        "LCBoNCwgaDUsIGg2LCAuaDEsIC5oMiwgLmgzLCAuaDQsIC5oNSwgLmg2e2ZvbnQtZmFt" \
        "aWx5OiBBcGV4LCAiSGVsdmV0aWNhIE5ldWUiLCBIZWx2ZXRpY2EsIEFyaWFsLCBzYW5z" \
        "LXNlcmlmOyBmb250LXdlaWdodDogNDAwOyBsaW5lLWhlaWdodDogMS4xOyBjb2xvcjog" \
        "aW5oZXJpdDt9aDR7ZGlzcGxheTogYmxvY2s7IC13ZWJraXQtbWFyZ2luLWJlZm9yZTog" \
        "MS4zM2VtOyAtd2Via2l0LW1hcmdpbi1hZnRlcjogMS4zM2VtOyAtd2Via2l0LW1hcmdp" \
        "bi1zdGFydDogMHB4OyAtd2Via2l0LW1hcmdpbi1lbmQ6IDBweDsgZm9udC13ZWlnaHQ6" \
        "IGJvbGQ7fWxhYmVse2Rpc3BsYXk6IGlubGluZS1ibG9jazsgbWF4LXdpZHRoOiAxMDAl" \
        "OyBtYXJnaW4tYm90dG9tOiA1cHg7IGZvbnQtd2VpZ2h0OiA3MDA7fWRse21hcmdpbi10" \
        "b3A6IDA7IG1hcmdpbi1ib3R0b206IDIwcHg7IGRpc3BsYXk6IGJsb2NrOyAtd2Via2l0" \
        "LW1hcmdpbi1iZWZvcmU6IDFlbTsgLXdlYmtpdC1tYXJnaW4tYWZ0ZXI6IDFlbTsgLXdl" \
        "YmtpdC1tYXJnaW4tc3RhcnQ6IDBweDsgLXdlYmtpdC1tYXJnaW4tZW5kOiAwcHg7fWRk" \
        "e2Rpc3BsYXk6IGJsb2NrOyAtd2Via2l0LW1hcmdpbi1zdGFydDogNDBweDsgbWFyZ2lu" \
        "LWxlZnQ6IDA7IHdvcmQtd3JhcDogYnJlYWstd29yZDt9ZHR7Zm9udC13ZWlnaHQ6IDcw" \
        "MDsgZGlzcGxheTogYmxvY2s7fWR0LCBkZHtsaW5lLWhlaWdodDogMS40Mjg1NzE0Mzt9" \
        "LmRsLWhvcml6b250YWwgZHR7ZmxvYXQ6IGxlZnQ7IHdpZHRoOiAxNjBweDsgb3ZlcmZs" \
        "b3c6IGhpZGRlbjsgY2xlYXI6IGxlZnQ7IHRleHQtYWxpZ246IHJpZ2h0OyB0ZXh0LW92" \
        "ZXJmbG93OiBlbGxpcHNpczsgd2hpdGUtc3BhY2U6IG5vd3JhcDt9LmRsLWhvcml6b250" \
        "YWwgZGR7bWFyZ2luLWxlZnQ6IDE4MHB4O308L3N0eWxlPiA8ZGl2IGNsYXNzPSJjb250" \
        "YWluZXIiPiA8ZGl2IGNsYXNzPSJjYWxsb3V0IGNhbGxvdXQtZGFuZ2VyIj4gPGg0IGNs" \
        "YXNzPSJsYWJlbCI+"                                                     \
        "Rm9yYmlkZGVuPC9oND4gPGRsIGNsYXNzPSJkbC1ob3Jpem9udGFsIj4gPGR0PkNsaWVu" \
        "dCBJUDwvZHQ+"                                                         \
        "IDxkZD57e0NMSUVOVF9JUH19PC9kZD4gPGR0PlVzZXItQWdlbnQ8L2R0PiA8ZGQ+"     \
        "e3tVU0VSX0FHRU5UfX08L2RkPiA8ZHQ+UmVxdWVzdCBVUkw8L2R0PiA8ZGQ+"         \
        "e3tSRVFVRVNUX1VSTH19PC9kZD4gPGR0PlJlYXNvbjwvZHQ+"                     \
        "IDxkZD57e1JVTEVfTVNHfX08L2RkPiA8ZHQ+RGF0ZTwvZHQ+"                     \
        "IDxkZD57e1RJTUVTVEFNUH19PC9kZD4gPC9kbD4gPC9kaXY+PC9kaXY+"             \
        "PC9ib2R5PjwvaHRtbD4="
namespace ns_waflz_server {
//! ----------------------------------------------------------------------------
//! \details: Constructor
//! \return:  None
//! \param a_engine:
//! ----------------------------------------------------------------------------
sx_api_gw::sx_api_gw(ns_waflz::engine& a_engine)
    : m_engine(a_engine), m_api_gw(NULL), m_action(NULL)
{
        // -------------------------------------------------
        // set up default enforcement
        // -------------------------------------------------
        m_action = new waflz_pb::enforcement();
        m_action->set_enf_type(waflz_pb::enforcement_type_t_BLOCK_REQUEST);
        m_action->set_status(403);
        m_action->set_response_body_base64(_DEFAULT_RESP_BODY_B64);
}

//! ----------------------------------------------------------------------------
//! \details: Destructor
//! \return:  None
//! ----------------------------------------------------------------------------
sx_api_gw::~sx_api_gw(void)
{
        if (m_api_gw)
        {       
                delete m_api_gw;
                m_api_gw = NULL;
        }
        if(m_action) { delete m_action; m_action = NULL; }
}
//! ----------------------------------------------------------------------------
//! \details: Initialize sx_api gateway with m_config from sx superclass
//!           and create m_api_gw
//! \return:  WAFLZ Status Code
//! ----------------------------------------------------------------------------
int32_t sx_api_gw::init(void)
{
        // -------------------------------------------------
        // read file
        // -------------------------------------------------
        int32_t l_s;
        char* l_buf;
        uint32_t l_buf_len;
        l_s = ns_waflz::read_file(m_config.c_str(), &l_buf, l_buf_len);
        if (l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error read_file: %s\n", m_config.c_str());
                if (l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // load api_gw
        // -------------------------------------------------
        m_api_gw = new ns_waflz::api_gw(m_engine);
        l_s = m_api_gw->load(l_buf, l_buf_len, m_conf_dir);
        if (l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error loading config: %s. reason: %s\n",
                           m_config.c_str(),
                           m_api_gw->get_err_msg());
                if (l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // clean up and return
        // -------------------------------------------------
        if (l_buf)
        {
                free(l_buf);
                l_buf = NULL;
                l_buf_len = 0;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Handle Request
//! \return:  IS2 Response
//! ----------------------------------------------------------------------------
ns_is2::h_resp_t sx_api_gw::handle_rqst(
    waflz_pb::enforcement** ao_enf,
    ns_waflz::rqst_ctx** ao_ctx,
    ns_is2::session& a_session,
    ns_is2::rqst& a_rqst,
    const ns_is2::url_pmap_t& a_url_pmap)
{
        // -------------------------------------------------
        // if no api_gw - return error
        // -------------------------------------------------
        if (!m_api_gw) { return ns_is2::H_RESP_SERVER_ERROR; }
        // -------------------------------------------------
        // default response
        // -------------------------------------------------
        m_resp = "{\"status\": \"ok\"}";
        // -------------------------------------------------
        // create a request context
        // -------------------------------------------------
        ns_waflz::rqst_ctx* l_ctx = NULL;
        l_ctx = new ns_waflz::rqst_ctx((void*)&a_session,
                                       DEFAULT_BODY_SIZE_MAX,
                                       DEFAULT_BODY_API_SEC_SIZE_MAX,
                                       m_callbacks,
                                       false,
                                       true);
        // -------------------------------------------------
        // create event
        // -------------------------------------------------
        waflz_pb::event* l_event = NULL;
        // -------------------------------------------------
        // api_gw process
        // -------------------------------------------------
        int32_t l_s;
        l_s = m_api_gw->process(&l_event, NULL, &l_ctx);
        // -------------------------------------------------
        // if we got an error, delete and return with msg
        // -------------------------------------------------
        if (l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error processing config. reason: %s\n",
                           m_api_gw->get_err_msg());
                if (l_event)
                {
                        delete l_event;
                        l_event = NULL;
                }
                if (l_ctx)
                {
                        delete l_ctx;
                        l_ctx = NULL;
                }
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // if it processed all good - no issues
        // -------------------------------------------------
        if (!l_event)
        {
                if (l_event)
                {
                        delete l_event;
                        l_event = NULL;
                }
                if (l_ctx)
                {
                        delete l_ctx;
                        l_ctx = NULL;
                }
                return ns_is2::H_RESP_DONE;
        }
        // -------------------------------------------------
        // save event from api_gw
        // -------------------------------------------------
        l_ctx->m_event = l_event;
        // -------------------------------------------------
        // serialize event...
        // -------------------------------------------------
        l_s = ns_waflz::convert_to_json(m_resp, *l_event);
        if (l_s != JSPB_OK)
        {
                NDBG_PRINT("error performing convert_to_json.\n");
                if (l_event)
                {
                        delete l_event;
                        l_event = NULL;
                }
                if (l_ctx)
                {
                        delete l_ctx;
                        l_ctx = NULL;
                }
                return ns_is2::H_RESP_SERVER_ERROR;
        }
        // -------------------------------------------------
        // create enforcement copy...
        // -------------------------------------------------
        if(m_action)
        {
                *ao_enf = new waflz_pb::enforcement();
                (*ao_enf)->CopyFrom(*m_action);
        }
        // -------------------------------------------------
        // cleanup and returns
        // -------------------------------------------------
        if (ao_ctx) { *ao_ctx = l_ctx; }
        else if (l_ctx)
        {
                delete l_ctx;
                l_ctx = NULL;
        }
        // -------------------------------------------------
        // return good response
        // -------------------------------------------------
        return ns_is2::H_RESP_DONE;
}
}  // namespace ns_waflz_server