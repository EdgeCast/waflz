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
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include "parser/parser_url_encoded.h"
#include "support/ndebug.h"
#include "core/decode.h"
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
parser_url_encoded::parser_url_encoded(rqst_ctx *a_rqst_ctx):
        parser(a_rqst_ctx)
{
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
parser_url_encoded::~parser_url_encoded()
{
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t parser_url_encoded::init()
{
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t parser_url_encoded::process_chunk(const char *a_buf, uint32_t a_len)
{
        // TODO url encoded doesn't stream...
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t parser_url_encoded::finish(void)
{
        if(!m_rqst_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        if(!m_rqst_ctx->m_body_data ||
           !m_rqst_ctx->m_body_len)
        {
                return WAFLZ_STATUS_OK;
        }
        uint32_t l_invalid_cnt = 0;
        int32_t l_s;
        uint32_t l_parse_len = m_rqst_ctx->m_body_len;
        l_s = parse_args(m_rqst_ctx->m_body_arg_list,
                         m_rqst_ctx->m_body_arg_map,
                         l_invalid_cnt,
                         m_rqst_ctx->m_body_data,
                         l_parse_len,
                         '&');
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
}
