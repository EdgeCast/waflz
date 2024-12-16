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
#include "waflz/ac.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <stack>
#include <errno.h>
#include <algorithm>
#ifdef _AC_UTF8
// utf8 support
#include "ac_utf8.h"
#endif
namespace ns_waflz
{
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
#ifdef _AC_UTF8
typedef long char_t;
#else
typedef char char_t;
#endif
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                               N O D E
//! ****************************************************************************
//! ----------------------------------------------------------------------------
typedef std::map <char_t, node_t *> edge_map_t;
typedef struct _node {
#ifdef AC_DEBUG
        uint32_t m_id;
#endif
        std::string m_match_str;
        void* m_data_pkg;
        bool m_last;
        struct _node *m_parent;
        struct _node *m_fail;
        edge_map_t *m_edge_map;
#ifdef AC_DEBUG
        static uint32_t s_id;
#endif
        _node():
#ifdef AC_DEBUG
                m_id(),
#endif
                m_match_str(""),
                m_data_pkg(nullptr),
                m_last(false),
                m_parent(NULL),
                m_fail(NULL),
                m_edge_map(NULL)
        {
#ifdef AC_DEBUG
                m_id = s_id++;
#endif
        }
        ~_node()
        {
                if(m_edge_map)
                {
                        for(edge_map_t::iterator i_e = m_edge_map->begin();
                            i_e != m_edge_map->end();
                            ++i_e)
                        {
                                if(i_e->second) { delete i_e->second; }
                        }
                        delete m_edge_map;
                        m_edge_map = NULL;
                }
        }
        typedef void (*node_traverse_cb_t)(struct _node *);
        void traverse_action(node_traverse_cb_t a_cb, bool a_top_down)
        {
                if(a_top_down) { a_cb(this); }
                if(m_edge_map)
                {
                        for(edge_map_t::iterator i_e = m_edge_map->begin();
                            i_e != m_edge_map->end();
                            ++i_e)
                        {
                                i_e->second->traverse_action(a_cb, a_top_down);
                        }
                }
                if(!a_top_down) { a_cb(this); }
        }
private:
        // disallow copy/assign
        _node(const _node &);
        _node& operator=(const _node &);
} node_t;
#ifdef AC_DEBUG
uint32_t node_t::s_id = 0;
#endif
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                        S T A T I C   U T I L S
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: node with given letter, or null if not found
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static node_t *edge_for_code(node_t *a_parent, char_t a_char)
{
        if(!a_parent ||
           !a_parent->m_edge_map)
        {
                return NULL;
        }
        edge_map_t::iterator i_n = a_parent->m_edge_map->find(a_char);
        if(i_n != a_parent->m_edge_map->end())
        {
                return i_n->second;
        }
        return NULL;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t match_handler_find_first(ac *a_ac, node_t* a_current_node, void** a_data)
{
        // non-zero return value will stop search
        return 1;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t get_data_from_first_node(ac *a_ac, node_t* a_current_node, void** a_data)
{
        // -------------------------------------------------
        // return data package if exists
        // -------------------------------------------------
        if (a_current_node->m_data_pkg)
        {
                *a_data = a_current_node->m_data_pkg;
        }
        // -------------------------------------------------
        // non-zero return value will stop search
        // -------------------------------------------------
        return 1;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t get_data_from_node(ac *a_ac, node_t* a_current_node, void** a_data)
{
        // -------------------------------------------------
        // return data package if exists
        // -------------------------------------------------
        if (a_current_node->m_data_pkg)
        {
                *a_data = a_current_node->m_data_pkg;
        }
        // -------------------------------------------------
        // non-zero return value will stop search
        // -------------------------------------------------
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: displays all nodes recursively
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
#ifdef AC_DEBUG
static void node_display(node_t *a_node)
{
        if(!a_node)
        {
                // TODO log error???
                return;
        }
        NDBG_OUTPUT("node(%6d)|====FAIL====> ", a_node->m_id);
        if(a_node->m_fail)
        {
                NDBG_OUTPUT("node(%6d)", a_node->m_fail->m_id);
        }
        else
        {
                NDBG_OUTPUT("node(%6s)", "__na__");
        }
        NDBG_OUTPUT(" ::LAST[%d]::\n", a_node->m_last);
        if(a_node->m_edge_map)
        {
        for(edge_map_t::iterator i_e = a_node->m_edge_map->begin();
            i_e != a_node->m_edge_map->end();
            ++i_e)
        {
                NDBG_OUTPUT("            |----(");
                if(isgraph(i_e->first))
                {
                        NDBG_OUTPUT("%c)---", (char)i_e->first);
                }
                else
                {
                        NDBG_OUTPUT("0x%x)", (char)i_e->first);
                }
                NDBG_OUTPUT("--> node(%6d)\n", i_e->second->m_id);
        }
        }
#ifdef PM_DEBUG
        if(a_node->m_matched_size)
        {
                NDBG_OUTPUT("accept: {");
                for (uint32_t i_n = 0; i_n < a_node->m_matched_size; ++i_n)
                {
                        pm::pattern_t *l_p = &(a_node->m_matched[i_n]);
                        if(!l_p)
                        {
                                continue;
                        }
                        if(i_n)
                        {
                                NDBG_OUTPUT(", ");
                        }
                        switch(l_p->m_id.m_type)
                        {
                        case pm::PATTERN_ID_TYPE_DEFAULT:
                        case pm::PATTERN_ID_TYPE_NUMBER:
                        {
                                NDBG_OUTPUT("%ld", l_p->m_id.m_u.m_number);
                                break;
                        }
                        case pm::PATTERN_ID_TYPE_STRING:
                        {
                                NDBG_OUTPUT("%s", l_p->m_id.m_u.m_stringy);
                                break;
                        }
                        }
                        NDBG_OUTPUT(": %.*s", (int)l_p->m_text.m_len, l_p->m_text.m_str);
                }
                NDBG_OUTPUT("}\n");
        }
#endif
        NDBG_OUTPUT("\n");
}
#endif
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                        U T F 8   S U P P O R T
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: length of utf-8 sequence based on its first byte
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
#ifdef _AC_UTF8
static int utf8_seq_len(const char *first_byte)
{
    return utf8_seq_lengths[(unsigned int)(unsigned char)first_byte[0]];
}
#endif
//! ----------------------------------------------------------------------------
//! \details: length of utf8-encoded text
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
#ifdef _AC_UTF8
static size_t utf8_strlen(const char *str)
{
        int len = 0;
        const char *c = str;
        while (*c != 0)
        {
                c += utf8_seq_len(c);
                ++len;
        }
        return len;
}
#endif
//! ----------------------------------------------------------------------------
//! \details: lowercase for given unicode character in utf8_lcase_map table.
//!           if no-exist, assumes no lowercase variant and returns code itself.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
#ifdef _AC_UTF8
static long utf8_lcase(acmp_utf8_char_t ucs_code)
{
        long mid;
        long left = 1;
        long right = UTF8_LCASEMAP_LEN * 2 + 1;
        while (left <= right)
        {
                mid = (left + right) >> 1;
                mid -= (mid % 2);
                ++mid;
                if (ucs_code > utf8_lcase_map[mid])
                {
                        left = mid + 2;
                }
                else if (ucs_code < utf8_lcase_map[mid])
                {
                        right = mid - 2;
                }
                else if (ucs_code == utf8_lcase_map[mid])
                {
                        return utf8_lcase_map[mid - 1];
                }
        }
        return ucs_code;
}
#endif
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                                  A C
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
ac::ac(bool a_cfg_case_sensitive):
        m_finalized(false),
        m_root(NULL),
        m_cfg_case_sensitive(a_cfg_case_sensitive)
{
        m_root = new node_t();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
ac::~ac()
{
        if(m_root)
        {
                delete m_root;
                m_root = NULL;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t ac::add(const char *a_buf, uint32_t a_len, void* a_data_pkg)
{
        if(m_finalized)
        {
                // TODO log error reason???
                WAFLZ_PERROR(m_err_msg, "Failed to add: already finalized");
                return WAFLZ_STATUS_ERROR;
        }
        if(!a_buf)
        {
                // TODO log error reason???
                WAFLZ_PERROR(m_err_msg, "Failed to add no input");
                return WAFLZ_STATUS_ERROR;
        }
        uint32_t l_len = a_len;
        if(!l_len)
        {
#ifdef _AC_UTF8
                if(m_cfg_utf8)
                {
                        utf8_strlen(a_buf);
                }
                else
                {
#endif
                // TODO risque???
                l_len = strlen(a_buf);
#ifdef _AC_UTF8
                }
#endif
        }
        char_t *l_buf = NULL;
        l_buf = (char_t *)malloc(sizeof(char_t)*l_len);
        // -------------------------------------------------
        // copy in
        // -------------------------------------------------
#ifdef _AC_UTF8
        if(m_cfg_utf8)
        {
                const char *l_b = a_buf;
                for(uint32_t i_c = 0; i_c < l_len; ++i_c)
                {
                        l_buf[i_c] = utf8_decodechar(l_b);
                        l_b += utf8_seq_len(l_b);
                }
        }
        else
        {
#endif
        if(sizeof(char_t) == sizeof(char)) { memcpy(l_buf, a_buf, l_len); }
        else { for(uint32_t i_c = 0; i_c < l_len; ++i_c) { l_buf[i_c] = a_buf[i_c]; } }
#ifdef _AC_UTF8
        }
#endif
        node_t *l_parent = m_root;
        // -------------------------------------------------
        // loop over chars in str
        // -------------------------------------------------
        for(uint32_t i_c = 0; i_c < l_len; ++i_c)
        {
                // -----------------------------------------
                // get char in str
                // -----------------------------------------
                char_t l_c = l_buf[i_c];
                // -----------------------------------------
                // convert to lower case???
                // -----------------------------------------
                if(!m_cfg_case_sensitive)
                {
#ifdef _AC_UTF8
                        if(m_cfg_utf8)
                        {
                                l_c = utf8_lcase(l_c);
                        }
                        else
                        {
#endif
                        l_c = tolower(l_c);
#ifdef _AC_UTF8
                        }
#endif
                }
                node_t *l_child = edge_for_code(l_parent, l_c);
                if(l_child == NULL)
                {
                        //printf("%s.%s.%d: char: %c\n",__FILE__,__FUNCTION__,__LINE__,(char)l_c);
                        l_child = new node_t();
                }
                // -----------------------------------------
                // last char in str???
                // -----------------------------------------
                if(i_c == (l_len - 1))
                {
                        if(!l_child->m_last)
                        {
                                l_child->m_last = true;
                        }
                        l_child->m_match_str = std::string(l_buf,l_len);
                        l_child->m_data_pkg = a_data_pkg;

                }
                // -----------------------------------------
                // add node to parent
                // -----------------------------------------
                l_child->m_parent = l_parent;
                if(!l_parent->m_edge_map)
                {
                        l_parent->m_edge_map = new edge_map_t();
                }
                (*l_parent->m_edge_map)[l_c] = l_child;
                l_parent = l_child;
        }
        if(l_buf) { free(l_buf); l_buf = NULL; }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t ac::finalize(void)
{
        if(m_finalized)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // *************************************************
        //            connect fail branches
        // *************************************************
        // -------------------------------------------------
        m_root->m_fail = NULL;
        // -------------------------------------------------
        // first level children will fail back to root node
        // -------------------------------------------------
        typedef std::pair <char, node_t *>edge_t;
        typedef std::stack <edge_t> node_stack_t;
        node_stack_t *l_node_stack_1 = new node_stack_t();
        if(m_root->m_edge_map)
        {
                for(edge_map_t::iterator i_e = m_root->m_edge_map->begin();
                    i_e != m_root->m_edge_map->end();
                    ++i_e)
                {
                        i_e->second->m_fail = m_root;
                        l_node_stack_1->push(std::make_pair(i_e->first, i_e->second));
                }
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        node_stack_t *l_node_stack_2 = new node_stack_t();
        while(true)
        {
                // foreach child...
                while(!l_node_stack_1->empty())
                {
                        edge_t l_e = l_node_stack_1->top();
                        node_t *l_n = l_e.second;
                        char_t l_c = l_e.first;
                        l_node_stack_1->pop();
                        // ---------------------------------
                        // fail node root for leaves
                        // ---------------------------------
                        if(l_n->m_parent != m_root)
                        {
                                l_n->m_fail = edge_for_code(l_n->m_parent->m_fail, l_c);
                                if(!l_n->m_fail)
                                {
                                        l_n->m_fail = m_root;
                                }
                        }
                        // ---------------------------------
                        // 
                        // ---------------------------------
                        if(l_n->m_edge_map)
                        {
                                for(edge_map_t::iterator i_e = l_n->m_edge_map->begin();
                                    i_e != l_n->m_edge_map->end();
                                    ++i_e)
                                {
                                        l_node_stack_2->push(std::make_pair(i_e->first, i_e->second));
                                }
                        }
                }
                if(l_node_stack_2->empty())
                {
                        break;
                }
                // -----------------------------------------
                // swap ???
                // -----------------------------------------
                node_stack_t *l_tmp;
                l_tmp = l_node_stack_1;
                l_node_stack_1 = l_node_stack_2;
                l_node_stack_2 = l_tmp;
        }
        if(l_node_stack_1) { delete l_node_stack_1; l_node_stack_1 = NULL; }
        if(l_node_stack_2) { delete l_node_stack_2; l_node_stack_2 = NULL; }
        // -------------------------------------------------
        // empty???
        // -------------------------------------------------
        if(m_root->m_edge_map == NULL)
        {
                m_finalized = true;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // connect matches
        // -------------------------------------------------
        //connect_matches(m_root);
        m_finalized = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bool ac::find(const char *a_buf, uint32_t a_len, std::string& ao_str_match, match_cb_t a_cb, void** a_data,
              bool a_override_case_sensitive)
{
        if(!m_finalized)
        {
                // TODO log error reason???
                return false;
        }
        if(!a_len || !a_buf)
        {
                // TODO log error reason???
                return false;
        }
        node_t *l_n = m_root;
        const char *l_end = a_buf + a_len;
        const char *l_buf = a_buf;
        bool l_found = false;
        while(l_buf < l_end)
        {
                char_t l_c = (unsigned char)*(l_buf);
                // -----------------------------------------
                // force char to lower if NOT case sensitive
                // -----------------------------------------
                if(!m_cfg_case_sensitive && !a_override_case_sensitive)
                {
#ifdef _AC_UTF8
                        if(m_cfg_utf8)
                        {
                                l_c = utf8_lcase(l_c);
                        }
                        else
                        {
#endif
                                l_c = tolower(l_c);
#ifdef _AC_UTF8
                        }
#endif
                }
                // -----------------------------------------
                // edge find
                // -----------------------------------------
                node_t *l_next = NULL;
                if(l_n->m_edge_map)
                {
                        edge_map_t::iterator i_n = l_n->m_edge_map->find(l_c);
                        if((i_n != l_n->m_edge_map->end()))
                        {
                                l_next = i_n->second;
                        }
                }
                if(l_next)
                {
                        l_n = l_next;
                        if(l_n->m_last)
                        {
                                ao_str_match = l_n->m_match_str;
                                if(a_cb)
                                {
                                        int32_t l_s;
                                        l_s = a_cb(this, l_n, a_data);
                                        if(l_s)
                                        {
                                                return true;
                                        }
                                }
                                l_found = true;
                        }
                }
                else if(l_n->m_fail)
                {
                        l_n = l_n->m_fail;
                        continue;
                }
                ++l_buf;
        }
        return l_found;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bool ac::find_first(const char *a_buf, uint32_t a_len, std::string& ao_str_match, bool a_override_case_sensitive)
{
        return find(a_buf, a_len, ao_str_match, match_handler_find_first, NULL, a_override_case_sensitive);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bool ac::find_first_with_data(const char *a_buf, uint32_t a_len, std::string& ao_str_match, void** a_data, bool a_override_case_sensitive)
{
        return find(a_buf, a_len, ao_str_match, get_data_from_first_node, a_data, a_override_case_sensitive);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bool ac::find_with_data(const char *a_buf, uint32_t a_len, std::string& ao_str_match, void** a_data, bool a_override_case_sensitive)
{
        return find(a_buf, a_len, ao_str_match, get_data_from_node, a_data, a_override_case_sensitive);
}

//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
#ifdef AC_DEBUG
void ac::display(void)
{
        if(!m_root)
        {
                // TODO log error???
                return;
        }
        m_root->traverse_action(node_display, true);
}
#endif
//! ----------------------------------------------------------------------------
//! \details: connects each node with its first fail node that's end of phrase.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
/*
void ac::connect_matches(node_t *a_node)
{
        if(!a_node ||
           !a_node->m_edge_map)
        {
                return;
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        for(edge_map_t::iterator i_e = a_node->m_edge_map->begin();
            i_e != a_node->m_edge_map->end();
            ++i_e)
        {
                node_t *i_n = i_e->second;
                if(!i_n ||
                   !i_n->m_fail)
                {
                        continue;
                }
                node_t *l_om = i_n->m_fail;
                while(l_om != m_root)
                {
                        if(l_om->m_last)
                        {
                                break;
                        }
                        l_om = l_om->m_fail;
                }
        }
        // -------------------------------------------------
        // recurse thru children of this node w/child nodes
        // -------------------------------------------------
        for(edge_map_t::iterator i_e = a_node->m_edge_map->begin();
            i_e != a_node->m_edge_map->end();
            ++i_e)
        {
                connect_matches(i_e->second);
        }
}
*/
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                            U T I L I T I E S
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define MAX_READLINE_SIZE 4096
#define PM_STR_SEPARATOR ' '
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t create_ac_from_str(ac **ao_ac, const std::string &a_str)
{
        //NDBG_PRINT("%sAC_FROM_STR%s: %s\n",ANSI_COLOR_BG_WHITE, ANSI_COLOR_OFF, a_str.c_str());
        if(!ao_ac)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_ac = NULL;
        // -------------------------------------------------
        // split by PM string sep...
        // -------------------------------------------------
        ac *l_ac = new ac();
        size_t l_start = 0;
        size_t l_end = 0;
        while((l_end = a_str.find(PM_STR_SEPARATOR, l_start)) != std::string::npos)
        {
                if(l_end != l_start)
                {
                        std::string i_str = a_str.substr(l_start, l_end - l_start);
                        i_str.erase( std::remove_if( i_str.begin(), i_str.end(), ::isspace ), i_str.end() );
                        //NDBG_PRINT("ADD: '%s'\n", i_str.c_str());
                        l_ac->add(i_str.c_str(), i_str.length());
                }
                l_start = l_end + 1;
        }
        if(l_end != l_start)
        {
                std::string i_str = a_str.substr(l_start);
                i_str.erase( std::remove_if( i_str.begin(), i_str.end(), ::isspace ), i_str.end() );
                //NDBG_PRINT("ADD: '%s'\n", i_str.c_str());
                l_ac->add(i_str.c_str(), i_str.length());
        }
        int32_t l_s;
        l_s = l_ac->finalize();
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_ac) { delete l_ac; l_ac = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        *ao_ac = l_ac;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t create_ac_from_file(ac **ao_ac, const std::string &a_file)
{
        FILE * l_fp;
        l_fp = fopen(a_file.c_str(),"r");
        if (NULL == l_fp)
        {
                //NDBG_PRINT("error opening file: %s.  Reason: %s\n", a_file.c_str(), strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        ac *l_ac = new ac();
        char l_rline[MAX_READLINE_SIZE];
        while(fgets(l_rline, sizeof(l_rline), l_fp))
        {
                size_t l_rline_len = strnlen(l_rline, MAX_READLINE_SIZE);
                if(!l_rline_len)
                {
                        continue;
                }
                else if(l_rline_len == MAX_READLINE_SIZE)
                {
                        // line was truncated
                        //TRC_OUTPUT("Error: lines must be shorter than %d chars\n", MAX_READLINE_SIZE);
                        if(l_ac) { delete l_ac; l_ac = NULL;}
                        if(l_fp) { fclose(l_fp); l_fp = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // TODO -zero copy version???
                // -----------------------------------------
                // nuke endline
                l_rline[l_rline_len - 1] = '\0';
                std::string l_line(l_rline);
                l_line.erase( std::remove_if( l_line.begin(), l_line.end(), ::isspace ), l_line.end() );
                if(l_line.empty())
                {
                        continue;
                }
                l_ac->add(l_line.c_str(), l_line.length());
                //NDBG_PRINT("READLINE: %s\n", l_line.c_str());
        }
        int32_t l_s;
        l_s = l_ac->finalize();
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_ac) { delete l_ac; l_ac = NULL;}
                if(l_fp) { fclose(l_fp); l_fp = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        *ao_ac = l_ac;
        // -------------------------------------------------
        // Close file...
        // -------------------------------------------------
        if(l_fp) { fclose(l_fp); l_fp = NULL;}
        return WAFLZ_STATUS_OK;
}
}
