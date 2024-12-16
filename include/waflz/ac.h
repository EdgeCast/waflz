//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _AC_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
// uncomment to display match info...
// #define AC_DEBUG 1
#define PM_PATTERN_MAX_LEN 1024
#ifndef WAFLZ_STATUS_OK
  #define WAFLZ_STATUS_OK 0
#endif
#ifndef WAFLZ_STATUS_ERROR
  #define WAFLZ_STATUS_ERROR -1
#endif
#ifndef WAFLZ_ERR_LEN
  #define WAFLZ_ERR_LEN 4096
#endif
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#ifndef NDBG_OUTPUT
#define NDBG_OUTPUT(...) \
        do { \
                fprintf(stdout, __VA_ARGS__); \
                fflush(stdout); \
        } while(0)
#endif
#ifndef NDBG_PRINT
#define NDBG_PRINT(...) \
        do { \
                fprintf(stdout, "%s:%s.%d: ", __FILE__, __FUNCTION__, __LINE__); \
                fprintf(stdout, __VA_ARGS__);               \
                fflush(stdout); \
        } while(0)
#endif
#ifndef WAFLZ_PERROR
#define WAFLZ_PERROR(_str, ...) do { \
  snprintf(_str, WAFLZ_ERR_LEN, "%s.%s.%d: ",__FILE__,__FUNCTION__,__LINE__); \
  int _len = strlen(_str); \
  snprintf(_str + _len, WAFLZ_ERR_LEN - _len, __VA_ARGS__); \
} while(0)
#endif
//#define _AC_UTF8
namespace ns_waflz
{
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
typedef struct _node node_t;
//! ----------------------------------------------------------------------------
//! ac
//! ----------------------------------------------------------------------------
class ac
{
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
        typedef int32_t (*match_cb_t)(ac *, node_t *, void **);
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        ac(bool a_cfg_case_sensitive = false);
        ~ac();
        int32_t add(const char *a_buf, uint32_t a_len, void* a_data_pkg = nullptr);
        int32_t finalize(void);
        bool find(const char *a_buf, uint32_t a_len,
                  std::string& ao_str_match, 
                  match_cb_t a_cb,
                  void** a_data,
                  bool a_override_case_sensitive =
                      false); //!< override case sensitive

        bool find_first(const char *a_buf, uint32_t a_len,
                        std::string& ao_str_match,
                        bool a_override_case_sensitive =
                            false); //!< override case sensitive
        bool find_first_with_data(const char *a_buf, uint32_t a_len,
                                  std::string& ao_str_match, void** a_data,
                                  bool a_override_case_sensitive = false);
        bool find_with_data(const char *a_buf, uint32_t a_len,
                            std::string& ao_str_match, void** a_data,
                            bool a_override_case_sensitive = false);

        const char *get_err_msg(void) { return m_err_msg; }
#ifdef AC_DEBUG
        void display(void);
#endif
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        ac(const ac &);
        ac& operator=(const ac &);
        void connect_matches(node_t *a_node);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_finalized;
        node_t *m_root;
        bool m_cfg_case_sensitive;
#ifdef _AC_UTF8
        bool m_cfg_utf8;
#endif
        char m_err_msg[WAFLZ_ERR_LEN];
};
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                            U T I L I T I E S
//! ****************************************************************************
//! ----------------------------------------------------------------------------
int32_t create_ac_from_str(ac **ao_ac, const std::string &a_str);
int32_t create_ac_from_file(ac **ao_ac, const std::string &a_file);
}
#endif
