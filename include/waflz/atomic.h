//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _ATOMIC_H
#define _ATOMIC_H
//! ----------------------------------------------------------------------------
//! Includes
//! ----------------------------------------------------------------------------
// For fixed size types
#include <stdint.h>
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details: atomic support -in lieu of C++11 support
//! \author:  Robert Peters
//! ----------------------------------------------------------------------------
template <class T>
class atomic_gcc_builtin
{
public:
        // see http://gcc.gnu.org/onlinedocs/gcc-4.1.0/gcc/Atomic-Builtins.html
        atomic_gcc_builtin() : v(0) {}
        atomic_gcc_builtin(T i) : v(i) {}
        atomic_gcc_builtin& operator=(T rhs)
        {
                (void) __sync_lock_test_and_set (&v, rhs);
                return *this;
        }
        operator T() const
        {
                __sync_synchronize();
                return v;
        }
#pragma GCC diagnostic push
        // ignored because inc/dec prefix operators should really return const refs
#pragma GCC diagnostic ignored "-Weffc++"
        T operator ++() { return __sync_add_and_fetch(&v, T(1)); }
        T operator --() { return __sync_sub_and_fetch(&v, T(1)); }
        // back to default behaviour
#pragma GCC diagnostic pop
        T operator +=(T i) { return __sync_add_and_fetch(&v, i); }
        T operator -=(T i) { return __sync_sub_and_fetch(&v, i); }
        bool exchange(T oldval, T newval)
        {
                return __sync_bool_compare_and_swap(&v, oldval, newval);
        }
        volatile T v;
};
typedef atomic_gcc_builtin<uint64_t> uint64_atomic_t;
}
#endif

