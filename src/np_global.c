/*
 * np_global.c — library init, cleanup, and strerror
 */

#include <stdlib.h>
#include <stdio.h>

#include "netpipe.h"
#include "log/np_log.h"

np_err_t np_init(void)
{
    np_log_set_color(true);
    np_log_set_level(NP_LOG_INFO);
    NP_LOG_DEBUG("netpipe %s initialised", NETPIPE_VERSION_STR);
    return NP_OK;
}

void np_cleanup(void)
{
    NP_LOG_DEBUG("netpipe cleanup");
}

const char *np_strerror(np_err_t err)
{
    switch (err) {
    case NP_OK:           return "success";
    case NP_ERR_GENERIC:  return "generic error";
    case NP_ERR_NOMEM:    return "out of memory";
    case NP_ERR_IO:       return "I/O error";
    case NP_ERR_PROTO:    return "protocol error";
    case NP_ERR_FILTER:   return "filter error";
    case NP_ERR_TIMEOUT:  return "timeout";
    case NP_ERR_NODEV:    return "no such device";
    case NP_ERR_PERM:     return "permission denied";
    case NP_ERR_EOF:      return "end of stream";
    default:              return "unknown error";
    }
}
