/*
 * np_global.c — library init, cleanup, version, and strerror
 */

#include <stdlib.h>
#include <stdio.h>

#include "netpipe.h"
#include "log/np_log.h"
#include "packet/np_packet.h"   /* FIX: np_packet_pool_destroy on cleanup */

np_err_t np_init(void)
{
    np_log_set_color(true);
    np_log_set_level(NP_LOG_INFO);
    NP_LOG_DEBUG("%s", "netpipe " NETPIPE_VERSION_STR " initialised");
    return NP_OK;
}

void np_cleanup(void)
{
    /* FIX (issue: np_bufpool was never wired up): destroy the process-
     * global packet bufpool on cleanup so valgrind doesn't report it
     * as a leak.  Must be called AFTER all pipelines are freed (which
     * drops all packet references). */
    np_packet_pool_destroy();
    NP_LOG_DEBUG("%s", "netpipe cleanup");
}

void np_version(int *major, int *minor, int *patch)
{
    if (major) *major = NETPIPE_VERSION_MAJOR;
    if (minor) *minor = NETPIPE_VERSION_MINOR;
    if (patch) *patch = NETPIPE_VERSION_PATCH;
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
