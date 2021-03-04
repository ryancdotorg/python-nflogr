/* Copyright 2021 Ryan Castellucci, MIT License */

#include <Python.h>

#include <netinet/in.h>
#include <errno.h>

extern "C" {
#include <libnetfilter_log/libnetfilter_log.h>
#include <libnfnetlink/libnfnetlink.h>
#include <linux/netlink.h>
}

#include "nflogr.h"
#include "nflogopt.h"

/* I probably should not be allowed anywhere near a c preprocessor... */

#define NFLO_SETTER_PRE(T, N, F, MIN, MAX) \
int nflo_validate_ ## N(T __val) { \
  T __min = (MIN), __max = (MAX); \
  if (__val < __min || __val > __max) { \
    char buf[1024]; \
    if (strchr(F, '%')) { \
_Pragma("GCC diagnostic push"); \
_Pragma("GCC diagnostic ignored \"-Wformat-extra-args\""); \
      snprintf(buf, sizeof(buf), "%s must be in range [" F "," F "]", #N, __min, __max); \
_Pragma("GCC diagnostic pop"); \
    } else { \
      snprintf(buf, sizeof(buf), "%s must be %s", #N, F); \
    } \
    PyErr_SetString(PyExc_ValueError, buf); \
    return -1; \
  } \
  return 0; \
}; \
\
int nflo_set_ ## N(struct nflog_handle *h, struct nflog_g_handle *gh, T N) { \
  if (nflo_validate_ ## N(N) != 0) { return -1; }

#define NFLO_SETTER_END \
  return 0; \
}

NFLO_SETTER_PRE(int, group, "%d", 0, 65535)
  PyErr_SetString(PyExc_RuntimeError, "don't use this function");
  return -1;
}

NFLO_SETTER_PRE(double, timeout, "%.2f", 0, 42949672.951)
  if (nflog_set_timeout(gh, timeout * 100.0) != 0) {
    PyErr_SetString(PyExc_OSError, "could not set timeout");
    return -1;
  }
NFLO_SETTER_END

NFLO_SETTER_PRE(long long, qthresh, "%lld", 0, 4294967295)
  if (nflog_set_qthresh(gh, qthresh) != 0) {
    PyErr_SetString(PyExc_OSError, "could not set qthresh");
    return -1;
  }
NFLO_SETTER_END

NFLO_SETTER_PRE(int, rcvbuf, "%d", 0, 1073741823)
  int opt, fd = nflog_fd(h);
  socklen_t len;
  if (rcvbuf > 0) {
    opt = rcvbuf;
    // SO_RCVBUFFORCE requires root/cap_net_admin, which we should have...
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &opt, sizeof(int)) != 0) {
      nfldbg("setsockopt SO_RCVBUFFORCE failed %s (%d)\n", strerror(errno), errno);
      if (errno == EPERM) {
        len = sizeof(int);
        // the kernel will double the value supplied, and we need to confirm
        // with a getsockopt call since this setsockopt won't ever error
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(int)) != 0) {
          PyErr_SetString(PyExc_OSError, "this should never happen (SO_RCVBUF)");
          return -1;
        } else if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, &len) != 0) {
          PyErr_SetString(PyExc_OSError, "could not get rcvbuf");
          return -1;
        } else if (opt < rcvbuf * 2) {
          PyErr_Format(PyExc_PermissionError,
            "could not set rcvbuf (ENOPERM, %d != %d)",
            opt, rcvbuf * 2
          );
          return -1;
        }
      } else {
        PyErr_Format(PyExc_OSError, "could not set rcvbuf (SO_RCVBUFFORCE)");
        return -1;
      }
    }
  }
NFLO_SETTER_END

NFLO_SETTER_PRE(long long, nlbuf, "%lld", 0, 4294967295)
  if (nlbuf > 0 && nflog_set_nlbufsiz(gh, nlbuf) != 0) {
    PyErr_SetString(PyExc_OSError, "could not set nlbuf");
    return -1;
  }
NFLO_SETTER_END

NFLO_SETTER_PRE(unsigned char, enobufs, "ENOBUFS_RAISE, ENOBUFS_HANDLE, or ENOBUFS_DISABLE", NFLOGR_ENOBUFS_RAISE, NFLOGR_ENOBUFS_DISABLE)
  int fd = nflog_fd(h), opt = enobufs == NFLOGR_ENOBUFS_DISABLE ? 1 : 0;
  if (setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int)) != 0) {
    PyErr_SetString(PyExc_OSError, "could not set NO_ENOBUFS");
    return -1;
  }
NFLO_SETTER_END

NFLO_SETTER_PRE(unsigned char, copymode, "COPY_NONE, COPY_META, or COPY_PACKET", NFULNL_COPY_NONE, NFULNL_COPY_PACKET)
  if (nflog_set_mode(gh, copymode, 0xffff) != 0) {
    PyErr_SetString(PyExc_OSError, "could not set packet copy mode");
    return -1;
  }
NFLO_SETTER_END

/* vim: set ts=2 sw=2 et ai si: */
