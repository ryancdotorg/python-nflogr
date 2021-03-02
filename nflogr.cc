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
#include "nflog.h"
#include "nflogdata.h"
#include "nflogconst.h"

PyObject *NflogError;
PyObject *NflogClosedError;

static int _nflog_bind_pf(struct nflog_handle *h, u_int16_t pf) {
  // XXX Some example code tries to do nflog_unbind_pf first, but the docs say
  // it is dangerous, prone to breaking other software, and should not be used.
  if (nflog_bind_pf(h, pf) != 0) {
    if (errno == EPERM) {
      PyErr_SetString(
        PyExc_PermissionError,
        "could not bind protocol family (are you root?)"
      );
    } else {
      PyErr_Format(
        PyExc_OSError,
        "could not bind protocol family: %s (%d)",
        strerror(errno), errno
      );
    }
    return -1;
  }
  return 0;
}

static PyObject * l_open(PyObject *self, PyObject *args, PyObject *kwargs) {
  int opt, group;

  int enobufs = 1;
  long long qthresh = 1, nlbufsiz = 0;
  unsigned char copymode = NFULNL_COPY_PACKET;
  double timeout = 0.00;

  static const char *kwlist[] = {
    "group", "copymode", "timeout", "qthresh", "nlbufsiz", "enobufs",
    NULL
  };
  if (!PyArg_ParseTupleAndKeywords(
    args, kwargs, "i|$bdLLp:open", (char **)kwlist,
    &group, &copymode, &timeout, &qthresh, &nlbufsiz, &enobufs
  )) {
    return NULL;
  }

  if (group < 0 || group > 65535) {
    PyErr_SetString(PyExc_ValueError, "group value must be in range [0,65535]");
    return NULL;
  }

  if (timeout < 0 || timeout > 42949672.951) {
    PyErr_SetString(PyExc_ValueError, "timeout value must be in range [0.00,42949672.95]");
    return NULL;
  }

  if (qthresh < 0 || qthresh > 4294967295) {
    PyErr_SetString(PyExc_ValueError, "qthresh value must be in range [0,4294967295]");
    return NULL;
  }

  if (nlbufsiz < 0 || nlbufsiz > 4294967295) {
    PyErr_SetString(PyExc_ValueError, "nlbufsiz value must be in range [0,4294967295]");
    return NULL;
  }

  struct nflog_handle *h;
  struct nflog_g_handle *gh;

  if (!(h = nflog_open())) {
    PyErr_SetString(PyExc_OSError, "could not open nflog handle");
    return NULL;
  }

  if (_nflog_bind_pf(h, PF_INET) != 0) { goto l_open_cleanup_h; }
  if (_nflog_bind_pf(h, PF_INET6) != 0) { goto l_open_cleanup_h; }

  errno = 0;
  if (!(gh = nflog_bind_group(h, group))) {
    if (errno == EPERM) {
      PyErr_Format(
        PyExc_PermissionError,
        "could not bind nflog group %i, it may be in use, see "
        "/proc/net/netfilter/nfnetlink_log",
        group
      );
    } else {
      PyErr_Format(
        PyExc_OSError,
        "could not bind nflog group %i: %s (%d)",
        group, strerror(errno), errno
      );
    }
    goto l_open_cleanup_h;
  }

  if (nflog_set_mode(gh, copymode, 0xffff) != 0) {
    PyErr_SetString(PyExc_OSError, "could not set packet copy mode");
    goto l_open_cleanup_gh;
  }

  if (nflog_set_qthresh(gh, qthresh) != 0) {
    PyErr_SetString(PyExc_OSError, "could not set qthresh");
    goto l_open_cleanup_gh;
  }

  if (nlbufsiz > 0 && nflog_set_nlbufsiz(gh, nlbufsiz) != 0) {
    PyErr_SetString(PyExc_OSError, "could not set nlbufsiz");
    goto l_open_cleanup_gh;
  }

  if (nflog_set_timeout(gh, timeout * 100.0) != 0) {
    PyErr_SetString(PyExc_OSError, "could not set timeout");
    goto l_open_cleanup_gh;
  }

  if (!enobufs) {
    opt = 1;
    if (setsockopt(nflog_fd(h), SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int)) != 0) {
      PyErr_SetString(PyExc_OSError, "could not set NO_ENOBUFS");
      goto l_open_cleanup_gh;
    }
  }

  return new_nflogobject(h, gh, group);

l_open_cleanup_gh:
  nflog_unbind_group(gh);
l_open_cleanup_h:
  nflog_close(h);
  return NULL;
}

static PyObject * l__from_iter(PyObject *self, PyObject *args) {
  PyObject *iter;

  if (!PyArg_ParseTuple(args, "O:_from_iter", &iter) || !PyIter_Check(iter)) {
    PyErr_SetString(PyExc_TypeError, "iter must be an interator");
    return NULL;
  }

  return mock_nflogobject(iter);
}

static PyMethodDef nflogrMethods[] = {
  {"open", (PyCFunction)l_open, METH_VARARGS | METH_KEYWORDS, PyDoc_STR(
    "open($module, /, group, *, copymode=nflogr.COPY_PACKET, timeout=0.0,"
    " qthresh=1, nlbufsiz=0, enobufs=True)\n"
    "--\n\n"
    "Open an nflog listener for the specifed group."
  )},
  {"_from_iter", (PyCFunction)l__from_iter, METH_VARARGS, PyDoc_STR(
    "_from_iter($module, iterator, /)\n"
    "--\n\n"
    "Open a mock nflog 'listener' which pulls messages from an iterator.\n"
    "INTENDED FOR DEBUGGING/TESTING ONLY!"
  )},
  {NULL, NULL} /* sentinel */
};

static struct PyModuleDef nflogr_module = {
  PyModuleDef_HEAD_INIT,
  "nflogr",
  "An object-oriented Python interface to read data via NFLOG",
  0,  // m_size - this module has no state
  nflogrMethods
};

#define MOD_ADD_OBJ(M, N, O) \
  Py_XINCREF(O); \
  if (PyModule_AddObject(M, N, (PyObject *)(O)) != 0) { \
    Py_XDECREF(O); \
    Py_DECREF(M); \
    return NULL; \
  }

PyMODINIT_FUNC PyInit_nflogr(void) {
  PyObject *m;

  m = PyModule_Create(&nflogr_module);

  NflogError = PyErr_NewException("nflogr.NflogError", PyExc_Exception, NULL);
  MOD_ADD_OBJ(m, "NflogError", NflogError);

  NflogClosedError = PyErr_NewException("nflogr.NflogClosedError", NflogError, NULL);
  MOD_ADD_OBJ(m, "NflogClosedError", NflogClosedError);

  if (PyType_Ready(&Nflogtype) != 0) { return NULL; }
  MOD_ADD_OBJ(m, _PyType_Name(&Nflogtype), &Nflogtype);

  if (PyType_Ready(&NflogDatatype) != 0) { return NULL; }
  MOD_ADD_OBJ(m, _PyType_Name(&NflogDatatype), &NflogDatatype);

  if (nflog_add_protos(m) != 0) { goto nflogr_cleanup; }
  if (nflog_add_hwtypes(m) != 0) { goto nflogr_cleanup; }
  if (PyModule_AddIntConstant(m, "COPY_NONE", NFULNL_COPY_NONE) != 0) { goto nflogr_cleanup; }
  if (PyModule_AddIntConstant(m, "COPY_META", NFULNL_COPY_META) != 0) { goto nflogr_cleanup; }
  if (PyModule_AddIntConstant(m, "COPY_PACKET", NFULNL_COPY_PACKET) != 0) { goto nflogr_cleanup; }

  return m;

nflogr_cleanup:
  Py_DECREF(m);
  return NULL;
}

/*  vim: set ts=2 sw=2 et ai si: */
