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
#include "nflogopt.h"
#include "nflogdata.h"
#include "nflogconst.h"

PyObject *NflogError;
PyObject *NflogRetryError;
PyObject *NflogDroppedError;
PyObject *NflogClosedError;

int _nflogr_tristate(PyObject *o, int *x) {
  if (o == Py_True) {
    *x = 1;
  } else if (o == Py_False) {
    *x = 0;
  } else if (o != Py_None)  {
    PyErr_SetString(PyExc_ValueError, "value must be `True`, `False` or `None`");
    return -1;
  }

  return 0;
}

PyObject * _GIL_PyErr_Occurred() {
  PyObject *ret;
  PyGILState_STATE gil = PyGILState_Ensure();
  ret = PyErr_Occurred();
  PyGILState_Release(gil);
  return ret;
}

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
  // argument parsing
  int group;
  long long qthresh = 1, rcvbuf = 0, nlbuf = 0;
  unsigned char enobufs = NFLOGR_ENOBUFS_RAISE;
  unsigned char copymode = NFULNL_COPY_PACKET;
  double timeout = 0.00;

  const char *kwlist[] = {
    "group",
    "timeout",       "qthresh",         "rcvbuf",
    "nlbuf",         "enobufs",         "copymode",
    NULL
  };
  if (!PyArg_ParseTupleAndKeywords(
    args, kwargs, "i|$dLLLbb:open", (char **)kwlist,
    &group,   /* i */
    &timeout, /* d */ &qthresh, /* L */ &rcvbuf,  /* L */
    &nlbuf,   /* L */ &enobufs, /* b */ &copymode /* b */
  )) { return NULL; }

  // argument range validation
  if (nflo_validate_group(group) != 0) { return NULL; }
  if (nflo_validate_timeout(timeout) != 0) { return NULL; }
  if (nflo_validate_qthresh(qthresh) != 0) { return NULL; }
  if (nflo_validate_rcvbuf(rcvbuf) != 0) { return NULL; }
  if (nflo_validate_nlbuf(nlbuf) != 0) { return NULL; }
  if (nflo_validate_enobufs(enobufs) != 0) { return NULL; }
  if (nflo_validate_copymode(copymode) != 0) { return NULL; }

  struct nflog_handle *h;
  struct nflog_g_handle *gh;

  if (!(h = nflog_open())) {
    PyErr_SetString(PyExc_OSError, "could not open nflog handle");
    return NULL;
  }

  // bind protocol families
  if (_nflog_bind_pf(h, PF_INET) != 0) { goto l_open_cleanup_h; }
  if (_nflog_bind_pf(h, PF_INET6) != 0) { goto l_open_cleanup_h; }

  // bind group
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

  // set options
  if (nflo_set_timeout(h, gh, timeout) != 0) { goto l_open_cleanup_gh; }
  if (nflo_set_qthresh(h, gh, qthresh) != 0) { goto l_open_cleanup_gh; }
  if (nflo_set_rcvbuf(h, gh, rcvbuf) != 0) { goto l_open_cleanup_gh; }
  if (nflo_set_nlbuf(h, gh, nlbuf) != 0) { goto l_open_cleanup_gh; }
  if (nflo_set_enobufs(h, gh, enobufs) != 0) { goto l_open_cleanup_gh; }
  if (nflo_set_copymode(h, gh, copymode) != 0) { goto l_open_cleanup_gh; }

  // build the Nflog instance
  return new_nflogobject(h, gh, group, enobufs);

  // error handling
l_open_cleanup_gh:
  nflog_unbind_group(gh);
l_open_cleanup_h:
  nflog_close(h);
  return NULL;
}

static PyObject * l__from_iter(PyObject *self, PyObject *args) {
  PyObject *o, *iter;

  if (!PyArg_ParseTuple(args, "O:_from_iter", &o)) { return NULL; }
  if (PyIter_Check(o)) {
    iter = o;
    Py_INCREF(o);
  } else if (PySequence_Check(o)) {
    if (!(iter = PySeqIter_New(o))) {
      PyErr_SetString(PyExc_TypeError, "can't construct iterator from sequence");
      return NULL;
    }
  } else {
    PyErr_SetString(PyExc_TypeError, "iter must be a sequence or an iterator");
    return NULL;
  }

  return mock_nflogobject(iter);
}

static PyMethodDef nflogrMethods[] = {
  {"open", (PyCFunction)l_open, METH_VARARGS | METH_KEYWORDS, PyDoc_STR(
    "open($module, /, group, *, timeout=0.0, qthresh=1, rcvbuf=0, nlbuf=0,"
    " copymode=nflogr.COPY_PACKET, enobufs=nflogr.ENOBUFS_RAISE)\n"
    "--\n\n"
    "Open an nflog listener for the specifed group.\n"
    "\nArgs:\n"
    "    group (int): The number of the group to listen on.\n"
    "    timeout (float): The maximum time that nflog waits until it pushes the\n"
    "        log buffer to userspace if no new logged packets have occurred.\n\n"
    "        Specified in seconds with 0.01 granularity.\n\n"
    "        (optional, keyword only, defaults to 0)\n"
    "    qthresh (int): The maximum number of log entries in the buffer until\n"
    "        it is pushed to userspace.\n\n"
    "        (optional, keyword only, defaults to 1)\n"
    "    rcvbuf (int): The maximum size (in bytes) of the receiving socket buffer.\n"
    "        Large values may be needed to avoid dropping packets.\n\n"
    "        (optional, keyword only, defaults to 0)\n"
    "    nlbuf (int): The size (in bytes) of the buffer that is used to\n"
    "        stack log messages in nflog. If set to 0, the kernel default (one\n"
    "        memory page) will be used.\n\n"
    "        NOTE: Changing this from the default is strongly discouraged.\n\n"
    "        (optional, keyword only, defaults to 0)\n"
    "    enobufs (int): Control what happens when recv() fails with ENOBUFS due\n"
    "        to dropped packets.\n\n"
    "        nflogr.ENOBUFS_RAISE - raise an nflogr.NflogDroppedError exception\n"
    "        nflogr.ENOBUFS_HANDLE - increment the enbufs counter\n"
    "        nflogr.ENOBUFS_DISABLE - disable ENOBUFS errors entirely\n\n"
    "        (optional, keyword only, defaults to nflogr.ENOBUFS_RAISE)\n"
    "    copymode (int): The amount of data to be copied to userspace for each\n"
    "        packet.\n\n"
    "        nflogr.COPY_NONE - do not copy any data\n"
    "        nflogr.COPY_META - copy only packet metadata\n"
    "        nflogr.COPY_PACKET - copy entire packet\n\n"
    "        (optional, keyword only, defaults to nflogr.COPY_PACKET)\n"
    "\nReturns:\n"
    "    Nflog: An Nflog listener instance.\n"
    "\n"
  )},
  {"_from_iter", (PyCFunction)l__from_iter, METH_VARARGS, PyDoc_STR(
    "_from_iter($module, iterator, /)\n"
    "--\n\n"
    "INTENDED FOR DEBUGGING/TESTING ONLY!\n\n"
    "Open a mock nflog 'listener' which pulls messages from an iterator."
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

  NflogRetryError = PyErr_NewException("nflogr.NflogRetryError", NflogError, NULL);
  MOD_ADD_OBJ(m, "NflogRetryError", NflogRetryError);

  NflogDroppedError = PyErr_NewException("nflogr.NflogDroppedError", NflogError, NULL);
  MOD_ADD_OBJ(m, "NflogDroppedError", NflogDroppedError);

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
  if (PyModule_AddIntConstant(m, "ENOBUFS_RAISE", NFLOGR_ENOBUFS_RAISE) != 0) { goto nflogr_cleanup; }
  if (PyModule_AddIntConstant(m, "ENOBUFS_HANDLE", NFLOGR_ENOBUFS_HANDLE) != 0) { goto nflogr_cleanup; }
  if (PyModule_AddIntConstant(m, "ENOBUFS_DISABLE", NFLOGR_ENOBUFS_DISABLE) != 0) { goto nflogr_cleanup; }

#ifdef NFLOGR_META
  {
    int failed = 1;
    const char *meta_json = NFLOGR_META;
    PyObject *pystr, *args = NULL, *md = NULL, *json = NULL, *loads = NULL, *dict = NULL;

    do {  // load module metadata from string literal
      if (!(pystr = Py_BuildValue("s", meta_json))) { break; }
      if (!(args = PyTuple_New(1))) { Py_DECREF(pystr); break; }
      PyTuple_SET_ITEM(args, 0, pystr); // steals refrence to pystr
      if (!(md = PyModule_GetDict(m))) { break; } // returns borrows reference
      if (!(json = PyImport_ImportModule("json"))) { break; }
      if (!(loads = PyObject_GetAttrString(json, "loads"))) { break; }
      if (!(dict = PyObject_CallObject(loads, args))) { break; }
      if (!PyDict_Check(dict)) {
        PyErr_SetString(PyExc_ValueError, "loaded metadata not a dict");
        break;
      }
      if (PyDict_Merge(md, dict, 0) != 0) { break; }
    } while((failed = 0));

    Py_XDECREF(args);
    Py_XDECREF(json);
    Py_XDECREF(loads);
    Py_XDECREF(dict);

    if (failed) { goto nflogr_cleanup; }
  }
#endif

  return m;

nflogr_cleanup:
  Py_DECREF(m);
  return NULL;
}

/*  vim: set ts=2 sw=2 et ai si: */
