/* Copyright 2021 Ryan Castellucci, MIT License */

#include <Python.h>

#include <netinet/in.h>

extern "C" {
#include <libnetfilter_log/libnetfilter_log.h>
}

#include "nflogr.h"
#include "nflog.h"
#include "nflogdata.h"
#include "nflogconst.h"

PyObject *NflogError;
PyObject *NflogClosedError;

static PyObject * l_open(PyObject *self, PyObject *args) {
  int group;

  if (!PyArg_ParseTuple(args, "i:open", &group)) {
    PyErr_SetString(PyExc_TypeError, "group must be an integer");
    return NULL;
  } else if (group < 0 || group > 65535) {
    PyErr_SetString(PyExc_ValueError, "valid group range is [0,65535]");
    return NULL;
  }

  struct nflog_handle *h;
  struct nflog_g_handle *gh;

  if (!(h = nflog_open())) {
    PyErr_SetString(PyExc_PermissionError, "could not get nflog handle");
    return NULL;
  }
  if (nflog_bind_pf(h, AF_INET) < 0) {
    nflog_close(h);
    PyErr_SetString(PyExc_PermissionError, "could not bind protocol family (are you root?)");
    return NULL;
  }
  if (!(gh = nflog_bind_group(h, group))) {
    nflog_close(h);
    PyErr_SetString(PyExc_OSError, "could not get group handle");
    return NULL;
  }
  if (nflog_set_mode(gh, NFULNL_COPY_PACKET, 0xffff) < 0) {
    nflog_unbind_group(gh);
    nflog_close(h);
    PyErr_SetString(PyExc_PermissionError, "could not set packet copy mode");
    return NULL;
  }

  return new_nflogobject(h, gh, group);
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
  {"open", l_open, METH_VARARGS, PyDoc_STR(
    "open(group)\n"
    "--\n\n"
    "Open an nflog listener for the specifed group."
  )},
  {"_from_iter", l__from_iter, METH_VARARGS, PyDoc_STR(
    "_from_iter(iterator)\n"
    "--\n\n"
    "Open a mock nflog 'listener' which pulls messages from an iterator.\n"
    "INTENDED FOR DEBUGGING/TESTING ONLY!"
  )},
  {NULL, NULL} /* sentinel */
};

static struct PyModuleDef nflogr_module = {
  PyModuleDef_HEAD_INIT,
  "nflog",
  "Interface for accessing nflog.",
  0,  // m_size - this module has no state
  nflogrMethods
};

#define MOD_ADD_OBJ(M, N, O) \
  do { \
    Py_INCREF(O); \
    if (PyModule_AddObject(M, N, (PyObject *)(O)) < 0) { \
      Py_DECREF(M); \
      Py_DECREF(O); \
      return NULL; \
    } \
  } while (0);

PyMODINIT_FUNC PyInit_nflogr(void) {
  PyObject *m;

  m = PyModule_Create(&nflogr_module);

  NflogError = PyErr_NewException("nflogr.NflogError", PyExc_Exception, NULL);
  MOD_ADD_OBJ(m, "NflogError", NflogError);

  NflogClosedError = PyErr_NewException("nflogr.NflogClosedError", NflogError, NULL);
  MOD_ADD_OBJ(m, "NflogClosedError", NflogClosedError);

  if (PyType_Ready(&Nflogtype) < 0) { return NULL; }
  MOD_ADD_OBJ(m, _PyType_Name(&Nflogtype), &Nflogtype);

  if (PyType_Ready(&NflogDatatype) < 0) { return NULL; }
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
