/* Copyright 2021 Ryan Castellucci, MIT License */

#include <Python.h>
#include <pytime.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/if.h>

extern "C" {
#include <libnetfilter_log/libnetfilter_log.h>
}

#include "nflogr.h"
#include "nflogdata.h"

// internal nflogdataobject
typedef struct {
  PyObject_HEAD
  uint16_t proto;
  uint16_t hwtype;
  uint32_t nfmark;

  double   timestamp;

  uint32_t indev;
  uint32_t physindev;
  uint32_t outdev;
  uint32_t physoutdev;

  PyObject *uid;
  PyObject *gid;

  PyObject *hwhdr;
  PyObject *payload;

  PyObject *prefix;

  PyObject *raw;
} nflogdataobject;

typedef struct {
  PyObject_HEAD
  nflogdataobject *nd;
  int        n;
} nflogdataiter;

static PyObject * _NfadAsTuple(struct nflog_data *nfad);
static struct nflog_data * _TupleAsNfad(PyObject *tup);

static void ndi_dealloc(register nflogdataiter *ndi) {
  Py_DECREF(ndi->nd);
  PyObject_Del(ndi);
}

static void nflogdata_dealloc(register nflogdataobject *nd) {
  Py_DECREF(nd->uid);
  Py_DECREF(nd->gid);
  Py_DECREF(nd->hwhdr);
  Py_DECREF(nd->payload);
  Py_DECREF(nd->prefix);
  Py_DECREF(nd->raw);
  PyObject_Del(nd);
}

PyObject * new_nflogdataobject(struct nflog_data *nfad, int raw) {
  nflogdataobject *nd = PyObject_New(nflogdataobject, &NflogDatatype);
  if (nd == NULL) { return NULL; }

  nd->hwtype = nflog_get_hwtype(nfad);
  nd->nfmark = nflog_get_nfmark(nfad);

  // proto
  struct nfulnl_msg_packet_hdr *ph = nflog_get_msg_packet_hdr(nfad);
  nd->proto = ph ? ntohs(ph->hw_protocol) : 0;

  // timestamp
  _PyTime_t tp;
  struct timeval tv;
  if (nflog_get_timestamp(nfad, &tv) != 0) {
    PyErr_SetString(NflogError, "no timestamp data");
    PyObject_Del(nd);
    return NULL;
  }
  if (_PyTime_FromTimeval(&tp, &tv) != 0) {
    PyErr_SetString(NflogError, "invalid timeval");
    PyObject_Del(nd);
    return NULL;
  }
  nd->timestamp = _PyTime_AsSecondsDouble(tp);

  // devs
  nd->indev = nflog_get_indev(nfad);
  nd->physindev = nflog_get_physindev(nfad);
  nd->outdev = nflog_get_outdev(nfad);
  nd->physoutdev = nflog_get_physoutdev(nfad);

  // uid/gid
  uint32_t id;
  if (nflog_get_uid(nfad, &id) == 0) {
    nd->uid = Py_BuildValue("k", id);
  } else {
    nd->uid = Py_None;
    Py_INCREF(Py_None);
  }
  if (nflog_get_gid(nfad, &id) == 0) {
    nd->gid = Py_BuildValue("k", id);
  } else {
    nd->gid = Py_None;
    Py_INCREF(Py_None);
  }

  // hwhdr
  char *hwhdr = nflog_get_msg_packet_hwhdr(nfad);
  size_t hwhdr_sz = nflog_get_msg_packet_hwhdrlen(nfad);
  nd->hwhdr = Py_BuildValue("y#", hwhdr, hwhdr_sz);

  // payload
  char *payload;
  int payload_sz = nflog_get_payload(nfad, &payload);
  nd->payload = Py_BuildValue("y#", payload, payload_sz);

  char *prefix = nflog_get_prefix(nfad);
  nd->prefix = Py_BuildValue("s", prefix);

  if (raw) {
    nd->raw = _NfadAsTuple(nfad);
  } else {
    nd->raw = Py_None;
    Py_INCREF(Py_None);
  }

  return (PyObject *)nd;
}

static PyObject * _devname(uint32_t idx) {
  char buf[20] = {0};
  if (idx) {
    if_indextoname(idx, buf);
    return Py_BuildValue("s", buf);
  } else {
    Py_RETURN_NONE;
  }
}

static PyObject * nd_get_proto(register nflogdataobject *nd, void *) {
  return Py_BuildValue("H", nd->proto);
}

static PyObject * nd_get_hwtype(register nflogdataobject *nd, void *) {
  return Py_BuildValue("H", nd->hwtype);
}

static PyObject * nd_get_nfmark(register nflogdataobject *nd, void *) {
  return Py_BuildValue("k", nd->nfmark);
}

static PyObject * nd_get_timestamp(register nflogdataobject *nd, void *) {
  return PyFloat_FromDouble(nd->timestamp);
}

static PyObject * nd_get_indev(register nflogdataobject *nd, void *) {
  return _devname(nd->indev);
}

static PyObject * nd_get_physindev(register nflogdataobject *nd, void *) {
  return _devname(nd->physindev);
}

static PyObject * nd_get_outdev(register nflogdataobject *nd, void *) {
  return _devname(nd->outdev);
}

static PyObject * nd_get_physoutdev(register nflogdataobject *nd, void *) {
  return _devname(nd->physoutdev);
}

static PyObject * nd_get_uid(register nflogdataobject *nd, void *) {
  Py_INCREF(nd->uid);
  return nd->uid;
}

static PyObject * nd_get_gid(register nflogdataobject *nd, void *) {
  Py_INCREF(nd->gid);
  return nd->gid;
}

static PyObject * nd_get_hwhdr(register nflogdataobject *nd, void *) {
  Py_INCREF(nd->hwhdr);
  return nd->hwhdr;
}

static PyObject * nd_get_payload(register nflogdataobject *nd, void *) {
  Py_INCREF(nd->payload);
  return nd->payload;
}

static PyObject * nd_get_prefix(register nflogdataobject *nd, void *) {
  Py_INCREF(nd->prefix);
  return nd->prefix;
}

static PyObject * nd_get__raw(register nflogdataobject *nd, void *) {
  Py_INCREF(nd->raw);
  return nd->raw;
}

static PyGetSetDef nd_getset[] = {
  {"proto",      (getter)nd_get_proto,      NULL, NULL, NULL},
  {"hwtype",     (getter)nd_get_hwtype,     NULL, NULL, NULL},
  {"nfmark",     (getter)nd_get_nfmark,     NULL, NULL, NULL},
  {"timestamp",  (getter)nd_get_timestamp,  NULL, NULL, NULL},
  {"indev",      (getter)nd_get_indev,      NULL, NULL, NULL},
  {"physindev",  (getter)nd_get_physindev,  NULL, NULL, NULL},
  {"outdev",     (getter)nd_get_outdev,     NULL, NULL, NULL},
  {"physoutdev", (getter)nd_get_physoutdev, NULL, NULL, NULL},
  {"uid",        (getter)nd_get_uid,        NULL, NULL, NULL},
  {"gid",        (getter)nd_get_gid,        NULL, NULL, NULL},
  {"hwhdr",      (getter)nd_get_hwhdr,      NULL, NULL, NULL},
  {"payload",    (getter)nd_get_payload,    NULL, NULL, NULL},
  {"prefix",     (getter)nd_get_prefix,     NULL, NULL, NULL},
  {"_raw",       (getter)nd_get__raw,       NULL, NULL, NULL},
  {NULL}
};

static PyMethodDef nd_methods[] = {
//  {"__getstate__", (PyCFunction) nd__enter__, METH_NOARGS, NULL},
//  {"__setstate__", (PyCFunction) nd__enter__, METH_NOARGS, NULL},
  {NULL, NULL}
};

struct nflog_data {
  struct nfattr **nfa;
};

static PyObject * _NfadAsTuple(struct nflog_data *nfad) {
  PyObject *tup = PyTuple_New(NFULA_MAX);
  struct nfattr *nfa;
  int i;

  for (i = 0; i < NFULA_MAX; ++i) {
    nfa = nfad->nfa[i];
    if (nfa) {
      PyTuple_SetItem(tup, i, Py_BuildValue("y#", (((char *)(nfa)) + NFA_LENGTH(0)), nfa->nfa_len));
    } else {
      Py_INCREF(Py_None);
      PyTuple_SetItem(tup, i, Py_None);
    }
  }

  return tup;
}

static struct nflog_data * _TupleAsNfad(PyObject *tup) {
  int i, alignto = 4;
  PyObject *bytes;
  Py_ssize_t sz = sizeof(void *) * __NFULA_MAX, off = sz;
  Py_ssize_t len, n = PyTuple_Size(tup);
  char *buf;

  // first loop - calculate size required
  for (i = 0; i < NFULA_MAX && i < n; ++i) {
    bytes = PyTuple_GetItem(tup, i);
    PyBytes_Check(bytes);
    if (bytes == Py_None) {
      continue;
    } else if (!PyBytes_Check(bytes)) {
      PyErr_SetString(PyExc_TypeError, "tuple memeber not bytes or None");
      return NULL;
    }
    if ((len = PyBytes_Size(bytes)) > 65535) {
      PyErr_SetString(PyExc_ValueError, "tuple members must be at most 65535 bytes");
      return NULL;
    }
    sz += (4 + PyBytes_Size(bytes) + alignto - 1) & ~(alignto - 1);
  }

  char *nfad = (char *)malloc(sz);
  if (!nfad) {
    PyErr_NoMemory();
    return NULL;
  }
  // set nfa pointer
  ((char **)nfad)[0] = nfad + sizeof(void *);

  i = 0;  // second loop - copy data
  while (i < NFULA_MAX) {
    // if the tuple is short, the remaining pointers still need to be null
    bytes = i < n ? PyTuple_GetItem(tup, i) : Py_None; ++i;
    if (bytes == Py_None) {
      ((char **)nfad)[i] = NULL;
      continue;
    }

    // this says `String` but per the docs null bytes are fine as of Python 3.5
    if (PyBytes_AsStringAndSize(bytes, &buf, &len) != 0) { return NULL; }
    ((char **)nfad)[i] = nfad + off;
    memcpy(nfad + off + 0, &len,   2);
    memcpy(nfad + off + 2,   &i,   2);
    memcpy(nfad + off + 4,  buf, len);
    off += (4 + len + alignto - 1) & ~(alignto - 1);
  }

  return (struct nflog_data *)nfad;
}

PyObject * nd__iter__(register nflogdataobject *nd) {
  if (PyType_Ready(&NflogDataItertype) < 0) { return NULL; }

  nflogdataiter *iter = PyObject_New(nflogdataiter, &NflogDataItertype);
  if (iter == NULL) { return NULL; }
  iter->nd = nd;
  iter->n = 0;
  Py_INCREF(nd);
  return (PyObject *)iter;
}

PyObject * nd__str__(register nflogdataobject *nd) {
  // basically equivalent to dict(nd)
  PyObject *dict = PyDict_New();
  PyDict_MergeFromSeq2(dict, (PyObject *)nd, 0);
  // format the dict with the name of the type
  PyObject *repr = PyUnicode_FromFormat("<%s %S>", _PyType_Name(Py_TYPE(nd)), dict);
  Py_DECREF(dict);
  return repr;
}

PyObject * nd__repr__(register nflogdataobject *nd) {
  if (nd->raw == Py_None) { return nd__str__(nd); }
  return PyUnicode_FromFormat("%s(%R)", _PyType_Name(Py_TYPE(nd)), nd->raw);
}

PyObject * nd__new__(PyTypeObject *subtype, PyObject *args, PyObject *) {
  PyObject *tup;
  if (!PyArg_ParseTuple(args, "O:__new__", &tup) || !PyTuple_Check(tup)) {
    PyErr_SetString(PyExc_TypeError, "argument must be a tuple");
    return NULL;
  }

  struct nflog_data *nfad = _TupleAsNfad(tup);
  if (!nfad) { return NULL; }
  return new_nflogdataobject(nfad, 1);
}

PyObject * ndi__iter__(register nflogdataiter *ndi) {
  Py_INCREF(ndi);
  return (PyObject *)ndi;
}

PyObject * ndi__next__(register nflogdataiter *ndi) {
  char *name;
  getter *get;

  do {
    name = (char *)(nd_getset[ndi->n].name);
    get = &(nd_getset[ndi->n].get);
    if (!name) {
      PyErr_SetNone(PyExc_StopIteration);
      return NULL;
    }

    ndi->n += 1;
  } while (name[0] == '_');

  return Py_BuildValue("(sN)", name, (*get)((PyObject *)(ndi->nd), NULL));
}

PyTypeObject NflogDatatype {
  PyVarObject_HEAD_INIT(&PyType_Type, 0)
  "NflogData",               /* tp_name */
  sizeof(nflogdataobject),        /* tp_basicsize */
  0,                         /* tp_itemsize */
  (destructor)nflogdata_dealloc, /* tp_dealloc */
  0,                         /* tp_print */
  0,                         /* tp_getattr */
  0,                         /* tp_setattr */
  0,                         /* tp_reserved */
  (reprfunc)nd__repr__,       /* tp_repr */
  0,                         /* tp_as_number */
  0,                         /* tp_as_sequence */
  0,                         /* tp_as_mapping */
  0,                         /* tp_hash */
  0,                         /* tp_call */
  (reprfunc)nd__str__,        /* tp_str */
  0,                         /* tp_getattro */
  0,                         /* tp_setattro */
  0,                         /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT,        /* tp_flags */
  NULL,                      /* tp_doc */
  0,                         /* tp_traverse */
  0,                         /* tp_clear */
  0,                         /* tp_richcompare */
  0,                         /* tp_weaklistoffset */
  (getiterfunc)nd__iter__,    /* tp_iter */
  0,                         /* tp_iternext */
  nd_methods,                 /* tp_methods */
  0,                         /* tp_members */
  nd_getset,                  /* tp_getset */
  0,                         /* tp_base */
  0,                         /* tp_dict */
  0,                         /* tp_descr_get */
  0,                         /* tp_descr_set */
  0,                         /* tp_dictoffset */
  0,                         /* tp_init */
  0,                         /* tp_alloc */
  (newfunc)nd__new__,         /* tp_new */
};

PyTypeObject NflogDataItertype {
  PyVarObject_HEAD_INIT(&PyType_Type, 0)
  "NflogDataIter",           /* tp_name */
  sizeof(nflogdataiter),     /* tp_basicsize */
  0,                         /* tp_itemsize */
  (destructor)ndi_dealloc,   /* tp_dealloc */
  0,                         /* tp_print */
  0,                         /* tp_getattr */
  0,                         /* tp_setattr */
  0,                         /* tp_reserved */
  0,                         /* tp_repr */
  0,                         /* tp_as_number */
  0,                         /* tp_as_sequence */
  0,                         /* tp_as_mapping */
  0,                         /* tp_hash */
  0,                         /* tp_call */
  0,                         /* tp_str */
  0,                         /* tp_getattro */
  0,                         /* tp_setattro */
  0,                         /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT,        /* tp_flags */
  NULL,                      /* tp_doc */
  0,                         /* tp_traverse */
  0,                         /* tp_clear */
  0,                         /* tp_richcompare */
  0,                         /* tp_weaklistoffset */
  (getiterfunc)ndi__iter__,  /* tp_iter */
  (iternextfunc)ndi__next__, /* tp_iternext */
  0,                         /* tp_methods */
  0,                         /* tp_members */
  0,                         /* tp_getset */
  0,                         /* tp_base */
  0,                         /* tp_dict */
  0,                         /* tp_descr_get */
  0,                         /* tp_descr_set */
  0,                         /* tp_dictoffset */
  0,                         /* tp_init */
  0,                         /* tp_alloc */
  0,                         /* tp_new */
};

/*  vim: set ts=2 sw=2 et ai si: */
