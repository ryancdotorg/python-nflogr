/* Copyright 2021 Ryan Castellucci, MIT License */

#include <Python.h>
#include <pytime.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <endian.h>
#include <netinet/in.h>
#include <net/if.h>

extern "C" {
#include <libnetfilter_log/libnetfilter_log.h>
#include <libnfnetlink/linux_nfnetlink_compat.h>
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

  PyObject *indev;
  PyObject *physindev;
  PyObject *outdev;
  PyObject *physoutdev;

  PyObject *uid;
  PyObject *gid;

  PyObject *hwhdr;
  PyObject *payload;

  PyObject *prefix;

  PyObject *raw;
  PyObject *devnames;
} nflogdataobject;

typedef struct {
  PyObject_HEAD
  nflogdataobject *nd;
  int        n;
} nflogdataiter;

static PyObject * _NfadAsTuple(struct nflog_data *nfad);
static struct nflog_data * _TupleAsNfad(PyObject *tup);
static PyObject * _PyLong_AsBigEndian(PyObject *pylong, unsigned char width);
static PyObject * _ull_AsBigEndian(unsigned long long val, unsigned char width);

static void nd_dealloc(register nflogdataobject *nd) {
  Py_XDECREF(nd->indev);
  Py_XDECREF(nd->physindev);
  Py_XDECREF(nd->outdev);
  Py_XDECREF(nd->physoutdev);

  Py_XDECREF(nd->uid);
  Py_XDECREF(nd->gid);

  Py_XDECREF(nd->hwhdr);
  Py_XDECREF(nd->payload);

  Py_XDECREF(nd->prefix);

  Py_XDECREF(nd->raw);
  Py_XDECREF(nd->devnames);

  PyObject_Del(nd);
}

// wraps if_indextoname with fallback behaviour for failure
static PyObject * _if_indextoname(uint32_t idx) {
  char buf[IF_NAMESIZE] = {0};
  if (!if_indextoname(idx, buf)) {
    snprintf(buf, sizeof(buf), "unkn/%u", idx);
  }
  return Py_BuildValue("s", buf);
}

// look up device name from index with mock support
static PyObject * _devname(register nflogdataobject *nd, uint32_t idx) {
  if (idx) {
    PyObject *devname;
    // if devnames is non-null, check there first
    if (nd->devnames) {
      PyObject *devidx;
      if (!(devidx = Py_BuildValue("k", idx))) { return NULL; }
      if ((devname = PyDict_GetItem(nd->devnames, devidx))) {
        // found
        Py_INCREF(devname);
      } else {
        // not found, ask the system and save
        devname = _if_indextoname(idx);
        if (PyDict_SetItem(nd->devnames, devidx, devname) != 0) {
          Py_DECREF(devname);
          Py_DECREF(devidx);
          return NULL;
        }
      }
      Py_DECREF(devidx);
    } else {
      devname = _if_indextoname(idx);
    }
    return devname;
  } else {
    Py_RETURN_NONE;
  }
}

PyObject * new_nflogdataobject(struct nflog_data *nfad, PyObject *devnames) {
  nflogdataobject *nd = PyObject_New(nflogdataobject, &NflogDatatype);
  if (!nd) { return NULL; }

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
    nd_dealloc(nd);
    return NULL;
  }
  if (_PyTime_FromTimeval(&tp, &tv) != 0) {
    nd_dealloc(nd);
    return NULL;
  }
  nd->timestamp = _PyTime_AsSecondsDouble(tp);

  // internal values
  if ((nd->devnames = devnames)) {
    nd->raw = _NfadAsTuple(nfad);
  } else {
    nd->raw = Py_None;
    Py_INCREF(Py_None);
  }

  // devs
  nd->indev = _devname(nd, nflog_get_indev(nfad));
  nd->physindev = _devname(nd, nflog_get_physindev(nfad));
  nd->outdev = _devname(nd, nflog_get_outdev(nfad));
  nd->physoutdev = _devname(nd, nflog_get_physoutdev(nfad));

  // uid/gid
  uint32_t id;
  if (nflog_get_uid(nfad, &id) == 0) {
    if (!(nd->uid = Py_BuildValue("k", id))) {
      nd_dealloc(nd);
      return NULL;
    }
  } else {
    nd->uid = Py_None;
    Py_INCREF(Py_None);
  }
  if (nflog_get_gid(nfad, &id) == 0) {
    if (!(nd->gid = Py_BuildValue("k", id))) {
      nd_dealloc(nd);
      return NULL;
    }
  } else {
    nd->gid = Py_None;
    Py_INCREF(Py_None);
  }

  char *hwhdr = nflog_get_msg_packet_hwhdr(nfad);
  size_t hwhdr_sz = nflog_get_msg_packet_hwhdrlen(nfad);
  if (!(nd->hwhdr = Py_BuildValue("y#", hwhdr, hwhdr_sz))) {
    nd_dealloc(nd);
    return NULL;
  }

  char *payload;
  int payload_sz = nflog_get_payload(nfad, &payload);
  if (!(nd->payload = Py_BuildValue("y#", payload, payload_sz))) {
    nd_dealloc(nd);
    return NULL;
  }

  char *prefix = nflog_get_prefix(nfad);
  if (!(nd->prefix = Py_BuildValue("s", prefix))) {
    nd_dealloc(nd);
    return NULL;
  }

  return (PyObject *)nd;
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
  Py_INCREF(nd->indev);
  return nd->indev;
}

static PyObject * nd_get_physindev(register nflogdataobject *nd, void *) {
  Py_INCREF(nd->physindev);
  return nd->physindev;
}

static PyObject * nd_get_outdev(register nflogdataobject *nd, void *) {
  Py_INCREF(nd->outdev);
  return nd->outdev;
}

static PyObject * nd_get_physoutdev(register nflogdataobject *nd, void *) {
  Py_INCREF(nd->physoutdev);
  return nd->physoutdev;
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

// all getters return new references
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
  {NULL}
};

// generate serialization structures for device names, returns -1 on failure
static int _set_dev(
  PyObject *devnames, PyObject *raw, PyObject *ifnames[], PyObject *dev,
  int ifcount, Py_ssize_t n
) {
  if (dev == Py_None) { return 0; }

  // loop over ifnames looking for a matching name
  int i = 0, rv;
  for (;;) {
    if (i > ifcount) {
      PyErr_SetString(PyExc_RuntimeError, "too many interfaces!?");
      return -1;
    } else if (i == ifcount) {
      ifnames[i] = dev;
      break;
    } else if ((rv = PyUnicode_Compare(ifnames[i], dev)) == 0) {
      break;
    } else if (rv == -1) {
      PyGILState_STATE gil = PyGILState_Ensure();
      // needs GIL
      if (PyErr_Occurred()) {
        PyGILState_Release(gil);
        return -1;
      }
      PyGILState_Release(gil);
    }
    ++i;
  }

  i = i + 1;  // device indexes start at 1

  // save the results
  PyObject *item, *devidx;
  if (!(item = _ull_AsBigEndian(i, 4))) { return -1; }
  PyTuple_SET_ITEM(raw, n, item);
  if (!(devidx = Py_BuildValue("k", i))) { return -1; }
  if (PyDict_SetItem(devnames, devidx, dev) != 0) { return -1; }
  Py_INCREF(dev);

  return i;
}

// get raw data, aliased as __getnewargs to enable pickling
PyDoc_STRVAR(nd__get_raw_doc,
"_get_raw($self, useraw=None, /)\n"
"--\n\n"
"INTENDED FOR DEBUGGING/TESTING ONLY!\n\n"
"get raw data, can be passed to pass to __new__ to recreate this object\n"
"\n"
"  useraw\n"
"   If `None`, use saved raw data if available.\n"
"   If `False`, don\'t use saved raw data.\n"
"   If `True`, return saved raw data or `None` if unavailable."
);
static PyObject * nd__get_raw(register nflogdataobject *nd, PyObject *args) {
  // by default, use the raw data if it exists
  int useraw = !!(nd->devnames);

  PyObject *ret, *devnames, *raw, *item = Py_None;
  if (!PyArg_ParseTuple(args, "|O:__getnewargs__", &item)) { return NULL; }
  if (_nflogr_tristate(item, &useraw) != 0) { return NULL; }

  if (!(ret = PyTuple_New(2))) { return NULL; }

  if (useraw) {
    if (!(nd->devnames)) {
      Py_DECREF(ret);
      Py_RETURN_NONE;
    }

    Py_INCREF(nd->devnames);
    PyTuple_SET_ITEM(ret, 0, nd->devnames);

    Py_INCREF(nd->raw);
    PyTuple_SET_ITEM(ret, 1, nd->raw);

    return ret;
  }

  // not using raw data, so generate a struct from the data we saved
  // XXX THIS WILL NOT MATCH EXACTLY!
  if (!(devnames = PyDict_New())) {
    Py_DECREF(ret);
    return NULL;
  }

  if (!(raw = PyTuple_New(NFULA_MAX))) {
    Py_DECREF(devnames);
    Py_DECREF(ret);
    return NULL;
  }

  // NFULA_PACKET_HDR - construct from nd->proto
  if (nd->proto) {
    char packet_hdr[4];
    packet_hdr[0] = ((nd->proto) >> 8) & 255;
    packet_hdr[1] = (nd->proto) & 255;
    if (!(item = Py_BuildValue("y#", packet_hdr, 4))) { goto nd__get_raw_cleanup; }
    PyTuple_SET_ITEM(raw, NFULA_PACKET_HDR-1, item);
  }

  // NFULA_MARK - construct from nd->nfmark
  if (!(item = _ull_AsBigEndian(nd->nfmark, 4))) { goto nd__get_raw_cleanup; }
  PyTuple_SET_ITEM(raw, NFULA_MARK-1, item);

  {
    // NFULA_TIMESTAMP - construct from nd->timestamp
    struct nfulnl_msg_packet_timestamp uts;
    double sec = nd->timestamp;
    uint64_t usec = ((0.0000005 + sec) - ((uint64_t)sec)) * 1000000.0;
    if (usec > 999999) { usec = 999999; }  // just in case...
    uts.sec = htobe64(sec);
    uts.usec = htobe64(usec);
    if (!(item = Py_BuildValue("y#", (char *)(&uts), sizeof(uts)))) {
      goto nd__get_raw_cleanup;
    }
    PyTuple_SET_ITEM(raw, NFULA_TIMESTAMP-1, item);
  }

  {
    // NFULA_IFINDEX_INDEV - construct from nd->indev + ifnames
    // NFULA_IFINDEX_PHYSINDEV - construct from nd->physindev + ifnames
    // NFULA_IFINDEX_OUTDEV - construct from nd->outdev + ifnames
    // NFULA_IFINDEX_PHYSOUTDEV - construct from nd->physoutdev + ifnames
    int ifcount = 0;
    PyObject *ifnames[4];
    if ((ifcount = _set_dev(
      devnames, raw, ifnames, nd->indev, ifcount, NFULA_IFINDEX_INDEV-1)
    ) < 0) { goto nd__get_raw_cleanup; }
    if ((ifcount = _set_dev(
      devnames, raw, ifnames, nd->physindev, ifcount, NFULA_IFINDEX_PHYSINDEV-1)
    ) < 0) { goto nd__get_raw_cleanup; }
    if ((ifcount = _set_dev(
      devnames, raw, ifnames, nd->outdev, ifcount, NFULA_IFINDEX_OUTDEV-1)
    ) < 0) { goto nd__get_raw_cleanup; }
    if ((ifcount = _set_dev(
      devnames, raw, ifnames, nd->physoutdev, ifcount, NFULA_IFINDEX_PHYSOUTDEV-1)
    ) < 0) { goto nd__get_raw_cleanup; }
  }

  // NFULA_HWADDR - not supported

  {
    // NFULA_PAYLOAD - construct from nd->payload
    // nflog_get_payload discards NFA_LENGTH(0) bytes, so we need to add padding
    char *payload_data, *payload_pad;
    Py_ssize_t payload_size;
    if (PyBytes_AsStringAndSize(nd->payload, &payload_data, &payload_size) != 0) {
      goto nd__get_raw_cleanup;
    }
    if (!(payload_pad = (char *)calloc(1, payload_size + NFA_LENGTH(0)))) {
      PyErr_NoMemory();
      goto nd__get_raw_cleanup;
    }
    memcpy(payload_pad, payload_data, payload_size);
    if (!(item = Py_BuildValue("y#", payload_pad, payload_size + NFA_LENGTH(0)))) {
       goto nd__get_raw_cleanup;
    }
    PyTuple_SET_ITEM(raw, NFULA_PAYLOAD-1, item);
  }

  {
    // NFULA_PREFIX - construction from nd->prefix
    Py_ssize_t pfxlen;
    char *pfxstr;
    if (!(pfxstr = (char *)PyUnicode_AsUTF8AndSize(nd->prefix, &pfxlen))) {
      goto nd__get_raw_cleanup;
    }
    if (!(item = Py_BuildValue("y#", pfxstr, pfxlen + 1))) { goto nd__get_raw_cleanup; }
    PyTuple_SET_ITEM(raw, NFULA_PREFIX-1, item);
  }

  // NFULA_UID - construct from nd->uid
  if (!(item = _PyLong_AsBigEndian(nd->uid, 4))) { goto nd__get_raw_cleanup; }
  PyTuple_SET_ITEM(raw, NFULA_UID-1, item);

  // NFULA_SEQ - not supported
  // NFULA_SEQ_GLOBAL - not supported

  // NFULA_GID - construct from nd->gid
  if (!(item = _PyLong_AsBigEndian(nd->gid, 4))) { goto nd__get_raw_cleanup; }
  PyTuple_SET_ITEM(raw, NFULA_GID-1, item);

  // NFULA_HWTYPE - construct from nd->hwtype
  if (!(item = _ull_AsBigEndian(nd->hwtype, 2))) { goto nd__get_raw_cleanup; }
  PyTuple_SET_ITEM(raw, NFULA_HWTYPE-1, item);

  // NFULA_HWHEADER - construct from nd->hwhdr
  Py_INCREF(nd->hwhdr);
  PyTuple_SET_ITEM(raw, NFULA_HWHEADER-1, nd->hwhdr);

  // NFULA_HWLEN - construct from nd->hwhdr
  if (!(item = _ull_AsBigEndian(PyBytes_Size(nd->hwhdr), 2))) { goto nd__get_raw_cleanup; }
  PyTuple_SET_ITEM(raw, NFULA_HWLEN-1, item);

  // set any remaining values in the tuple to `None`
  for (int i = 0; i < NFULA_MAX; ++i) {
    if (!(item = PyTuple_GET_ITEM(raw, i))) {
      Py_INCREF(Py_None);
      PyTuple_SET_ITEM(raw, i, Py_None);
    }
  }

  PyTuple_SET_ITEM(ret, 0, devnames);
  PyTuple_SET_ITEM(ret, 1, raw);

  return ret;

nd__get_raw_cleanup:
  Py_DECREF(raw);
  Py_DECREF(devnames);
  Py_DECREF(ret);
  return NULL;
}

static PyMethodDef nd_methods[] = {
  {"_get_raw", (PyCFunction) nd__get_raw, METH_VARARGS, nd__get_raw_doc},
  {"__getnewargs__", (PyCFunction) nd__get_raw, METH_VARARGS, PyDoc_STR(
    "__getnewargs__($self, /)\n"
    "--\n\n"
  )},
  {NULL, NULL}
};

struct nflog_data {
  struct nfattr **nfa;
};

static PyObject * _NfadAsTuple(struct nflog_data *nfad) {
  PyObject *tup = PyTuple_New(NFULA_MAX);
  if (!tup) { return NULL; }
  struct nfattr *nfa;
  int i;

  for (i = 0; i < NFULA_MAX; ++i) {
    nfa = nfad->nfa[i];
    if (nfa) {
      PyObject *bytes;
      if (!(bytes = Py_BuildValue("y#", (((char *)(nfa)) + NFA_LENGTH(0)), nfa->nfa_len))) {
        return NULL;
      }
      PyTuple_SET_ITEM(tup, i, bytes);
    } else {
      Py_INCREF(Py_None);
      PyTuple_SET_ITEM(tup, i, Py_None);
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
    if (!bytes) {
      return NULL;
    } else if (bytes == Py_None) {
      continue;
    } else if (!PyBytes_Check(bytes)) {
      PyErr_SetString(PyExc_TypeError, "tuple memeber not bytes or None");
      return NULL;
    } else if ((len = PyBytes_Size(bytes)) > 65535) {
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

static PyObject * _PyLong_AsBigEndian(PyObject *pylong, unsigned char width) {
  if (pylong == Py_None) { Py_RETURN_NONE; }

  unsigned long long val = PyLong_AsUnsignedLong(pylong);
  if (val == ((unsigned long long)-1)) {
    PyGILState_STATE gil = PyGILState_Ensure();
    // needs GIL
    if (PyErr_Occurred()) {
      PyGILState_Release(gil);
      return NULL;
    }
    PyGILState_Release(gil);
  }

  return _ull_AsBigEndian(val, width);
}

static PyObject * _ull_AsBigEndian(unsigned long long val, unsigned char width) {
  char buf[8];
  int p = 0;
  switch (width) {
    case 8:
      buf[p++] = (val >> 56) & 255;
      buf[p++] = (val >> 48) & 255;
      buf[p++] = (val >> 40) & 255;
      buf[p++] = (val >> 32) & 255;
    case 4:
      buf[p++] = (val >> 24) & 255;
      buf[p++] = (val >> 16) & 255;
    case 2:
      buf[p++] = (val >>  8) & 255;
    case 1:
      buf[p++] = val & 255;
      break;
    default:
      PyErr_SetString(PyExc_ValueError, "width must be 8, 4, 2 or 1");
      return NULL;
  }

  PyObject *bytes = Py_BuildValue("y#", buf, width);
  if (!bytes) { return NULL; }

  return bytes;
}

PyObject * nd__iter__(register nflogdataobject *nd) {
  if (PyType_Ready(&NflogDataItertype) != 0) { return NULL; }

  nflogdataiter *iter = PyObject_New(nflogdataiter, &NflogDataItertype);
  if (!iter) { return NULL; }
  iter->nd = nd;
  iter->n = 0;
  Py_INCREF(nd);
  return (PyObject *)iter;
}

PyObject * nd__str__(register nflogdataobject *nd) {
  // basically equivalent to dict(nd)
  PyObject *dict = PyDict_New();
  if (!dict) { return NULL; }
  if (PyDict_MergeFromSeq2(dict, (PyObject *)nd, 0) != 0) {
    Py_DECREF(dict);
    return NULL;
  }

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
  PyObject *dict, *tup;

  if (!PyArg_ParseTuple(args, "OO:__new__", &dict, &tup)) { return NULL; }

  if (!PyDict_Check(dict) || !PyTuple_Check(tup)) {
    PyErr_SetString(PyExc_TypeError, "arguments must be (dict, tuple)");
    return NULL;
  }

  // nflog_handle_packet normally takes care of freeing the nflog_data struct
  // after creating it and sending it to the callback, and since we're creating
  // the struct outselves here, we also need to free it ourselves.
  struct nflog_data *nfad = _TupleAsNfad(tup);
  if (!nfad) { return NULL; }
  Py_INCREF(dict);
  PyObject *nd = new_nflogdataobject(nfad, dict);
  free(nfad);
  return nd;
}

PyTypeObject NflogDatatype {
  PyVarObject_HEAD_INIT(&PyType_Type, 0)
  "nflogr.NflogData",        /* tp_name */
  sizeof(nflogdataobject),   /* tp_basicsize */
  0,                         /* tp_itemsize */
  (destructor)nd_dealloc,    /* tp_dealloc */
  0,                         /* tp_print */
  0,                         /* tp_getattr */
  0,                         /* tp_setattr */
  0,                         /* tp_reserved */
  (reprfunc)nd__repr__,      /* tp_repr */
  0,                         /* tp_as_number */
  0,                         /* tp_as_sequence */
  0,                         /* tp_as_mapping */
  0,                         /* tp_hash */
  0,                         /* tp_call */
  (reprfunc)nd__str__,       /* tp_str */
  0,                         /* tp_getattro */
  0,                         /* tp_setattro */
  0,                         /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT,        /* tp_flags */
  NULL,                      /* tp_doc */
  0,                         /* tp_traverse */
  0,                         /* tp_clear */
  0,                         /* tp_richcompare */
  0,                         /* tp_weaklistoffset */
  (getiterfunc)nd__iter__,   /* tp_iter */
  0,                         /* tp_iternext */
  nd_methods,                /* tp_methods */
  0,                         /* tp_members */
  nd_getset,                 /* tp_getset */
  0,                         /* tp_base */
  0,                         /* tp_dict */
  0,                         /* tp_descr_get */
  0,                         /* tp_descr_set */
  0,                         /* tp_dictoffset */
  0,                         /* tp_init */
  0,                         /* tp_alloc */
  (newfunc)nd__new__,        /* tp_new */
};

// iterator helper class
static void ndi_dealloc(register nflogdataiter *ndi) {
  Py_DECREF(ndi->nd);
  PyObject_Del(ndi);
}

PyObject * ndi__iter__(register nflogdataiter *ndi) {
  Py_INCREF(ndi);
  return (PyObject *)ndi;
}

PyObject * ndi__next__(register nflogdataiter *ndi) {
  char *name;
  getter *get;
  PyObject *val;

  do {
    name = (char *)(nd_getset[ndi->n].name);
    get = &(nd_getset[ndi->n].get);
    if (!name) {
      PyErr_SetNone(PyExc_StopIteration);
      return NULL;
    }

    ndi->n += 1;
    // skip over attributes starting with an underscore
  } while (name[0] == '_');

  // call the getter, passing along any failures
  if (!(val = (*get)((PyObject *)(ndi->nd), NULL))) {
    return NULL;
  }

  return Py_BuildValue("(sN)", name, val);
}

PyTypeObject NflogDataItertype {
  PyVarObject_HEAD_INIT(&PyType_Type, 0)
  "nflogr.NflogDataIter",    /* tp_name */
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
