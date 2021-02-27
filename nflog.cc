/* Copyright 2021 Ryan Castellucci, MIT License */

#include <Python.h>
#include <pytime.h>

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/if.h>

extern "C" {
#include <libnetfilter_log/libnetfilter_log.h>
}

#include "nflog.h"
#include "nflogdata.h"
#include "nflogr.h"

// linked list object
typedef struct fifo_s {
  PyObject *o;
  struct fifo_s *next;
} fifo_t;

// internal nflogobject
typedef struct {
  PyObject_HEAD
  PyObject *mock;
  struct nflog_handle *h;
  struct nflog_g_handle *gh;
  fifo_t *head;
  fifo_t *tail;
  int group;
  int fd;
  int raw;
} nflogobject;

static int fifo_push(register nflogobject *n, PyObject *o) {
  fifo_t *entry = (fifo_t *)malloc(sizeof(fifo_t));
  if (!entry) {
    PyErr_NoMemory();
    return -1;
  } else if (!o) {
    return -1;
  }

  // create entry
  entry->o = o;
  entry->next = NULL;

  // append entry to list
  if (n->tail) {
    n->tail->next = entry;
    n->tail = entry;
  } else {
    n->head = n->tail = entry;
  }

  return 0;
}

static PyObject * fifo_shift(register nflogobject *n) {
  if (!n->head) { Py_RETURN_NONE; }

  // get the first object
  PyObject *o = n->head->o;

  // save reference to next entry
  fifo_t *next = n->head->next;

  // remove first entry from list
  free(n->head);
  if (next) {
    n->head = next;
  } else {
    n->head = n->tail = NULL;
  }

  return o;
}

static void fifo_empty(register nflogobject *n) {
  PyObject *o;
  for (;;) {
    o = fifo_shift(n);
    if (o == Py_None) {
      Py_DECREF(o);
      break;
    } else {
      Py_DECREF(o);
    }
  }
}

// steals reference to o
static PyObject * entuple(PyObject *o) {
  PyObject *tup = PyTuple_New(1);
  PyTuple_SetItem(tup, 0, o);
  return tup;
}

static PyObject * n_close(register nflogobject *n, PyObject *) {
  if (n->gh) { nflog_unbind_group(n->gh); }
  if (n->h) { nflog_close(n->h); }

  // clear references
  n->h = NULL; n->gh = NULL;
  n->fd = -2;

  Py_RETURN_NONE;
}

static void nflog_dealloc(register nflogobject *n) {
  n_close(n, NULL);
  fifo_empty(n);
  PyObject_Del(n);
}

// nflog methods
static PyObject * n_next(register nflogobject *n, PyObject *args);
static PyObject * n_loop(register nflogobject *n, PyObject *args);
static PyObject * n_getfd(register nflogobject *n, PyObject *);
static PyObject * n_getgroup(register nflogobject *n, PyObject *);
static PyObject * n_fileno(register nflogobject *n, PyObject *);
static PyObject * n__raw(register nflogobject *n, PyObject *args);
static PyObject * n__recv_raw(register nflogobject *n, PyObject *);
static PyObject * n__enter__(register nflogobject *n, PyObject *);
static PyObject * n__iter__(register nflogobject *n);
static PyObject * n__next__(register nflogobject *n);

static PyMethodDef n_methods[] = {
  {"next", (PyCFunction) n_next, METH_VARARGS, PyDoc_STR(
      "next(fn=None)\n"
      "--\n\n"
      "return next message"
  )},
  {"loop", (PyCFunction) n_loop, METH_VARARGS, PyDoc_STR(
      "loop(fn, count=-1)\n"
      "--\n\n"
      "process `count` (-1 meaning 'infinite') messages in a loop,"
      "passing each to callback function `fn`"
  )},
  {"close", (PyCFunction) n_close, METH_NOARGS, PyDoc_STR(
      "close()\n"
      "--\n\n"
      "close the socket"
  )},
  {"getfd", (PyCFunction) n_getfd, METH_NOARGS, PyDoc_STR(
      "getfd()\n"
      "--\n\n"
      "get selectable nflog fd"
  )},
  {"getgroup", (PyCFunction) n_getgroup, METH_NOARGS, PyDoc_STR(
      "getgroup()\n"
      "--\n\n"
      "get nflog group id"
  )},
  {"_raw", (PyCFunction) n__raw, METH_VARARGS, PyDoc_STR(
      "query/enable/disable capture of raw nflog data\n"
      "INTENDED FOR DEBUGGING/TESTING ONLY!"
  )},
  {"_recv_raw", (PyCFunction) n__recv_raw, METH_NOARGS, PyDoc_STR(
      "receive raw nflog data\n"
      "INTENDED FOR DEBUGGING/TESTING ONLY!"
  )},
  {"fileno", (PyCFunction) n_fileno, METH_NOARGS, NULL},
  {"__enter__", (PyCFunction) n__enter__, METH_NOARGS, NULL},
  {"__exit__", (PyCFunction) n_close, METH_VARARGS, NULL},
  {NULL, NULL} /* sentinel */
};

PyTypeObject Nflogtype {
  PyVarObject_HEAD_INIT(&PyType_Type, 0)
  "Nflog",                   /* tp_name */
  sizeof(nflogobject),       /* tp_basicsize */
  0,                         /* tp_itemsize */
  (destructor)nflog_dealloc, /* tp_dealloc */
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
  (getiterfunc)n__iter__,    /* tp_iter */
  (iternextfunc)n__next__,   /* tp_iternext */
  n_methods,                 /* tp_methods */
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

static int NflogQueue(struct nflog_g_handle *, struct nfgenmsg *, struct nflog_data *nfad, void *data) {
  nflogobject *n = (nflogobject *)data;
  return fifo_push(n, new_nflogdataobject(nfad, n->raw));
}

PyObject * new_nflogobject(struct nflog_handle *h, struct nflog_g_handle *gh, int group) {
  if (PyType_Ready(&Nflogtype) < 0) { return NULL; }

  nflogobject *n = PyObject_New(nflogobject, &Nflogtype);
  if (n == NULL) { return NULL; }

  // initialize values
  n->h = h; n->gh = gh;
  n->group = group;
  n->mock = NULL;
  n->head = n->tail = NULL;
  n->raw = 0;

  if (h == NULL && gh == NULL && group < 0) {
    n->fd = -1;
  } else {
    n->fd = nflog_fd(h);
    nflog_callback_register(n->gh, NflogQueue, n);
  }

  return (PyObject *)n;
}

PyObject * mock_nflogobject(PyObject *iter) {
  nflogobject *n = (nflogobject *)new_nflogobject(NULL, NULL, -1);
  n->mock = iter;
  Py_INCREF(iter);
  return (PyObject *)n;
}

#define NFLOG_CHECK(N) \
  do { \
    if (Py_TYPE(N) != &Nflogtype) { \
      PyErr_SetString(NflogError, "not an nflog object"); \
      return NULL; \
    } \
  } while (0);

// return exactly one nflogdata object, calling recv if needed
static PyObject * _recv(register nflogobject *n) {
  NFLOG_CHECK(n);

  PyObject *list, *item, *nd;
  char buf[16384];
  int rv, i;
  Py_ssize_t count;

  if (n->head) {
    return fifo_shift(n);
  } else if (n->mock) {
    // inject raw data from an iterator
    if ((list = PyIter_Next(n->mock))) {
      for (i = 0, count = PyList_Size(list); i < count; ++i) {
        item = PyList_GetItem(list, i);
        nd = NflogDatatype.tp_new(&NflogDatatype, entuple(item), Py_None);
        if (!nd || fifo_push(n, nd) != 0) { return NULL; }
      }
      Py_DECREF(list);
      return fifo_shift(n);
    } else {
      PyGILState_STATE gil = PyGILState_Ensure();
      // needs GIL
      if (PyErr_Occurred()) {
        PyGILState_Release(gil);
        return NULL;
      }
      PyGILState_Release(gil);
    }

    n->mock = NULL;
    return _recv(n);
  } else if (!(n->h) || !(n->gh) || n->fd == -2) {
    PyErr_SetString(NflogClosedError, "nflog is closed");
    return NULL;
  } else if ((rv = recv(n->fd, buf, sizeof(buf), 0)) >= 0) {
    /*
    fprintf(stderr, "recv(%d): ", rv);
    for (int i = 0; i < rv; ++i) {
      fprintf(stderr, "%02x", (unsigned char)buf[i]);
    }
    fprintf(stderr, "\n");//*/
    // regularly returns non-fatal errors, so don't check return
    nflog_handle_packet(n->h, buf, rv);
    return fifo_shift(n);
  } else {
    PyErr_Format(
        PyExc_OSError,
        "recv() on nflog fd %s failed %s (%d)",
        n->fd, strerror(errno), errno
    );
    return NULL;
  }
}

static PyObject * n__recv_raw(register nflogobject *n, PyObject *) {
  fifo_empty(n);
  n->raw = 1;

  PyObject *nd, *raw, *list;
  if (!(list = PyList_New(0))) { return NULL; }

  if (fifo_push(n, _recv(n)) != 0) {
    Py_DECREF(list);
    return NULL;
  }

  while ((nd = fifo_shift(n)) != Py_None) {
    raw = PyObject_GetAttrString(nd, "_raw");
    Py_DECREF(nd);
    if (!raw) { return NULL; }

    if (PyList_Append(list, raw) != 0) {
      Py_DECREF(list);
      return NULL;
    }
  }
  return list;
}

static PyObject * n_next(register nflogobject *n, PyObject *args) {
  PyObject *nd, *map, *PyFn = Py_None;
  PyArg_ParseTuple(args, "|O:next", &PyFn);

  if (PyFn != Py_None) {
    if (!PyCallable_Check(PyFn)) {
      PyErr_SetString(PyExc_TypeError, "argument must be callable if not `None`");
      return NULL;
    }
    if (!(nd = _recv(n))) { return nd; }
    nd = entuple(nd);
    map = PyObject_CallObject(PyFn, nd);
    Py_DECREF(nd);
    return map;
  } else {
    return _recv(n);
  }
}

static PyObject * n_loop(register nflogobject *n, PyObject *args) {
  int cnt = -1;
  PyObject *nd, *PyFn;

  if (!PyArg_ParseTuple(args, "O|i:loop", &PyFn, &cnt)) {
    return NULL;
  } else if (!PyCallable_Check(PyFn)) {
    PyErr_SetString(PyExc_TypeError, "argument must be callable");
    return NULL;
  }

  while (cnt != 0) {
    if (!(nd = _recv(n))) { return nd; }

    if (nd == Py_None) {
      Py_DECREF(nd);
      break;
    } else {
      nd = entuple(nd);
      PyObject_CallObject(PyFn, nd);
      Py_DECREF(nd);
    }
    if (cnt > 0) { --cnt; }
  }

  Py_RETURN_NONE;
}

static PyObject * n_getfd(register nflogobject *n, PyObject *) {
  NFLOG_CHECK(n);

  if (n->fd >= 0) {
    return Py_BuildValue("i", n->fd);
  } else {
    Py_RETURN_NONE;
  }
}

static PyObject * n_fileno(register nflogobject *n, PyObject *) {
  NFLOG_CHECK(n);

  if (n->fd >= 0) {
    return Py_BuildValue("i", n->fd);
  } else {
    PyErr_SetString(PyExc_ValueError, "I/O operation on closed handle");
    return NULL;
  }
}

static PyObject * n_getgroup(register nflogobject *n, PyObject *) {
  NFLOG_CHECK(n);

  if (n->group >= 0) {
    return Py_BuildValue("i", n->group);
  } else {
    Py_RETURN_NONE;
  }
}

static PyObject * n__raw(register nflogobject *n, PyObject *args) {
  NFLOG_CHECK(n);

  int raw = -1;

  PyArg_ParseTuple(args, "|p:_raw", &raw);
  if (raw >= 0) { n->raw = raw; }

  return PyBool_FromLong(n->raw);
}

static PyObject * n__enter__(register nflogobject *n, PyObject *) {
  Py_INCREF(n);
  return (PyObject *)n;
}

static PyObject * n__iter__(register nflogobject *n) {
  Py_INCREF(n);
  return (PyObject *)n;
}

static PyObject * n__next__(register nflogobject *n) {
  NFLOG_CHECK(n);

  PyObject *nd;
  if (!(nd = _recv(n))) {
    PyGILState_STATE gil = PyGILState_Ensure();
    // needs GIL
    if (PyErr_ExceptionMatches(NflogClosedError)) {
      PyErr_SetNone(PyExc_StopIteration);
    }
    PyGILState_Release(gil);
    return NULL;
  }

  return nd;
}

/*  vim: set ts=2 sw=2 et ai si: */
