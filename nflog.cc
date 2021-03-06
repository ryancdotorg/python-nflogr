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

#include "nflogr.h"
#include "nflog.h"
#include "nflogopt.h"
#include "nflogdata.h"

// retry limit chosen unscientifically, may need to be higher
#define RECV_RETRY_LIMIT 64

// internal fifo object (singly linked list)
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
  int drops;
  int raw;
} nflogobject;

// should be called at the start of any function exposed to python which
// accesses any memebers of the nflogobject struct, or calls functions which do
#define NFLOG_CHECK(N, R) \
  do { \
    if (Py_TYPE(N) != &Nflogtype) { \
      PyErr_SetString(NflogError, "not an nflog object"); \
      return R; \
    } \
  } while (0);

// append to fifo, steals refrence to o, returns 0 on success, -1 on failure
static int fifo_push(register nflogobject *n, PyObject *o) {
  fifo_t *entry = (fifo_t *)malloc(sizeof(fifo_t));
  if (!entry) {
    PyErr_NoMemory();
    return -1;
  } else if (o == Py_None) {
    // don't push None
    return 0;
  } else if (!o) {
    // if we have a null pointer, something's gone very wrong
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

// take from fifo, returns owned reference, can't fail
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

// walk the fifo for size, can't fail under any reasonable circumstances
static Py_ssize_t fifo_len(register nflogobject *n) {
  Py_ssize_t len = 0;
  fifo_t *node = n->head;
  while (node) {
    node = node->next;
    ++len;
  }

  return len;
}

// empties the fifo, decrementing refrence count of contained objects
static void fifo_empty(register nflogobject *n) {
  PyObject *o;
  for (;;) {
    o = fifo_shift(n);
    if (o == Py_None) {
      Py_DECREF(o);
      break;
    }
    Py_DECREF(o);
  }
}

// steals reference to o, returns it enclosed in a new tuple
static PyObject * entuple(PyObject *o) {
  PyObject *tup = PyTuple_New(1);
  if (!tup) { return NULL; }
  PyTuple_SET_ITEM(tup, 0, o);
  return tup;
}

static PyObject * n_close(register nflogobject *n, PyObject *) {
  NFLOG_CHECK(n, NULL);

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

// nflog getters/setters
static PyObject * n_get_drops(register nflogobject *n, void *) {
  NFLOG_CHECK(n, NULL);

  return Py_BuildValue("i", n->drops > 0 ? n->drops : 0);
}

static int n_set_drops(register nflogobject *n, PyObject *v, void *) {
  NFLOG_CHECK(n, -1);

  if (PyLong_AsLong(v) != 0) {
    PyErr_SetString(PyExc_TypeError, "drops can only be set to 0");
    return -1;
  }

  if (n->drops > 0) { n->drops = 0; }
  return 0;
}

static PyObject * n_get_rcvbuf(register nflogobject *n, void *) {
  NFLOG_CHECK(n, NULL);

  int opt;
  socklen_t len;
  if (n->fd < 0) {
    Py_RETURN_NONE;
  } else if (getsockopt(n->fd, SOL_SOCKET, SO_RCVBUF, &opt, &len) != 0) {
    PyErr_SetString(PyExc_OSError, "could not get rcvbuf");
    return NULL;
  }
  // the kernel doubles the set value, divide by two for the original
  return Py_BuildValue("i", opt / 2);
}

static int n_set_rcvbuf(register nflogobject *n, PyObject *v, void *) {
  NFLOG_CHECK(n, -1);

  long rcvbuf = PyLong_AsLong(v);
  if (rcvbuf == -1 && _GIL_PyErr_Occurred()) { return -1; }
  if (nflo_set_rcvbuf(n->h, n->gh, rcvbuf) != 0) { return -1; }
  return 0;
}

// nflog getters without setters
static PyObject * n_get_queued(register nflogobject *n, void *) {
  NFLOG_CHECK(n, NULL);

  if (n->head) { Py_RETURN_TRUE; } else { Py_RETURN_FALSE; }
}

static PyMappingMethods n_mapping = {
  (lenfunc)fifo_len,         /* mp_length */
};

static PyMethodDef n_methods[] = {
  {"next", (PyCFunction) n_next, METH_VARARGS, PyDoc_STR(
      "next($self, wait=True, /)\n"
      "--\n\n"
      "return next message"
  )},
  {"loop", (PyCFunction) n_loop, METH_VARARGS, PyDoc_STR(
      "loop($self, fn, count=-1, /)\n"
      "--\n\n"
      "process `count` (-1 meaning 'infinite') messages in a loop,"
      "passing each to callback function `fn`"
  )},
  {"close", (PyCFunction) n_close, METH_NOARGS, PyDoc_STR(
      "close($self, /)\n"
      "--\n\n"
      "close the socket"
  )},
  {"getfd", (PyCFunction) n_getfd, METH_NOARGS, PyDoc_STR(
      "getfd($self, /)\n"
      "--\n\n"
      "get selectable nflog fd"
  )},
  {"getgroup", (PyCFunction) n_getgroup, METH_NOARGS, PyDoc_STR(
      "getgroup($self, /)\n"
      "--\n\n"
      "get nflog group id"
  )},
  {"_raw", (PyCFunction) n__raw, METH_VARARGS, PyDoc_STR(
      "_raw($self, value=None, /)\n"
      "--\n\n"
      "INTENDED FOR DEBUGGING/TESTING ONLY!\n\n"
      "query/enable/disable capture of raw nflog data"
  )},
  {"_recv_raw", (PyCFunction) n__recv_raw, METH_NOARGS, PyDoc_STR(
      "_recv_raw($self, /)\n"
      "--\n\n"
      "INTENDED FOR DEBUGGING/TESTING ONLY!\n\n"
      "receive raw nflog data"
  )},
  {"fileno", (PyCFunction) n_fileno, METH_NOARGS, PyDoc_STR(
      "fileno($self, /)\n"
      "--\n\n"
      "Returns underlying file descriptor if one exists."
  )},
  {"__enter__", (PyCFunction) n__enter__, METH_NOARGS, NULL},
  {"__exit__", (PyCFunction) n_close, METH_VARARGS, NULL},
  {NULL, NULL} /* sentinel */
};

// all getters return new references
static PyGetSetDef n_getset[] = {
  {"rcvbuf", (getter)n_get_rcvbuf, (setter)n_set_rcvbuf, NULL, NULL},
  {"drops",  (getter)n_get_drops,  (setter)n_set_drops,  NULL, NULL},
  {"queued", (getter)n_get_queued, NULL, NULL, NULL},
  {NULL}
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
  &n_mapping,                /* tp_as_mapping */
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
  n_getset,                  /* tp_getset */
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
  PyObject *devnames = NULL;

  if (n->raw && !(devnames = PyDict_New())) { return -1; }
  return fifo_push(n, new_nflogdataobject(nfad, devnames));
}

PyObject * new_nflogobject(struct nflog_handle *h, struct nflog_g_handle *gh, int group, int enobufs) {
  if (PyType_Ready(&Nflogtype) != 0) { return NULL; }

  nflogobject *n = PyObject_New(nflogobject, &Nflogtype);
  if (!n) { return NULL; }

  // initialize values
  n->h = h; n->gh = gh;
  n->group = group;
  n->mock = NULL;
  n->head = n->tail = NULL;
  n->drops = (enobufs == NFLOGR_ENOBUFS_RAISE ? -1 : 0);
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
  nflogobject *n = (nflogobject *)new_nflogobject(NULL, NULL, -1, -1);
  n->mock = iter;
  Py_INCREF(iter);
  return (PyObject *)n;
}

// return exactly one nflogdata object, calling recv if needed
static PyObject * _recv(register nflogobject *n, int wait) {
  NFLOG_CHECK(n);

  PyObject *list, *item, *nd, *ret;
  char buf[16384];
  int rv, i, flags = wait ? 0 : MSG_DONTWAIT;
  Py_ssize_t count;

  for (int retry = 0; retry < RECV_RETRY_LIMIT; ++retry) {
    if ((ret = fifo_shift(n)) != Py_None) {
      return ret;
    } else if (n->mock) {
      // inject raw data from an iterator
      if ((list = PyIter_Next(n->mock))) {
        for (i = 0, count = PyList_Size(list); i < count; ++i) {
          item = PyList_GetItem(list, i);
          nd = NflogDatatype.tp_new(&NflogDatatype, item, Py_None);
          if (!nd || fifo_push(n, nd) != 0) {
            Py_DECREF(list);
            return NULL;
          }
        }
        Py_DECREF(list);
        continue;
      } else if (_GIL_PyErr_Occurred()) {
        return NULL;
      }

      n->mock = NULL;
      continue;
    } else if (!(n->h) || !(n->gh) || n->fd == -2) {
      PyErr_SetString(NflogClosedError, "nflog is closed");
      return NULL;
    } else if ((rv = recv(n->fd, buf, sizeof(buf), flags)) >= 0) {
      /*
      fprintf(stderr, "recv(%d): ", rv);
      for (int i = 0; i < rv; ++i) {
        fprintf(stderr, "%02x", (unsigned char)buf[i]);
      }
      fprintf(stderr, "\n");//*/
      // regularly returns non-fatal errors, so don't check return, and it can
      // sometimes process zero packets for some reason
      nflog_handle_packet(n->h, buf, rv);
      continue;
    } else if (errno == ENOBUFS) {
      if (n->enobufs < 0) {
        PyErr_SetString(NflogDroppedError, "packets were dropped (ENOBUFS)");
        return NULL;
      }
      n->enobufs++;
    } else if (errno == EWOULDBLOCK) {
      // handle nonblocking socket
      Py_RETURN_NONE;
    } else {
      // PyErr_Format was segfaulting when ctrl-c was hit
      char err[256];
      snprintf(err, sizeof(err),
        "recv() on nflog fd %d failed: %s (%d)",
        n->fd, strerror(errno), errno
      );
      PyErr_SetString(PyExc_OSError, err);
      return NULL;
    }
  }

  PyErr_SetString(NflogRetryError, "_recv stuck in a loop?");
  return NULL;
}

static PyObject * n__recv_raw(register nflogobject *n, PyObject *) {
  NFLOG_CHECK(n, NULL);

  fifo_empty(n);
  n->raw = 1;

  PyObject *nd, *raw, *list;
  if (!(list = PyList_New(0))) { return NULL; }

  if (!(nd = _recv(n, 1))) { goto n__recv_raw_cleanup; }

  do {
    if (nd == Py_None) { return list; }
    raw = nd__get_raw_impl(nd, Py_None);
    Py_DECREF(nd);
    if (!raw || PyList_Append(list, raw) != 0) { goto n__recv_raw_cleanup; }
  } while ((nd = fifo_shift(n)) != NULL);

n__recv_raw_cleanup:
  Py_DECREF(list);
  return NULL;
}

static PyObject * n_next(register nflogobject *n, PyObject *args) {
  NFLOG_CHECK(n, NULL);

  int wait = 1;
  if (!PyArg_ParseTuple(args, "|p:next", &wait)) { return NULL; }
  return _recv(n, wait);
}

static PyObject * n_loop(register nflogobject *n, PyObject *args) {
  NFLOG_CHECK(n, NULL);

  int cnt = -1;
  PyObject *nd, *PyFn;

  if (!PyArg_ParseTuple(args, "O|i:loop", &PyFn, &cnt)) {
    return NULL;
  } else if (!PyCallable_Check(PyFn)) {
    PyErr_SetString(PyExc_TypeError, "argument must be callable");
    return NULL;
  }

  while (cnt != 0) {
    if (!(nd = _recv(n, 1))) { return nd; }

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
  NFLOG_CHECK(n, NULL);

  if (n->fd >= 0) {
    return Py_BuildValue("i", n->fd);
  } else {
    Py_RETURN_NONE;
  }
}

static PyObject * n_fileno(register nflogobject *n, PyObject *) {
  NFLOG_CHECK(n, NULL);

  if (n->fd >= 0) {
    return Py_BuildValue("i", n->fd);
  } else {
    PyErr_SetString(PyExc_ValueError, "I/O operation on closed handle");
    return NULL;
  }
}

static PyObject * n_getgroup(register nflogobject *n, PyObject *) {
  NFLOG_CHECK(n, NULL);

  if (n->group >= 0) {
    return Py_BuildValue("i", n->group);
  } else {
    Py_RETURN_NONE;
  }
}

static PyObject * n__raw(register nflogobject *n, PyObject *args) {
  NFLOG_CHECK(n, NULL);

  PyObject *value = Py_None;

  PyArg_ParseTuple(args, "|O:_raw", &value);
  if (_nflogr_tristate(value, &(n->raw)) != 0) { return NULL; }

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
  NFLOG_CHECK(n, NULL);

  PyObject *nd;
  if (!(nd = _recv(n, 1))) {
    PyObject *et = _GIL_PyErr_Occurred();
    if (et) {
      if (PyErr_GivenExceptionMatches(et, NflogClosedError)) {
        PyErr_SetNone(PyExc_StopIteration);
      }
    }
    return NULL;
  }

  return nd;
}

/*  vim: set ts=2 sw=2 et ai si: */
