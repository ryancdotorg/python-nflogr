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
  int queued;
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

// walk the fifo for size, can't fail under any reasonable circumstances
static Py_ssize_t fifo_len(nflogobject *n) {
  Py_ssize_t len = 0;

#if NFLOGR_DEBUG
  if (n->tail && n->tail->next) {
    nfldbg("n->tail->next:%p != (nil)\n", n->tail->next);
  }
#endif

  fifo_t *node = n->head;
  while (node) {
#if NFLOGR_DEBUG
  if (node->next == NULL && node != n->tail) {
    nfldbg("node:%p != n->tail:%p\n", node, n->tail);
  }
#endif
    node = node->next;
    ++len;
  }

#if NFLOGR_DEBUG
  if (len != n->queued) {
    nfldbg("len:%zd != n->queued:%d\n", len, n->queued);
  }
#endif

  return len;
}

// append to fifo, steals refrence to o, returns 0 on success, -1 on failure
static int fifo_push(nflogobject *n, PyObject *o) {
  fifo_t *entry;

  if (o == Py_None) {
    // don't push None
    return 0;
  } else if (!o) {
    // if we have a null pointer, something's gone very wrong
    return -1;
  } else if (!(entry = (fifo_t *)malloc(sizeof(fifo_t)))) {
    PyErr_NoMemory();
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

  n->queued++;
#if NFLOGR_DEBUG
  fifo_len(n);
#endif
  return 0;
}

// take from fifo, returns owned reference, can't fail
static PyObject * fifo_shift(nflogobject *n) {
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

  n->queued--;
#if NFLOGR_DEBUG
  fifo_len(n);
#endif
  return o;
}

// empties the fifo, decrementing refrence count of contained objects
static void fifo_empty(nflogobject *n) {
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

static PyObject * n_close(nflogobject *n, PyObject *) {
  NFLOG_CHECK(n, NULL);

  if (n->gh) { nflog_unbind_group(n->gh); }
  if (n->h) { nflog_close(n->h); }
  if (n->mock) {
    Py_DECREF(n->mock);
    n->mock = NULL;
  }

  // clear references
  n->h = NULL; n->gh = NULL;
  n->fd = -2;

  Py_RETURN_NONE;
}

static void nflog_dealloc(nflogobject *n) {
  n_close(n, NULL);
  fifo_empty(n);
  PyObject_Del(n);
}

// nflog methods
static PyObject * n_queue(nflogobject *n, PyObject *args);
static PyObject * n_next(nflogobject *n, PyObject *args);
static PyObject * n_loop(nflogobject *n, PyObject *args);
static PyObject * n_getfd(nflogobject *n, PyObject *);
static PyObject * n_getgroup(nflogobject *n, PyObject *);
static PyObject * n_fileno(nflogobject *n, PyObject *);
static PyObject * n__raw(nflogobject *n, PyObject *args);
static PyObject * n__recv_raw(nflogobject *n, PyObject *);
static PyObject * n__enter__(nflogobject *n, PyObject *);
static PyObject * n__iter__(nflogobject *n);
static PyObject * n__next__(nflogobject *n);

// nflog getters/setters
static PyObject * n_get_drops(nflogobject *n, void *) {
  NFLOG_CHECK(n, NULL);

  return Py_BuildValue("i", n->drops > 0 ? n->drops : 0);
}

static int n_set_drops(nflogobject *n, PyObject *v, void *) {
  NFLOG_CHECK(n, -1);

  if (PyLong_AsLong(v) != 0) {
    PyErr_SetString(PyExc_TypeError, "drops can only be set to 0");
    return -1;
  }

  if (n->drops > 0) { n->drops = 0; }
  return 0;
}

static PyObject * n_get_rcvbuf(nflogobject *n, void *) {
  NFLOG_CHECK(n, NULL);

  int opt = -2;
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

static int n_set_rcvbuf(nflogobject *n, PyObject *v, void *) {
  NFLOG_CHECK(n, -1);

  long rcvbuf = PyLong_AsLong(v);
  if (rcvbuf == -1 && _GIL_PyErr_Occurred()) { return -1; }
  if (nflo_set_rcvbuf(n->h, n->gh, rcvbuf) != 0) { return -1; }
  return 0;
}

// nflog getters without setters
static PyObject * n_get_queued(nflogobject *n, void *) {
  NFLOG_CHECK(n, NULL);

  if (n->head) { Py_RETURN_TRUE; } else { Py_RETURN_FALSE; }
}

static PyMappingMethods n_mapping = {
  (lenfunc)fifo_len,         /* mp_length */
};

static PyMethodDef n_methods[] = {
  {"queue", (PyCFunction) n_queue, METH_VARARGS, PyDoc_STR(
      "queue($self, wait=True, /)\n"
      "--\n\n"
      "queues any messages waiting on the socket, returns number queued"
  )},
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

static int NflogQueue(struct nflog_g_handle *, struct nfgenmsg *,
struct nflog_data *nfad, void *data) {
  nflogobject *n = (nflogobject *)data;
  PyObject *devnames = NULL;

  if (n->raw && !(devnames = PyDict_New())) { return -1; }
  return fifo_push(n, new_nflogdataobject(nfad, devnames));
}

PyObject * new_nflogobject(struct nflog_handle *h, struct nflog_g_handle *gh,
int group, int enobufs) {
  if (PyType_Ready(&Nflogtype) != 0) { return NULL; }

  nflogobject *n = PyObject_New(nflogobject, &Nflogtype);
  if (!n) { return NULL; }

  // initialize values
  n->h = h; n->gh = gh;
  n->group = group;
  n->mock = NULL;
  n->head = n->tail = NULL;
  n->queued = 0;
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

// queue received packets (if any), returns number queued or -1 on error
static int _queue(nflogobject *n, int wait) {
  // we don't need to try to receive for closed handles
  if (n->fd == -2 || !(n->h) || !(n->gh)) { return 0; }

  int queued = n->queued;
  if (!(n->mock)) {
    // handle real data
    int rv;
    char buf[16384];

    // only wait if the flag is requested *and* there's nothing queued
    int recv_flags = (wait && !(n->head)) ? 0 : MSG_DONTWAIT;
    if ((rv = recv(n->fd, buf, sizeof(buf), recv_flags)) >= 0) {
      /*
      fprintf(stderr, "recv(%d): ", rv);
      for (int i = 0; i < rv; ++i) {
        fprintf(stderr, "%02x", (unsigned char)buf[i]);
      }
      fprintf(stderr, "\n");//*/
      // regularly returns non-fatal errors, so don't check return, and it can
      // sometimes process zero packets for some reason
      nflog_handle_packet(n->h, buf, rv);
    } else if (errno == ENOBUFS) {
      if (n->drops < 0) {
        PyErr_SetString(NflogDroppedError, "packets were dropped (ENOBUFS)");
        return -1;
      }
      n->drops++;
    } else if (errno != EWOULDBLOCK) {  // EWOULDBLOCK == EAGAIN
      // PyErr_Format was segfaulting when ctrl-c was hit
      NFLOGR_PYERRNO(PyExc_OSError, "recv() on fd %d failed", n->fd);
      return -1;
    }
  } else {
    // handle mock connection
    PyObject *nd, *list, *item;

    // inject raw data from an iterator
    if ((list = PyIter_Next(n->mock))) {
      // batch queue each item in the list
      for (Py_ssize_t i = 0, count = PyList_Size(list); i < count; ++i) {
        item = PyList_GetItem(list, i);
        nd = NflogDatatype.tp_new(&NflogDatatype, item, Py_None);
        if (!nd || fifo_push(n, nd) != 0) {
          Py_DECREF(list);
          return -1;
        }
      }
      Py_DECREF(list);
    } else {
      // fail if an exception is set - PyIter_Next just returns NULL without
      // raising StopIteration when it runs out of items.
      if (_GIL_PyErr_Occurred()) { return -1; }

      // no more data from iterator
      n_close(n, NULL);
      return 0;
    }
  }

  return n->queued - queued;
}

// return exactly one nflogdata object (or None)
static PyObject * _next(nflogobject *n, int wait) {
  for (int retry = 0; retry < RECV_RETRY_LIMIT; ++retry) {
    PyObject *nd;
    int rv;
    if ((rv = _queue(n, wait)) < 0) { return NULL; }

    if ((nd = fifo_shift(n)) != Py_None) {
      return nd;
    } else if (!wait) {
      Py_RETURN_NONE;
    }
  }

  PyErr_SetString(NflogRetryError, "_queue stuck in a loop?");
  return NULL;
}

static PyObject * n__recv_raw(nflogobject *n, PyObject *) {
  NFLOG_CHECK(n, NULL);

  fifo_empty(n);
  n->raw = 1;

  PyObject *list, *nd = NULL, *raw = NULL;
  if (!(list = PyList_New(0))) { return NULL; }

  if (_queue(n, 1) < 0) { goto n__recv_raw_cleanup; }

  while ((nd = fifo_shift(n)) != NULL) {
    if (nd == Py_None) {
      Py_DECREF(nd);
      return list;
    }

    raw = nd__get_raw_impl(nd, Py_True);
    Py_DECREF(nd);
    if (!raw || PyList_Append(list, raw) != 0) { goto n__recv_raw_cleanup; }
  }

n__recv_raw_cleanup:
  Py_XDECREF(raw);  // XXX should this be here?
  Py_XDECREF(nd);
  Py_DECREF(list);
  return NULL;
}

static PyObject * n_queue(nflogobject *n, PyObject *args) {
  NFLOG_CHECK(n, NULL);

  int queued, wait = 1;
  if (!PyArg_ParseTuple(args, "|p:queue", &wait)) { return NULL; }
  if ((queued = _queue(n, wait)) < 0) { return NULL; }
  return Py_BuildValue("i", queued);
}

static PyObject * n_next(nflogobject *n, PyObject *args) {
  NFLOG_CHECK(n, NULL);

  int wait = 1;
  if (!PyArg_ParseTuple(args, "|p:next", &wait)) { return NULL; }
  return _next(n, wait);
}

static PyObject * n_loop(nflogobject *n, PyObject *args) {
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
    if (!(nd = _next(n, 1))) { return nd; }

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

static PyObject * n_getfd(nflogobject *n, PyObject *) {
  NFLOG_CHECK(n, NULL);

  if (n->fd >= 0) {
    return Py_BuildValue("i", n->fd);
  } else {
    Py_RETURN_NONE;
  }
}

static PyObject * n_fileno(nflogobject *n, PyObject *) {
  NFLOG_CHECK(n, NULL);

  if (n->fd >= 0) {
    return Py_BuildValue("i", n->fd);
  } else {
    PyErr_SetString(PyExc_ValueError, "I/O operation on closed handle");
    return NULL;
  }
}

static PyObject * n_getgroup(nflogobject *n, PyObject *) {
  NFLOG_CHECK(n, NULL);

  if (n->group >= 0) {
    return Py_BuildValue("i", n->group);
  } else {
    Py_RETURN_NONE;
  }
}

static PyObject * n__raw(nflogobject *n, PyObject *args) {
  NFLOG_CHECK(n, NULL);

  PyObject *value = Py_None;

  PyArg_ParseTuple(args, "|O:_raw", &value);
  if (_nflogr_tristate(value, &(n->raw)) != 0) { return NULL; }

  return PyBool_FromLong(n->raw);
}

static PyObject * n__enter__(nflogobject *n, PyObject *) {
  Py_INCREF(n);
  return (PyObject *)n;
}

static PyObject * n__iter__(nflogobject *n) {
  Py_INCREF(n);
  return (PyObject *)n;
}

static PyObject * n__next__(nflogobject *n) {
  NFLOG_CHECK(n, NULL);

  PyObject *nd;
  if (!(nd = _next(n, 1))) {
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
