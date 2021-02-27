/* Copyright 2021 Ryan Castellucci, MIT License */

#ifndef __nflog_h__
#define __nflog_h__

PyObject * mock_nflogobject(PyObject *iter);
PyObject * new_nflogobject(struct nflog_handle *h, struct nflog_g_handle *gh, int group);

extern PyTypeObject Nflogtype;

#endif//__nflog_h__
