/* Copyright 2021 Ryan Castellucci, MIT License */

#ifndef __nflogr_h__
#define __nflogr_h__

extern "C" {
PyObject * PyInit_nflog(void);
}

// helpers
int _nflogr_tristate(PyObject *o, int *x);

// exception objects
extern PyObject *NflogError;
extern PyObject *NflogClosedError;

#endif//__nflogr_h__
