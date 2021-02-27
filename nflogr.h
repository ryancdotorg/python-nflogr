/* Copyright 2021 Ryan Castellucci, MIT License */

#ifndef __nflogr__
#define __nflogr__

extern "C" {
PyObject * PyInit_nflog(void);
}

// exception objects
extern PyObject *NflogError;
extern PyObject *NflogClosedError;

#endif//__nflogr__
