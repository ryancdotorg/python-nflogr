/* Copyright 2021 Ryan Castellucci, MIT License */

#ifndef __nflogdata_h__
#define __nflogdata_h__

PyObject * new_nflogdataobject(struct nflog_data *nfad, PyObject *dict);
PyObject * nd__get_raw_impl(PyObject *o, PyObject *pyuseraw);

extern PyTypeObject NflogDatatype;
extern PyTypeObject NflogDataItertype;

#endif//__nflogdata_h__
