/* Copyright 2021 Ryan Castellucci, MIT License */

#ifndef __nflogdata_h__
#define __nflogdata_h__

PyObject * new_nflogdataobject(struct nflog_data *nfad, int raw);

extern PyTypeObject NflogDatatype;
extern PyTypeObject NflogDataItertype;

#endif//__nflogdata_h__
