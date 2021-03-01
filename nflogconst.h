/* Copyright 2021 Ryan Castellucci, MIT License */

#ifndef __nflogconst_h__
#define __nflogconst_h__

int nflog_add_protos(PyObject *dict);
int nflog_add_hwtypes(PyObject *dict);

#define ADDINTCONST(M, N, V) \
	if (PyModule_AddIntConstant(M, N, V) != 0) { \
		return -1; \
	}

#endif//__nflogconst_h__
