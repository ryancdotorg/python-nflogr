/* Copyright 2021 Ryan Castellucci, MIT License */

#ifndef __nflogr_h__
#define __nflogr_h__

extern "C" {
PyObject * PyInit_nflog(void);
}

#define NFLOGR_ENOBUFS_RAISE 0
#define NFLOGR_ENOBUFS_HANDLE 1
#define NFLOGR_ENOBUFS_DISABLE 2

// exception objects
extern PyObject *NflogError;
extern PyObject *NflogRetryError;
extern PyObject *NflogDroppedError;
extern PyObject *NflogClosedError;

#ifndef NFLOGR_DEBUG
#define NFLOGR_DEBUG 1
#endif
#define nfldbg(FMT, ...) do { \
	if (NFLOGR_DEBUG) { \
		fprintf(stderr, "DEBUG(nflogr %s:%s:%d) " FMT, \
			__FILE__, __func__, __LINE__, __VA_ARGS__ \
		); \
	} \
} while (0)

#define NFLOGR_PYERRNO(EXC, FMT, ...) do { \
	char buf[1024]; \
	snprintf(buf, sizeof(buf), FMT ": %s (%d)", \
		__VA_ARGS__, strerror(errno), errno \
	); \
	PyErr_SetString(EXC, buf); \
} while (0)

// helpers
int _nflogr_tristate(PyObject *o, int *x);
PyObject * _GIL_PyErr_Occurred();

#endif//__nflogr_h__
