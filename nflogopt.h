/* Copyright 2021 Ryan Castellucci, MIT License */

#ifndef __nflogopt_h__
#define __nflogopt_h__

#define NFLO_SETTER_DEF(T, N, F, MIN, MAX) \
int nflo_validate_ ## N(T __val); \
int nflo_set_ ## N(struct nflog_handle *h, struct nflog_g_handle *gh, T N);

NFLO_SETTER_DEF(int, group, "%d", 0, 65535)
NFLO_SETTER_DEF(double, timeout, "%.2f", 0, 42949672.951)
NFLO_SETTER_DEF(long long, qthresh, "%lld", 0, 4294967295)
NFLO_SETTER_DEF(int, rcvbuf, "%d", 0, 1073741823)
NFLO_SETTER_DEF(long long, nlbuf, "%lld", 0, 4294967295)
NFLO_SETTER_DEF(unsigned char, enobufs, "ENOBUFS_RAISE, ENOBUFS_HANDLE, or ENOBUFS_DISABLE", NFLOGR_ENOBUFS_RAISE, NFLOGR_ENOBUFS_DISABLE)
NFLO_SETTER_DEF(unsigned char, copymode, "COPY_NONE, COPY_META, or COPY_PACKET", NFULNL_COPY_NONE, NFULNL_COPY_PACKET)

#endif//__nflogopt_h__

/* vim: set ts=2 sw=2 et ai si: */
