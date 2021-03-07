/* Copyright 2021 Ryan Castellucci, MIT License */

#include <Python.h>

int nflog_add_hwtypes(PyObject *m) {
  if (!m) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_NETROM", 0) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_ETHER", 1) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_EETHER", 2) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_AX25", 3) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_PRONET", 4) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_CHAOS", 5) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_IEEE802", 6) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_ARCNET", 7) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_APPLETLK", 8) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_DLCI", 15) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_ATM", 19) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_METRICOM", 23) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_IEEE1394", 24) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_EUI64", 27) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_INFINIBAND", 32) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_SLIP", 256) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_CSLIP", 257) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_SLIP6", 258) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_CSLIP6", 259) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_RSRVD", 260) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_ADAPT", 264) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_ROSE", 270) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_X25", 271) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_HWX25", 272) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_CAN", 280) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_PPP", 512) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_CISCO", 513) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_HDLC", 513) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_LAPB", 516) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_DDCMP", 517) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_RAWHDLC", 518) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_RAWIP", 519) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_TUNNEL", 768) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_TUNNEL6", 769) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_FRAD", 770) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_SKIP", 771) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_LOOPBACK", 772) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_LOCALTLK", 773) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_FDDI", 774) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_BIF", 775) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_SIT", 776) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_IPDDP", 777) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_IPGRE", 778) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_PIMREG", 779) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_HIPPI", 780) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_ASH", 781) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_ECONET", 782) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_IRDA", 783) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_FCPP", 784) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_FCAL", 785) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_FCPL", 786) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_FCFABRIC", 787) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_IEEE802_TR", 800) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_IEEE80211", 801) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_IEEE80211_PRISM", 802) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_IEEE80211_RADIOTAP", 803) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_IEEE802154", 804) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_IEEE802154_MONITOR", 805) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_PHONET", 820) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_PHONET_PIPE", 821) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_CAIF", 822) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_IP6GRE", 823) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_NETLINK", 824) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_6LOWPAN", 825) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_VSOCKMON", 826) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_VOID", 0xFFFF) != 0) { return -1; }
  if (PyModule_AddIntConstant(m, "HWTYPE_NONE", 0xFFFE) != 0) { return -1; }
  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
