/* Copyright 2021 Ryan Castellucci, MIT License */

#include <Python.h>

#include <netinet/in.h>

extern "C" {
#include <libnetfilter_log/libnetfilter_log.h>
}

#include "nflogr.h"
#include "nflog.h"
#include "nflogdata.h"

PyObject *NflogError;
PyObject *NflogClosedError;

static PyObject * l_open(PyObject *self, PyObject *args) {
  int group;

  if (!PyArg_ParseTuple(args, "i:open", &group)) {
    PyErr_SetString(PyExc_TypeError, "group must be an integer");
    return NULL;
  } else if (group < 0 || group > 65535) {
    PyErr_SetString(PyExc_ValueError, "valid group range is [0,65535]");
    return NULL;
  }

  struct nflog_handle *h;
  struct nflog_g_handle *gh;

  if (!(h = nflog_open())) {
    PyErr_SetString(PyExc_PermissionError, "could not get nflog handle");
    return NULL;
  }
  if (nflog_bind_pf(h, AF_INET) < 0) {
    nflog_close(h);
    PyErr_SetString(PyExc_PermissionError, "could not bind protocol family (are you root?)");
    return NULL;
  }
  if (!(gh = nflog_bind_group(h, group))) {
    nflog_close(h);
    PyErr_SetString(PyExc_OSError, "could not get group handle");
    return NULL;
  }
  if (nflog_set_mode(gh, NFULNL_COPY_PACKET, 0xffff) < 0) {
    nflog_unbind_group(gh);
    nflog_close(h);
    PyErr_SetString(PyExc_PermissionError, "could not set packet copy mode");
    return NULL;
  }

  return new_nflogobject(h, gh, group);
}

static PyObject * l__from_iter(PyObject *self, PyObject *args) {
  PyObject *iter;

  if (!PyArg_ParseTuple(args, "O:_from_iter", &iter) || !PyIter_Check(iter)) {
    PyErr_SetString(PyExc_TypeError, "iter must be an interator");
    return NULL;
  }

  return mock_nflogobject(iter);
}

static PyMethodDef nflogrMethods[] = {
  {"open", l_open, METH_VARARGS, PyDoc_STR(
    "open(group)\n"
    "--\n\n"
    "Open an nflog listener for the specifed group."
  )},
  {"_from_iter", l__from_iter, METH_VARARGS, PyDoc_STR(
    "_from_iter(iterator)\n"
    "--\n\n"
    "Open a mock nflog 'listener' which pulls messages from an iterator.\n"
    "INTENDED FOR DEBUGGING/TESTING ONLY!"
  )},
  {NULL, NULL} /* sentinel */
};

static struct PyModuleDef nflogr_module = {
  PyModuleDef_HEAD_INIT,
  "nflog",
  "Interface for accessing nflog.",
  0,  // m_size - this module has no state
  nflogrMethods
};

#define MOD_ADD_OBJ(M, N, O) \
  do { \
    Py_INCREF(O); \
    if (PyModule_AddObject(M, N, (PyObject *)(O)) < 0) { \
      Py_DECREF(M); \
      Py_DECREF(O); \
      return NULL; \
    } \
  } while (0);

PyMODINIT_FUNC PyInit_nflogr(void) {
  PyObject *m;

  m = PyModule_Create(&nflogr_module);

  NflogError = PyErr_NewException("nflogr.NflogError", PyExc_Exception, NULL);
  MOD_ADD_OBJ(m, "NflogError", NflogError);

  NflogClosedError = PyErr_NewException("nflogr.NflogClosedError", NflogError, NULL);
  MOD_ADD_OBJ(m, "NflogClosedError", NflogClosedError);

  if (PyType_Ready(&Nflogtype) < 0) { return NULL; }
  MOD_ADD_OBJ(m, _PyType_Name(&Nflogtype), &Nflogtype);

  if (PyType_Ready(&NflogDatatype) < 0) { return NULL; }
  MOD_ADD_OBJ(m, _PyType_Name(&NflogDatatype), &NflogDatatype);

  // fgrep ARPHRD_ /usr/include/net/if_arp.h | perl -pe 's/.+ARPHRD_(\S+)\s+(\S+).*/  PyModule_AddIntConstant(m, "HWTYPE_$1", $2);/'
  PyModule_AddIntConstant(m, "HWTYPE_NETROM", 0);
  PyModule_AddIntConstant(m, "HWTYPE_ETHER", 1);
  PyModule_AddIntConstant(m, "HWTYPE_EETHER", 2);
  PyModule_AddIntConstant(m, "HWTYPE_AX25", 3);
  PyModule_AddIntConstant(m, "HWTYPE_PRONET", 4);
  PyModule_AddIntConstant(m, "HWTYPE_CHAOS", 5);
  PyModule_AddIntConstant(m, "HWTYPE_IEEE802", 6);
  PyModule_AddIntConstant(m, "HWTYPE_ARCNET", 7);
  PyModule_AddIntConstant(m, "HWTYPE_APPLETLK", 8);
  PyModule_AddIntConstant(m, "HWTYPE_DLCI", 15);
  PyModule_AddIntConstant(m, "HWTYPE_ATM", 19);
  PyModule_AddIntConstant(m, "HWTYPE_METRICOM", 23);
  PyModule_AddIntConstant(m, "HWTYPE_IEEE1394", 24);
  PyModule_AddIntConstant(m, "HWTYPE_EUI64", 27);
  PyModule_AddIntConstant(m, "HWTYPE_INFINIBAND", 32);
  PyModule_AddIntConstant(m, "HWTYPE_SLIP", 256);
  PyModule_AddIntConstant(m, "HWTYPE_CSLIP", 257);
  PyModule_AddIntConstant(m, "HWTYPE_SLIP6", 258);
  PyModule_AddIntConstant(m, "HWTYPE_CSLIP6", 259);
  PyModule_AddIntConstant(m, "HWTYPE_RSRVD", 260);
  PyModule_AddIntConstant(m, "HWTYPE_ADAPT", 264);
  PyModule_AddIntConstant(m, "HWTYPE_ROSE", 270);
  PyModule_AddIntConstant(m, "HWTYPE_X25", 271);
  PyModule_AddIntConstant(m, "HWTYPE_HWX25", 272);
  PyModule_AddIntConstant(m, "HWTYPE_PPP", 512);
  PyModule_AddIntConstant(m, "HWTYPE_CISCO", 513);
  PyModule_AddIntConstant(m, "HWTYPE_HDLC", 513);
  PyModule_AddIntConstant(m, "HWTYPE_LAPB", 516);
  PyModule_AddIntConstant(m, "HWTYPE_DDCMP", 517);
  PyModule_AddIntConstant(m, "HWTYPE_RAWHDLC", 518);
  PyModule_AddIntConstant(m, "HWTYPE_RAWIP", 519);
  PyModule_AddIntConstant(m, "HWTYPE_TUNNEL", 768);
  PyModule_AddIntConstant(m, "HWTYPE_TUNNEL6", 769);
  PyModule_AddIntConstant(m, "HWTYPE_FRAD", 770);
  PyModule_AddIntConstant(m, "HWTYPE_SKIP", 771);
  PyModule_AddIntConstant(m, "HWTYPE_LOOPBACK", 772);
  PyModule_AddIntConstant(m, "HWTYPE_LOCALTLK", 773);
  PyModule_AddIntConstant(m, "HWTYPE_FDDI", 774);
  PyModule_AddIntConstant(m, "HWTYPE_BIF", 775);
  PyModule_AddIntConstant(m, "HWTYPE_SIT", 776);
  PyModule_AddIntConstant(m, "HWTYPE_IPDDP", 777);
  PyModule_AddIntConstant(m, "HWTYPE_IPGRE", 778);
  PyModule_AddIntConstant(m, "HWTYPE_PIMREG", 779);
  PyModule_AddIntConstant(m, "HWTYPE_HIPPI", 780);
  PyModule_AddIntConstant(m, "HWTYPE_ASH", 781);
  PyModule_AddIntConstant(m, "HWTYPE_ECONET", 782);
  PyModule_AddIntConstant(m, "HWTYPE_IRDA", 783);
  PyModule_AddIntConstant(m, "HWTYPE_FCPP", 784);
  PyModule_AddIntConstant(m, "HWTYPE_FCAL", 785);
  PyModule_AddIntConstant(m, "HWTYPE_FCPL", 786);
  PyModule_AddIntConstant(m, "HWTYPE_FCFABRIC", 787);
  PyModule_AddIntConstant(m, "HWTYPE_IEEE802_TR", 800);
  PyModule_AddIntConstant(m, "HWTYPE_IEEE80211", 801);
  PyModule_AddIntConstant(m, "HWTYPE_IEEE80211_PRISM", 802);
  PyModule_AddIntConstant(m, "HWTYPE_IEEE80211_RADIOTAP", 803);
  PyModule_AddIntConstant(m, "HWTYPE_IEEE802154", 804);
  PyModule_AddIntConstant(m, "HWTYPE_IEEE802154_PHY", 805);
  PyModule_AddIntConstant(m, "HWTYPE_VOID", 0xFFFF);
  PyModule_AddIntConstant(m, "HWTYPE_NONE", 0xFFFE);

  // fgrep ETH_P_ /usr/include/linux/if_ether.h | perl -pe 's/.+ETH_P_(\S+)\s+(\S+).*/  PyModule_AddIntConstant(m, "PROTO_$1", $2);/'
  PyModule_AddIntConstant(m, "PROTO_LOOP", 0x0060);
  PyModule_AddIntConstant(m, "PROTO_PUP", 0x0200);
  PyModule_AddIntConstant(m, "PROTO_PUPAT", 0x0201);
  PyModule_AddIntConstant(m, "PROTO_TSN", 0x22F0);
  PyModule_AddIntConstant(m, "PROTO_ERSPAN2", 0x22EB);
  PyModule_AddIntConstant(m, "PROTO_IP", 0x0800);
  PyModule_AddIntConstant(m, "PROTO_X25", 0x0805);
  PyModule_AddIntConstant(m, "PROTO_ARP", 0x0806);
  PyModule_AddIntConstant(m, "PROTO_BPQ", 0x08FF);
  PyModule_AddIntConstant(m, "PROTO_IEEEPUP", 0x0a00);
  PyModule_AddIntConstant(m, "PROTO_IEEEPUPAT", 0x0a01);
  PyModule_AddIntConstant(m, "PROTO_BATMAN", 0x4305);
  PyModule_AddIntConstant(m, "PROTO_DEC", 0x6000);
  PyModule_AddIntConstant(m, "PROTO_DNA_DL", 0x6001);
  PyModule_AddIntConstant(m, "PROTO_DNA_RC", 0x6002);
  PyModule_AddIntConstant(m, "PROTO_DNA_RT", 0x6003);
  PyModule_AddIntConstant(m, "PROTO_LAT", 0x6004);
  PyModule_AddIntConstant(m, "PROTO_DIAG", 0x6005);
  PyModule_AddIntConstant(m, "PROTO_CUST", 0x6006);
  PyModule_AddIntConstant(m, "PROTO_SCA", 0x6007);
  PyModule_AddIntConstant(m, "PROTO_TEB", 0x6558);
  PyModule_AddIntConstant(m, "PROTO_RARP", 0x8035);
  PyModule_AddIntConstant(m, "PROTO_ATALK", 0x809B);
  PyModule_AddIntConstant(m, "PROTO_AARP", 0x80F3);
  PyModule_AddIntConstant(m, "PROTO_8021Q", 0x8100);
  PyModule_AddIntConstant(m, "PROTO_ERSPAN", 0x88BE);
  PyModule_AddIntConstant(m, "PROTO_IPX", 0x8137);
  PyModule_AddIntConstant(m, "PROTO_IPV6", 0x86DD);
  PyModule_AddIntConstant(m, "PROTO_PAUSE", 0x8808);
  PyModule_AddIntConstant(m, "PROTO_SLOW", 0x8809);
  PyModule_AddIntConstant(m, "PROTO_WCCP", 0x883E);
  PyModule_AddIntConstant(m, "PROTO_MPLS_UC", 0x8847);
  PyModule_AddIntConstant(m, "PROTO_MPLS_MC", 0x8848);
  PyModule_AddIntConstant(m, "PROTO_ATMMPOA", 0x884c);
  PyModule_AddIntConstant(m, "PROTO_PPP_DISC", 0x8863);
  PyModule_AddIntConstant(m, "PROTO_PPP_SES", 0x8864);
  PyModule_AddIntConstant(m, "PROTO_LINK_CTL", 0x886c);
  PyModule_AddIntConstant(m, "PROTO_ATMFATE", 0x8884);
  PyModule_AddIntConstant(m, "PROTO_PAE", 0x888E);
  PyModule_AddIntConstant(m, "PROTO_AOE", 0x88A2);
  PyModule_AddIntConstant(m, "PROTO_8021AD", 0x88A8);
  PyModule_AddIntConstant(m, "PROTO_802_EX1", 0x88B5);
  PyModule_AddIntConstant(m, "PROTO_PREAUTH", 0x88C7);
  PyModule_AddIntConstant(m, "PROTO_TIPC", 0x88CA);
  PyModule_AddIntConstant(m, "PROTO_MACSEC", 0x88E5);
  PyModule_AddIntConstant(m, "PROTO_8021AH", 0x88E7);
  PyModule_AddIntConstant(m, "PROTO_MVRP", 0x88F5);
  PyModule_AddIntConstant(m, "PROTO_1588", 0x88F7);
  PyModule_AddIntConstant(m, "PROTO_NCSI", 0x88F8);
  PyModule_AddIntConstant(m, "PROTO_PRP", 0x88FB);
  PyModule_AddIntConstant(m, "PROTO_FCOE", 0x8906);
  PyModule_AddIntConstant(m, "PROTO_IBOE", 0x8915);
  PyModule_AddIntConstant(m, "PROTO_TDLS", 0x890D);
  PyModule_AddIntConstant(m, "PROTO_FIP", 0x8914);
  PyModule_AddIntConstant(m, "PROTO_80221", 0x8917);
  PyModule_AddIntConstant(m, "PROTO_HSR", 0x892F);
  PyModule_AddIntConstant(m, "PROTO_NSH", 0x894F);
  PyModule_AddIntConstant(m, "PROTO_LOOPBACK", 0x9000);
  PyModule_AddIntConstant(m, "PROTO_QINQ1", 0x9100);
  PyModule_AddIntConstant(m, "PROTO_QINQ2", 0x9200);
  PyModule_AddIntConstant(m, "PROTO_QINQ3", 0x9300);
  PyModule_AddIntConstant(m, "PROTO_EDSA", 0xDADA);
  PyModule_AddIntConstant(m, "PROTO_IFE", 0xED3E);
  PyModule_AddIntConstant(m, "PROTO_AF_IUCV", 0xFBFB);
  PyModule_AddIntConstant(m, "PROTO_802_3_MIN", 0x0600);
  PyModule_AddIntConstant(m, "PROTO_802_3", 0x0001);
  PyModule_AddIntConstant(m, "PROTO_AX25", 0x0002);
  PyModule_AddIntConstant(m, "PROTO_ALL", 0x0003);
  PyModule_AddIntConstant(m, "PROTO_802_2", 0x0004);
  PyModule_AddIntConstant(m, "PROTO_SNAP", 0x0005);
  PyModule_AddIntConstant(m, "PROTO_DDCMP", 0x0006);
  PyModule_AddIntConstant(m, "PROTO_WAN_PPP", 0x0007);
  PyModule_AddIntConstant(m, "PROTO_PPP_MP", 0x0008);
  PyModule_AddIntConstant(m, "PROTO_LOCALTALK", 0x0009);
  PyModule_AddIntConstant(m, "PROTO_CAN", 0x000C);
  PyModule_AddIntConstant(m, "PROTO_CANFD", 0x000D);
  PyModule_AddIntConstant(m, "PROTO_PPPTALK", 0x0010);
  PyModule_AddIntConstant(m, "PROTO_TR_802_2", 0x0011);
  PyModule_AddIntConstant(m, "PROTO_MOBITEX", 0x0015);
  PyModule_AddIntConstant(m, "PROTO_CONTROL", 0x0016);
  PyModule_AddIntConstant(m, "PROTO_IRDA", 0x0017);
  PyModule_AddIntConstant(m, "PROTO_ECONET", 0x0018);
  PyModule_AddIntConstant(m, "PROTO_HDLC", 0x0019);
  PyModule_AddIntConstant(m, "PROTO_ARCNET", 0x001A);
  PyModule_AddIntConstant(m, "PROTO_DSA", 0x001B);
  PyModule_AddIntConstant(m, "PROTO_TRAILER", 0x001C);
  PyModule_AddIntConstant(m, "PROTO_PHONET", 0x00F5);
  PyModule_AddIntConstant(m, "PROTO_IEEE802154", 0x00F6);
  PyModule_AddIntConstant(m, "PROTO_CAIF", 0x00F7);
  PyModule_AddIntConstant(m, "PROTO_XDSA", 0x00F8);
  PyModule_AddIntConstant(m, "PROTO_MAP", 0x00F9);

  return m;
}

/*  vim: set ts=2 sw=2 et ai si: */
