/* Copyright 2021 Ryan Castellucci, MIT License */

#include <Python.h>

#include "nflogconst.h"

int nflog_add_protos(PyObject *m) {
  if (!m) { return -1; }
  ADDINTCONST(m, "PROTO_LOOP", 0x0060);
  ADDINTCONST(m, "PROTO_PUP", 0x0200);
  ADDINTCONST(m, "PROTO_PUPAT", 0x0201);
  ADDINTCONST(m, "PROTO_TSN", 0x22F0);
  ADDINTCONST(m, "PROTO_ERSPAN2", 0x22EB);
  ADDINTCONST(m, "PROTO_IP", 0x0800);
  ADDINTCONST(m, "PROTO_X25", 0x0805);
  ADDINTCONST(m, "PROTO_ARP", 0x0806);
  ADDINTCONST(m, "PROTO_BPQ", 0x08FF);
  ADDINTCONST(m, "PROTO_IEEEPUP", 0x0a00);
  ADDINTCONST(m, "PROTO_IEEEPUPAT", 0x0a01);
  ADDINTCONST(m, "PROTO_BATMAN", 0x4305);
  ADDINTCONST(m, "PROTO_DEC", 0x6000);
  ADDINTCONST(m, "PROTO_DNA_DL", 0x6001);
  ADDINTCONST(m, "PROTO_DNA_RC", 0x6002);
  ADDINTCONST(m, "PROTO_DNA_RT", 0x6003);
  ADDINTCONST(m, "PROTO_LAT", 0x6004);
  ADDINTCONST(m, "PROTO_DIAG", 0x6005);
  ADDINTCONST(m, "PROTO_CUST", 0x6006);
  ADDINTCONST(m, "PROTO_SCA", 0x6007);
  ADDINTCONST(m, "PROTO_TEB", 0x6558);
  ADDINTCONST(m, "PROTO_RARP", 0x8035);
  ADDINTCONST(m, "PROTO_ATALK", 0x809B);
  ADDINTCONST(m, "PROTO_AARP", 0x80F3);
  ADDINTCONST(m, "PROTO_8021Q", 0x8100);
  ADDINTCONST(m, "PROTO_ERSPAN", 0x88BE);
  ADDINTCONST(m, "PROTO_IPX", 0x8137);
  ADDINTCONST(m, "PROTO_IPV6", 0x86DD);
  ADDINTCONST(m, "PROTO_PAUSE", 0x8808);
  ADDINTCONST(m, "PROTO_SLOW", 0x8809);
  ADDINTCONST(m, "PROTO_WCCP", 0x883E);
  ADDINTCONST(m, "PROTO_MPLS_UC", 0x8847);
  ADDINTCONST(m, "PROTO_MPLS_MC", 0x8848);
  ADDINTCONST(m, "PROTO_ATMMPOA", 0x884c);
  ADDINTCONST(m, "PROTO_PPP_DISC", 0x8863);
  ADDINTCONST(m, "PROTO_PPP_SES", 0x8864);
  ADDINTCONST(m, "PROTO_LINK_CTL", 0x886c);
  ADDINTCONST(m, "PROTO_ATMFATE", 0x8884);
  ADDINTCONST(m, "PROTO_PAE", 0x888E);
  ADDINTCONST(m, "PROTO_AOE", 0x88A2);
  ADDINTCONST(m, "PROTO_8021AD", 0x88A8);
  ADDINTCONST(m, "PROTO_802_EX1", 0x88B5);
  ADDINTCONST(m, "PROTO_PREAUTH", 0x88C7);
  ADDINTCONST(m, "PROTO_TIPC", 0x88CA);
  ADDINTCONST(m, "PROTO_LLDP", 0x88CC);
  ADDINTCONST(m, "PROTO_MACSEC", 0x88E5);
  ADDINTCONST(m, "PROTO_8021AH", 0x88E7);
  ADDINTCONST(m, "PROTO_MVRP", 0x88F5);
  ADDINTCONST(m, "PROTO_1588", 0x88F7);
  ADDINTCONST(m, "PROTO_NCSI", 0x88F8);
  ADDINTCONST(m, "PROTO_PRP", 0x88FB);
  ADDINTCONST(m, "PROTO_FCOE", 0x8906);
  ADDINTCONST(m, "PROTO_IBOE", 0x8915);
  ADDINTCONST(m, "PROTO_TDLS", 0x890D);
  ADDINTCONST(m, "PROTO_FIP", 0x8914);
  ADDINTCONST(m, "PROTO_80221", 0x8917);
  ADDINTCONST(m, "PROTO_HSR", 0x892F);
  ADDINTCONST(m, "PROTO_NSH", 0x894F);
  ADDINTCONST(m, "PROTO_LOOPBACK", 0x9000);
  ADDINTCONST(m, "PROTO_QINQ1", 0x9100);
  ADDINTCONST(m, "PROTO_QINQ2", 0x9200);
  ADDINTCONST(m, "PROTO_QINQ3", 0x9300);
  ADDINTCONST(m, "PROTO_EDSA", 0xDADA);
  ADDINTCONST(m, "PROTO_DSA_8021Q", 0xDADB);
  ADDINTCONST(m, "PROTO_IFE", 0xED3E);
  ADDINTCONST(m, "PROTO_AF_IUCV", 0xFBFB);
  ADDINTCONST(m, "PROTO_802_3_MIN", 0x0600);
  ADDINTCONST(m, "PROTO_802_3", 0x0001);
  ADDINTCONST(m, "PROTO_AX25", 0x0002);
  ADDINTCONST(m, "PROTO_ALL", 0x0003);
  ADDINTCONST(m, "PROTO_802_2", 0x0004);
  ADDINTCONST(m, "PROTO_SNAP", 0x0005);
  ADDINTCONST(m, "PROTO_DDCMP", 0x0006);
  ADDINTCONST(m, "PROTO_WAN_PPP", 0x0007);
  ADDINTCONST(m, "PROTO_PPP_MP", 0x0008);
  ADDINTCONST(m, "PROTO_LOCALTALK", 0x0009);
  ADDINTCONST(m, "PROTO_CAN", 0x000C);
  ADDINTCONST(m, "PROTO_CANFD", 0x000D);
  ADDINTCONST(m, "PROTO_PPPTALK", 0x0010);
  ADDINTCONST(m, "PROTO_TR_802_2", 0x0011);
  ADDINTCONST(m, "PROTO_MOBITEX", 0x0015);
  ADDINTCONST(m, "PROTO_CONTROL", 0x0016);
  ADDINTCONST(m, "PROTO_IRDA", 0x0017);
  ADDINTCONST(m, "PROTO_ECONET", 0x0018);
  ADDINTCONST(m, "PROTO_HDLC", 0x0019);
  ADDINTCONST(m, "PROTO_ARCNET", 0x001A);
  ADDINTCONST(m, "PROTO_DSA", 0x001B);
  ADDINTCONST(m, "PROTO_TRAILER", 0x001C);
  ADDINTCONST(m, "PROTO_PHONET", 0x00F5);
  ADDINTCONST(m, "PROTO_IEEE802154", 0x00F6);
  ADDINTCONST(m, "PROTO_CAIF", 0x00F7);
  ADDINTCONST(m, "PROTO_XDSA", 0x00F8);
  ADDINTCONST(m, "PROTO_MAP", 0x00F9);
  return 0;
}