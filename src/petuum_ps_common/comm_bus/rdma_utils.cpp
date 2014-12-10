/*
 * Copyright (c) 2005-2009 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <glog/logging.h>
#include "rdma_utils.hpp"

namespace petuum {
static int rdma_get_recv_compp(struct rdma_cm_id *id, struct ibv_wc *wc);
static int rdma_get_send_compp(struct rdma_cm_id *id, struct ibv_wc *wc);

// rdma_get_*_compp methods are rdma_get_*_comp methods from more recent version
// of rdma_verbs.h:
/*
 * Copyright (c) 2005 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2005-2010 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
inline static int rdma_get_recv_compp(struct rdma_cm_id *id,
                                      struct ibv_wc *wc) {
  struct ibv_cq *cq;
  void *context;
  int ret;

  do {
    ret = ibv_poll_cq(id->recv_cq, 1, wc);
    if (ret) break;

    ret = ibv_req_notify_cq(id->recv_cq, 0);
    if (ret) return rdma_seterrno(ret);

    ret = ibv_poll_cq(id->recv_cq, 1, wc);
    if (ret) break;

    ret = ibv_get_cq_event(id->recv_cq_channel, &cq, &context);
    if (ret) return ret;

    assert(cq == id->recv_cq && context == id);
    ibv_ack_cq_events(id->recv_cq, 1);
  } while (1);

  return (ret < 0) ? rdma_seterrno(ret) : ret;
}

inline static int rdma_get_send_compp(struct rdma_cm_id *id,
                                      struct ibv_wc *wc) {
  struct ibv_cq *cq;
  void *context;
  int ret;

  do {
    ret = ibv_poll_cq(id->send_cq, 1, wc);
    if (ret) break;

    ret = ibv_req_notify_cq(id->send_cq, 0);
    if (ret) return rdma_seterrno(ret);

    ret = ibv_poll_cq(id->send_cq, 1, wc);
    if (ret) break;

    ret = ibv_get_cq_event(id->send_cq_channel, &cq, &context);
    if (ret) return ret;

    assert(cq == id->send_cq && context == id);
    ibv_ack_cq_events(id->send_cq, 1);
  } while (1);

  return (ret < 0) ? rdma_seterrno(ret) : ret;
}

RDMAException::RDMAException(std::string const &source, int const code)
    : source_(source), code_(code) {
  VLOG(0) << "RDMAException: " << source << " returned " << code;
  VLOG(0) << *this;
}

RDMAException::~RDMAException() throw() {}

RDMAAddrInfo::RDMAAddrInfo(char *const server, char *const port,
                           bool rai_passive)
    : res_() {
  rdma_addrinfo hints;
  memset(&hints, 0, sizeof hints);
  hints.ai_flags = rai_passive;  // supposedly whether listener uses address
                                 // info, but it seems to need to be true for
                                 // the listener and false for the connector
  hints.ai_port_space = RDMA_PS_TCP;
  int ret = rdma_getaddrinfo(server, port, &hints, &res_);
  if (ret) throw RDMAException("rdma_getaddrinfo", ret);
}

RDMAAddrInfo::~RDMAAddrInfo() { rdma_freeaddrinfo(res_); }

RDMAQueuePair::RDMAQueuePair(struct rdma_cm_id *id) : id_(id) {}

RDMAQueuePair::~RDMAQueuePair() {
  if (id_) rdma_destroy_ep(id_);
}

std::pair<ibv_qp_attr, ibv_qp_init_attr> RDMAQueuePair::Attr() const {
  if (!id_)
    throw RDMAException("Attributes requested from QP with null cm_id", -1);
  struct ibv_qp_attr qp_attr;
  struct ibv_qp_init_attr init_attr;
  memset(&qp_attr, 0, sizeof qp_attr);
  memset(&init_attr, 0, sizeof init_attr);
  int ret = ibv_query_qp(id_->qp, &qp_attr, IBV_QP_CAP, &init_attr);
  if (ret) {
    throw RDMAException("ibv_query_qp", ret);
  }
  return std::make_pair(qp_attr, init_attr);
}

RDMAQueuePair::RDMAQueuePair() {}

RDMARecvMemoryRegistration::RDMARecvMemoryRegistration(RDMAQueuePair const &qp,
                                                       void volatile *buf,
                                                       size_t length)
    : qp_(qp), buf_((volatile uint8_t *)buf), length_(length) {
  mr_ = rdma_reg_msgs(qp.id_, (uint8_t *)buf, length);
  if (!mr_) {
    throw RDMAException("rdma_reg_msgs for recv_msg", 0);
  }
  VLOG(0) << "RECV REGION CONSTRUCTED";
}

RDMARecvMemoryRegistration::RDMARecvMemoryRegistration(RDMAQueuePair const &qp,
                                                       void volatile *buf,
                                                       size_t length,
                                                       bool post_immed)
    : RDMARecvMemoryRegistration(qp, buf, length) {
  VLOG(0) << "REGD RECV";
  if (post_immed) PostRecv();
}

RDMARecvMemoryRegistration::~RDMARecvMemoryRegistration() {
  rdma_dereg_mr(mr_);
}

void RDMARecvMemoryRegistration::PostRecv() const {
  VLOG(0) << "PostRecv" << buf_;
  int ret =
      rdma_post_recv(qp_.id_, NULL, const_cast<uint8_t *>(buf_), length_, mr_);
  if (ret) {
    throw RDMAException("rdma_post_recv", ret);
  }
  VLOG(0) << "POSTED RECV";
}

struct ibv_wc RDMARecvMemoryRegistration::GetRecvCompletionBusyWait() const {
  struct ibv_wc wc;
  int ret;
  while ((ret = rdma_get_recv_compp(qp_.id_, &wc)) == 0)
    ;
  if (ret < 0) {
    throw RDMAException("rdma_get_recv_comp", ret);
  }
  VLOG(0) << "GOT RECV COMPL";
  return wc;
}

RDMASendMemoryRegistration::RDMASendMemoryRegistration(RDMAQueuePair const &qp,
                                                       void *buf, size_t length,
                                                       int send_flags)
    : qp_(qp), buf_((uint8_t *)buf), length_(length), send_flags_(send_flags) {
  // memset(&qp_attr, 0, sizeof qp_attr);
  // memset(&init_attr, 0, sizeof init_attr);
  // ret = ibv_query_qp(connect_id->qp, &qp_attr, IBV_QP_CAP,
  // 		   &init_attr);
  // if (ret) {
  // 	perror("ibv_query_qp");
  // 	goto out_destroy_accept_ep;
  // }
  // printf("init_attr.cap.max_inline_data: %d\n",
  // init_attr.cap.max_inline_data);
  /* if (init_attr.cap.max_inline_data >= 16) */
  /* 	send_flags = IBV_SEND_INLINE; */
  /* else */
  /* 	printf("rdma_server: device doesn't support IBV_SEND_INLINE, " */
  /* 	       "using sge sends\n"); */
  if ((send_flags_ & IBV_SEND_INLINE) == 0) {
    mr_ = rdma_reg_msgs(qp_.id_, buf_, length_);
    if (!mr_) {
      int ret = -1;
      throw RDMAException("rdma_reg_msgs for send_msg", ret);
    }
  }
  VLOG(0) << "REGD SEND";
}

RDMASendMemoryRegistration::RDMASendMemoryRegistration(RDMAQueuePair const &qp,
                                                       void *buf, size_t length,
                                                       int send_flags,
                                                       bool post_immed)
    : RDMASendMemoryRegistration(qp, buf, length, send_flags) {
  VLOG(0) << "REGD SEND";
  if (post_immed) PostSend();
}

RDMASendMemoryRegistration::~RDMASendMemoryRegistration() {
  if ((send_flags_ & IBV_SEND_INLINE) == 0) rdma_dereg_mr(mr_);
}

void RDMASendMemoryRegistration::PostSend() const {
  int ret = rdma_post_send(qp_.id_, NULL, buf_, length_, mr_, send_flags_);
  if (ret) {
    throw RDMAException("rdma_post_send", ret);
  }
  VLOG(0) << "POSTED SEND";
}

struct ibv_wc RDMASendMemoryRegistration::GetSendCompletionBusyWait() const {
  struct ibv_wc wc;
  int ret;
  while ((ret = rdma_get_send_compp(qp_.id_, &wc)) == 0)
    ;
  if (ret < 0) throw RDMAException("rdma_get_send_comp", ret);
  VLOG(0) << "GOT SEND COMPL";
  return wc;
}

RDMALinker::RDMALinker(RDMAAddrInfo const &addr_info) {
  struct ibv_qp_init_attr init_attr;
  memset(&init_attr, 0, sizeof init_attr);
  init_attr.cap.max_send_wr = init_attr.cap.max_recv_wr = 10;
  init_attr.cap.max_send_sge = init_attr.cap.max_recv_sge = 1;
  init_attr.cap.max_inline_data = 16;
  init_attr.sq_sig_all = 1;
  init_attr.qp_type = IBV_QPT_RC;  // reliable connection (RC), TCP-like
  int ret = rdma_create_ep(&id_, addr_info.res_, NULL, &init_attr);
  if (ret) {
    throw RDMAException("rdma_create_ep", ret);
  }
  VLOG(0) << "CONSTRUCTED LINKER";
}

RDMALinker::~RDMALinker() { rdma_destroy_ep(id_); }

RDMAListenForQueuePairAsync::RDMAListenForQueuePairAsync(
    RDMALinker const &linker)
    : RDMAQueuePair(NULL), linker_(linker) {
  VLOG(0) << "MIDCONSTRUCT ASYNC LISTENER";
  if (int ret = rdma_listen(linker_.id_, 0)) {
    throw RDMAException("rdma_listen", ret);
  }
  VLOG(0) << "CONSTRUCTED ASYNC LISTENER";
}

void RDMAListenForQueuePairAsync::GetConnectionRequestBlocking() {
  struct rdma_cm_id *connect_id;
  if (int ret = rdma_get_request(linker_.id_, &connect_id)) {
    throw RDMAException("rdma_get_request", ret);
  }
  this->id_ = connect_id;
}

RDMAListenForQueuePairBlocking::RDMAListenForQueuePairBlocking(
    RDMALinker const &linker)
    : RDMAQueuePair(NULL) {
  VLOG(0) << "MIDCONSTRUCT BLOCKING LISTENER";
  VLOG(0) << "&linker: " << &linker;
  VLOG(0) << "linker.id_: " << linker.id_;
  struct rdma_cm_id *connect_id;
  int ret = rdma_listen(linker.id_, 0);
  if (ret) {
    throw RDMAException("rdma_listen", ret);
  }
  VLOG(0) << "GETTING CONNECTION REQUEST";
  ret = rdma_get_request(linker.id_, &connect_id);
  if (ret) {
    throw RDMAException("rdma_get_request", ret);
  }
  this->id_ = connect_id;
  VLOG(0) << "CONSTRUCTED BLOCKING LISTENER";
}

RDMAConnectorQueuePair::RDMAConnectorQueuePair(RDMALinker const &linker)
    : RDMAQueuePair(linker.id_) {}

RDMAConnectionScope::RDMAConnectionScope(RDMAQueuePair const &qp) : qp_(qp) {
  int ret = rdma_connect(qp_.id_, NULL);
  if (ret) {
    throw RDMAException("rdma_connect", ret);
  }
  VLOG(0) << "CONSTRUCTED CONNECTION SCOPE";
}

RDMAConnectionScope::RDMAConnectionScope(
    RDMAQueuePair const &qp,
    RDMASendMemoryRegistration const &post_and_block_for_wc,
    RDMARecvMemoryRegistration const &block_for_wc)
    : RDMAConnectionScope(qp) {
  try {
    VLOG(0) << "Connector post send...";
    post_and_block_for_wc.PostSend();
    VLOG(0) << "Connector get recv compl...";
    block_for_wc.GetRecvCompletionBusyWait();
    VLOG(0) << "Connector get send compl...";
    post_and_block_for_wc.GetSendCompletionBusyWait();
  } catch (const RDMAException &e) {
    rdma_disconnect(qp_.id_);
    throw e;
  }
  VLOG(0) << "CONSTRUCTED CONNECTION SCOPE";
}

RDMAConnectionScope::~RDMAConnectionScope() { rdma_disconnect(qp_.id_); }

RDMAAcceptanceScope::RDMAAcceptanceScope(RDMAQueuePair const &qp) : qp_(qp) {
  int ret = rdma_accept(qp_.id_, NULL);
  if (ret) {
    throw RDMAException("rdma_accept", ret);
  }
  VLOG(0) << "CONSTRUCTED ACCEPTANCE SCOPE";
}

RDMAAcceptanceScope::RDMAAcceptanceScope(
    RDMAQueuePair const &qp,
    RDMASendMemoryRegistration const &post_and_block_for_wc,
    RDMARecvMemoryRegistration const &block_for_wc)
    : RDMAAcceptanceScope(qp) {
  try {
    VLOG(0) << "Listener post send...";
    post_and_block_for_wc.PostSend();
    VLOG(0) << "Listener get recv compl...";
    block_for_wc.GetRecvCompletionBusyWait();
    VLOG(0) << "Listener get send compl...";
    post_and_block_for_wc.GetSendCompletionBusyWait();
  } catch (const RDMAException &e) {
    rdma_disconnect(qp_.id_);
    throw e;
  }
  VLOG(0) << "CONSTRUCTED ACCEPTANCE SCOPE";
}

RDMAAcceptanceScope::~RDMAAcceptanceScope() { rdma_disconnect(qp_.id_); }

RDMABufferLocationInfo::RDMABufferLocationInfo()
    : net_addr_(0), net_len_(0), rkey_(0) {}

RDMABufferLocationInfo::RDMABufferLocationInfo(void volatile *addr, size_t len,
                                               uint64_t rkey)
    : net_addr_(htonll((uint64_t)(volatile uint8_t *) addr)),
      net_len_(htonll(len)),
      rkey_(htonll(rkey)) {}
uint8_t *RDMABufferLocationInfo::LocalizedAddrAsPtr() const {
  return (uint8_t *)ntohll(net_addr_);
}

size_t RDMABufferLocationInfo::LocalizedLenAsSize() const {
  return ntohll(net_len_);
}

uint64_t RDMABufferLocationInfo::LocalizedAddr() const {
  return ntohll(net_addr_);
}

uint64_t RDMABufferLocationInfo::LocalizedLen() const {
  return ntohll(net_len_);
}

uint64_t RDMABufferLocationInfo::LocalizedRKey() const { return ntohll(rkey_); }

uint64_t RDMABufferLocationInfo::NetAddr() const { return net_addr_; }

uint64_t RDMABufferLocationInfo::NetLen() const { return net_len_; }

uint64_t RDMABufferLocationInfo::NetRKey() const { return rkey_; }

uint64_t htonll(uint64_t value) {
  if (htonl(42) != 42)
    return (((uint64_t)htonl(value)) << 32) | htonl(value >> 32);
  else
    return value;
}

uint64_t ntohll(uint64_t value) {
  return htonll(value);  // assuming just a swap or not, so ntoh = hton
}

RDMAWriteDestMemoryRegistration::RDMAWriteDestMemoryRegistration(
    RDMAQueuePair const &qp, void volatile *buf, size_t length, int send_flags)
    : qp_(qp),
      buf_((volatile uint8_t *)buf),
      length_(length),
      send_flags_(send_flags) {
  VLOG(0) << "MID WRITEDEST REG";
  VLOG(0) << "qp_.id_: " << qp_.id_;
  VLOG(0) << "buf_: " << (void *)buf_;
  VLOG(0) << "length: " << length;
  VLOG(0) << "send_flags: " << send_flags;
  mr_ = rdma_reg_write(qp_.id_, const_cast<uint8_t *>(buf_), length_);
  VLOG(0) << "DID WRITEDEST REG";
}

RDMAWriteDestMemoryRegistration::~RDMAWriteDestMemoryRegistration() {
  if (int ret = rdma_dereg_mr(mr_)) throw RDMAException("rdma_dereg_mr", ret);
}

RDMAWriteSrcMemoryRegistration::RDMAWriteSrcMemoryRegistration(
    RDMAQueuePair const &qp, void *buf, size_t length, int send_flags,
    RDMABufferLocationInfo const &remote_loc_info)
    : qp_(qp),
      buf_((uint8_t *)buf),
      length_(length),
      send_flags_(send_flags),
      remote_loc_info_(remote_loc_info) {
  mr_ = rdma_reg_msgs(qp_.id_, buf_, length_);
}

RDMAWriteSrcMemoryRegistration::~RDMAWriteSrcMemoryRegistration() {
  if (int ret = rdma_dereg_mr(mr_)) throw RDMAException("rdma_dereg_mr", ret);
}

void RDMAWriteSrcMemoryRegistration::PostWrite() const {
  // struct ibv_sge sg;
  // memset(&sg, 0, sizeof sg);
  // sg.addr = (uintptr_t)send_msg;
  // sg.length = sizeof send_msg;
  // sg.lkey = msg_reg->lkey;

  // struct ibv_send_wr wr;
  // memset(&wr, 0, sizeof(wr));
  // wr.wr_id = 0;
  // wr.sg_list = &sg;
  // wr.num_sge = 1;
  // wr.opcode = IBV_WR_RDMA_WRITE;
  // // wr.send_flags = IBV_SEND_SIGNALED;
  // wr.wr.rdma.remote_addr = htonll(send_msg_remote_loc.addr());
  // wr.wr.rdma.rkey = sender.mr_->rkey;

  // struct ibv_send_wr *bad_wr;
  // rdma_post_writev
  // ibv_post_wr

  // printf("sender lkey: %d", sender.mr_->lkey);
  // printf("sender rkey: %d", sender.mr_->rkey);

  // if(int ret = rdma_post_write(qp.id_, NULL, send_msg, sizeof send_msg,
  // NULL, 0, send_msg_remote_loc.NetAddr(), send_msg_remote_loc.NetRKey())) {
  // if(int ret = rdma_post_write(qp.id_, NULL, send_msg, sizeof send_msg,
  // msg_reg, 0, send_msg_remote_loc.NetAddr(),
  // send_msg_remote_loc.NetRKey())) {
  // xxx Apparently, rdma_post_write wants the localized or remote byte order,
  // not network byte order.  In the same-computer cluster setting, localized
  // and remote are the same (but different from network order), but this may
  // break in other settings:
  if (int ret = rdma_post_write(qp_.id_, NULL, buf_, length_, mr_, send_flags_,
                                remote_loc_info_.LocalizedAddr(),
                                remote_loc_info_.LocalizedRKey())) {
    throw RDMAException("ibv_rdma_post_write", ret);
  }
}

void RDMAWriteSrcMemoryRegistration::PostWrite(size_t offset, size_t length,
                                               uint64_t remote_addr) const {
  VLOG(0) << "BEGINNING POSTWRITE";
  if (offset + length > length_) {
    std::string str_buf(200, ' ');
    std::ostringstream builder(str_buf);
    builder << "PostWrite(offset=" << offset << ", length=" << length
            << ") using write registration of length only " << length_ << ".";
    throw RDMAException(builder.str(), -1);
  }
  if (remote_addr < remote_loc_info_.LocalizedAddr() ||
      remote_addr + length >
          remote_loc_info_.LocalizedAddr() + remote_loc_info_.LocalizedLen()) {
    std::cout << remote_addr << " " << remote_loc_info_.LocalizedAddr() << " "
              << remote_addr + length << " "
              << remote_loc_info_.LocalizedAddr() +
                     remote_loc_info_.LocalizedLen() << std::endl;
    throw RDMAException(
        "Provided remote_addr (/+length) don't make sense with writer's "
        "remote location info.",
        -1);
  }
  if (int ret = rdma_post_write(qp_.id_, NULL, buf_ + offset, length, mr_,
                                send_flags_, remote_addr,
                                remote_loc_info_.LocalizedRKey())) {
    throw RDMAException("ibv_rdma_post_write", ret);
  }
  VLOG(0) << "ENDING POSTWRITE";
}

void RDMAWriteSrcMemoryRegistration::PostWrite(size_t offset,
                                               size_t length) const {
  PostWrite(offset, length, remote_loc_info_.LocalizedAddr() +
                                offset);  // xxx should be RemoteAddr()
}

struct ibv_wc RDMAWriteSrcMemoryRegistration::GetWriteCompletionBusyWait()
    const {
  VLOG(0) << "BEGINNING WRITESRC REG";
  struct ibv_wc wc;
  int ret;
  while ((ret = rdma_get_send_compp(qp_.id_, &wc)) == 0)
    ;
  if (ret < 0) throw RDMAException("rdma_get_send_comp", ret);
  VLOG(0) << "GOT WRITESRC REG";
  return wc;
}

struct ibv_wc RDMAWriteBlockingInPlace(
    RDMAQueuePair const &qp, void *buf, size_t length, int send_flags,
    RDMABufferLocationInfo const &remote_loc_info) {
  const RDMAWriteSrcMemoryRegistration writer(qp, buf, length, send_flags,
                                              remote_loc_info);
  qp.Attr();
  writer.PostWrite();
  qp.Attr();
  return writer.GetWriteCompletionBusyWait();
}

struct ibv_wc RDMAWriteBlockingCopying(
    RDMAWriteSrcMemoryRegistration const &writer, void *buf, size_t length,
    uint64_t remote_addr) {
  if (length > writer.length_) {
    std::string str_buf(200, ' ');
    std::ostringstream builder(str_buf);
    builder << "RDMAWriteBlockingCopying(writer,_,length=" << length
            << ",_) with insufficient writer.length_=" << writer.length_ << ".";
    throw RDMAException(builder.str(), -1);
  }
  // PrintU8(std::cerr, writer.buf_, writer.length_) << "Pusher writer buffer
  // before memcpy" << std::endl;
  memcpy(writer.buf_, (uint8_t *)buf,
         length);  // xxx assumes we don't have other stuff
                   // reading from there, e.g., other RDMA
                   // writes
  // PrintU8(std::cerr, writer.buf_, writer.length_) << "Pusher writer buffer
  // after memcpy" << std::endl;
  writer.PostWrite(0, length, remote_addr);
  return writer.GetWriteCompletionBusyWait();
}

struct ibv_wc RDMAWriteBlockingCopyingWithLength(
    RDMAWriteSrcMemoryRegistration const &writer, void *buf, uint64_t length,
    uint64_t remote_addr) {
  if (length > writer.length_) {
    std::string str_buf(200, ' ');
    std::ostringstream builder(str_buf);
    builder << "RDMAWriteBlockingCopying(writer,_,length=" << length
            << ",_) with insufficient writer.length_=" << writer.length_ << ".";
    throw RDMAException(builder.str(), -1);
  }
  VLOG(0) << "Length: " << length;
  VLOG(0) << "Network length: " << htonll(length);
  *(uint64_t *)writer.buf_ = length - 2 * sizeof(uint64_t);
  VLOG(0) << "Reading written length: " << *(uint64_t *)writer.buf_;
  // memcpy(writer.buf_, ((uint8_t *)buf) + sizeof(uint64_t),
  //        length);  // xxx assumes we don't have other stuff
  //                  // reading from there, e.g., other RDMA
  //                  // writes
  memcpy(
      ((uint8_t *)writer.buf_) + sizeof(uint64_t), buf,
      length - 2 * sizeof(uint64_t));  // xxx assumes we don't have other stuff
                                       // reading from there, e.g., other RDMA
                                       // writes
  *(uint64_t *)(writer.buf_ + length - sizeof(uint64_t)) = UINT64_MAX;
  writer.PostWrite(0, length, remote_addr);
  return writer.GetWriteCompletionBusyWait();
}

RDMAMessageListener::RDMAMessageListener(char *port, int send_flags,
                                         void volatile *local_write_dest,
                                         uint64_t local_write_dest_length,
                                         void *remote_write_src,
                                         uint64_t remote_write_src_length)
    : local_write_dest_((volatile uint8_t *)local_write_dest),
      local_write_dest_length_(local_write_dest_length),
      remote_write_src_((uint8_t *)remote_write_src),
      remote_write_src_length_(remote_write_src_length),
      send_flags_(send_flags),
      addr_info_(NULL, port, true),
      listener_(addr_info_),
      qp_(listener_),
      write_dest_reg_(qp_, local_write_dest_, local_write_dest_length_,
                      send_flags_),
      local_write_dest_loc_(local_write_dest_, local_write_dest_length_,
                            write_dest_reg_.mr_->rkey),
      sender_(qp_, &local_write_dest_loc_, sizeof local_write_dest_loc_,
              send_flags_, false),
      remote_write_dest_loc_setup_(),
      receiver_(qp_, &remote_write_dest_loc_setup_,
                sizeof remote_write_dest_loc_setup_, true),
      acceptance_(qp_, sender_, receiver_),
      remote_write_dest_loc_(*const_cast<const RDMABufferLocationInfo *>(
                                 &remote_write_dest_loc_setup_)),
      write_src_reg_(qp_, remote_write_src_, remote_write_src_length_,
                     send_flags_, remote_write_dest_loc_) {
  VLOG(0) << "Message listener ready.";
}

RDMAMessageConnector::RDMAMessageConnector(char *server, char *port,
                                           int send_flags,
                                           void volatile *local_write_dest,
                                           uint64_t local_write_dest_length,
                                           void *remote_write_src,
                                           uint64_t remote_write_src_length)
    : local_write_dest_((volatile uint8_t *)local_write_dest),
      local_write_dest_length_(local_write_dest_length),
      remote_write_src_((uint8_t *)remote_write_src),
      remote_write_src_length_(remote_write_src_length),
      send_flags_(send_flags),
      addr_info_(server, port, false),
      connector_(addr_info_),
      qp_(connector_),
      write_dest_reg_(qp_, local_write_dest_, local_write_dest_length_,
                      send_flags_),
      local_write_dest_loc_(local_write_dest_, local_write_dest_length_,
                            write_dest_reg_.mr_->rkey),
      sender_(qp_, &local_write_dest_loc_, sizeof local_write_dest_loc_,
              send_flags_, false),
      remote_write_dest_loc_setup_(),
      receiver_(qp_, &remote_write_dest_loc_setup_,
                sizeof remote_write_dest_loc_setup_, true),
      connection_(qp_, sender_, receiver_),
      remote_write_dest_loc_(*const_cast<const RDMABufferLocationInfo *>(
                                 &remote_write_dest_loc_setup_)),
      write_src_reg_(qp_, remote_write_src_, remote_write_src_length_,
                     send_flags_, remote_write_dest_loc_) {
  VLOG(0) << "Message connector ready.";
}

std::ostream &PrintU8(std::ostream &stream, uint8_t const *buffer,
                      size_t length) {
  stream << "[";
  for (size_t i = 0; i < length; ++i) stream << (unsigned)buffer[i] << ",";
  stream << "]";
  return stream;
}

std::ostream &VolatilePrintU8(std::ostream &stream,
                              uint8_t const volatile *buffer, size_t length) {
  stream << "[";
  for (size_t i = 0; i < length; ++i) stream << (unsigned)buffer[i] << ",";
  stream << "]";
  return stream;
}

}  // namespace petuum
