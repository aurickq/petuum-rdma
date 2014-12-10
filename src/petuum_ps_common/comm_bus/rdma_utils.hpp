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

#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <unistd.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <iostream>
#include <string>
#include <exception>
#include <sstream>

namespace petuum {
class RDMAException : public std::exception {
 public:
  std::string const source_;
  int const code_;
  RDMAException(std::string const &source, int const code);
  virtual ~RDMAException() throw();
  friend std::ostream &operator<<(std::ostream &os, RDMAException const &e) {
    os << "RDMAException: " << e.source_ << " returned " << e.code_;
    return os;
  }
};

class RDMAAddrInfo {
 public:
  struct rdma_addrinfo *res_;
  RDMAAddrInfo(char *const server, char *const port, bool rai_passive);
  virtual ~RDMAAddrInfo();

 private:
  RDMAAddrInfo(RDMAAddrInfo const &_);
  RDMAAddrInfo &operator=(RDMAAddrInfo const &_);
};

class RDMAQueuePair {
 public:
  struct rdma_cm_id *id_;
  explicit RDMAQueuePair(struct rdma_cm_id *id);
  virtual ~RDMAQueuePair();
  std::pair<ibv_qp_attr, ibv_qp_init_attr> Attr() const;

 protected:
  explicit RDMAQueuePair();

 private:
  RDMAQueuePair(RDMAQueuePair const &_);
  RDMAQueuePair &operator=(RDMAQueuePair const &_);
};

class RDMARecvMemoryRegistration {
 public:
  RDMAQueuePair const &qp_;
  uint8_t volatile *buf_;
  size_t length_;
  struct ibv_mr *mr_;
  RDMARecvMemoryRegistration(RDMAQueuePair const &qp, void volatile *buf,
                             size_t length);
  RDMARecvMemoryRegistration(RDMAQueuePair const &qp, void volatile *buf,
                             size_t length, bool post_immed);
  virtual ~RDMARecvMemoryRegistration();
  void PostRecv() const;
  struct ibv_wc GetRecvCompletionBusyWait() const;

 private:
  RDMARecvMemoryRegistration(RDMARecvMemoryRegistration const &_);
  RDMARecvMemoryRegistration &operator=(RDMARecvMemoryRegistration const &_);
};

class RDMASendMemoryRegistration {
 public:
  RDMAQueuePair const &qp_;
  uint8_t *buf_;
  size_t length_;
  int send_flags_;
  struct ibv_mr *mr_;
  RDMASendMemoryRegistration(RDMAQueuePair const &qp, void *buf, size_t length,
                             int send_flags);
  RDMASendMemoryRegistration(RDMAQueuePair const &qp, void *buf, size_t length,
                             int send_flags, bool post_immed);
  virtual ~RDMASendMemoryRegistration();
  void PostSend() const;
  struct ibv_wc GetSendCompletionBusyWait() const;

 private:
  RDMASendMemoryRegistration(RDMASendMemoryRegistration const &_);
  RDMASendMemoryRegistration &operator=(RDMASendMemoryRegistration const &_);
};

class RDMALinker {
 public:
  struct rdma_cm_id *id_;
  explicit RDMALinker(RDMAAddrInfo const &addr_info);
  virtual ~RDMALinker();

 private:
  RDMALinker(RDMALinker const &_);
  RDMALinker &operator=(RDMALinker const &_);
};

class RDMAListenForQueuePairAsync : public RDMAQueuePair {
 public:
  explicit RDMAListenForQueuePairAsync(RDMALinker const &linker);
  void GetConnectionRequestBlocking();

 private:
  RDMALinker const &linker_;
  RDMAListenForQueuePairAsync(RDMAListenForQueuePairAsync const &_);
  RDMAListenForQueuePairAsync &operator=(RDMAListenForQueuePairAsync const &_);
};

class RDMAListenForQueuePairBlocking : public RDMAQueuePair {
 public:
  explicit RDMAListenForQueuePairBlocking(RDMALinker const &linker);

 private:
  RDMAListenForQueuePairBlocking(RDMAListenForQueuePairBlocking const &_);
  RDMAListenForQueuePairBlocking &operator=(
      RDMAListenForQueuePairBlocking const &_);
};

class RDMAConnectorQueuePair : public RDMAQueuePair {
 public:
  explicit RDMAConnectorQueuePair(RDMALinker const &linker);

 private:
  RDMAConnectorQueuePair(RDMAConnectorQueuePair const &_);
  RDMAConnectorQueuePair &operator=(RDMAConnectorQueuePair const &_);
};

class RDMAConnectionScope {
 public:
  RDMAQueuePair const &qp_;
  RDMAConnectionScope(RDMAQueuePair const &qp);
  RDMAConnectionScope(RDMAQueuePair const &qp,
                      RDMASendMemoryRegistration const &post_and_block_for_wc,
                      RDMARecvMemoryRegistration const &block_for_wc);
  virtual ~RDMAConnectionScope();

 private:
  RDMAConnectionScope(RDMAConnectionScope const &_);
  RDMAConnectionScope &operator=(RDMAConnectionScope const &_);
};

class RDMAAcceptanceScope {
 public:
  RDMAQueuePair const &qp_;
  RDMAAcceptanceScope(RDMAQueuePair const &qp);
  RDMAAcceptanceScope(RDMAQueuePair const &qp,
                      RDMASendMemoryRegistration const &post_and_block_for_wc,
                      RDMARecvMemoryRegistration const &block_for_wc);
  virtual ~RDMAAcceptanceScope();

 private:
  RDMAAcceptanceScope(RDMAAcceptanceScope const &_);
  RDMAAcceptanceScope &operator=(RDMAAcceptanceScope const &_);
};

class RDMABufferLocationInfo {
 private:
  uint64_t net_addr_;
  uint64_t net_len_;
  uint64_t rkey_;

 public:
  RDMABufferLocationInfo();
  RDMABufferLocationInfo(void volatile *addr, size_t len, uint64_t rkey);
  uint8_t *LocalizedAddrAsPtr() const;
  size_t LocalizedLenAsSize() const;
  uint64_t LocalizedAddr() const;
  uint64_t LocalizedLen() const;
  uint64_t LocalizedRKey() const;
  uint64_t NetAddr() const;
  uint64_t NetLen() const;
  uint64_t NetRKey() const;
};

uint64_t htonll(uint64_t value);
uint64_t ntohll(uint64_t value);
class RDMAWriteDestMemoryRegistration {
 public:
  RDMAQueuePair const &qp_;
  uint8_t volatile *buf_;
  size_t length_;
  int send_flags_;
  struct ibv_mr *mr_;
  RDMAWriteDestMemoryRegistration(RDMAQueuePair const &qp, void volatile *buf,
                                  size_t length, int send_flags);
  virtual ~RDMAWriteDestMemoryRegistration();

 private:
  RDMAWriteDestMemoryRegistration(RDMAWriteDestMemoryRegistration const &_);
  RDMAWriteDestMemoryRegistration &operator=(
      RDMAWriteDestMemoryRegistration const &_);
};

class RDMAWriteSrcMemoryRegistration {
 public:
  RDMAQueuePair const &qp_;
  uint8_t *buf_;
  size_t length_;
  int send_flags_;
  struct ibv_mr *mr_;
  RDMABufferLocationInfo const remote_loc_info_;
  RDMAWriteSrcMemoryRegistration(RDMAQueuePair const &qp, void *buf,
                                 size_t length, int send_flags,
                                 RDMABufferLocationInfo const &remote_loc_info);
  virtual ~RDMAWriteSrcMemoryRegistration();
  void PostWrite() const;
  void PostWrite(size_t offset, size_t length, uint64_t remote_addr) const;
  void PostWrite(size_t offset, size_t length) const;
  struct ibv_wc GetWriteCompletionBusyWait() const;

 private:
  RDMAWriteSrcMemoryRegistration(RDMAWriteSrcMemoryRegistration const &_);
  RDMAWriteSrcMemoryRegistration &operator=(
      RDMAWriteSrcMemoryRegistration const &_);
};

// xxx will be slow if memory registration is slow.
// Assumption: no other threads modify the memory that is writing during the
// write; RDMA might lock the memory to make this a certainty.
struct ibv_wc RDMAWriteBlockingInPlace(
    RDMAQueuePair const &qp, void *buf, size_t length, int send_flags,
    RDMABufferLocationInfo const &remote_loc_info);
// xxx if memory registration is fast compared to memcpy, this will be slower
// than in-place.
// Assumption: no other threads modify the memory that is writing during the
// write; RDMA might lock the memory to make this a certainty.
// Assumption: it is safe to write to |writer.buf_| anywhere without messing up
// other things, e.g., other RDMA writes.  This assumption may not hold in
// non-blocking or multi-threaded contexts.
struct ibv_wc RDMAWriteBlockingCopying(
    RDMAWriteSrcMemoryRegistration const &writer, void *buf, size_t length,
    uint64_t remote_addr);

struct ibv_wc RDMAWriteBlockingCopyingWithLength(
    RDMAWriteSrcMemoryRegistration const &writer, void *buf, size_t length,
    uint64_t remote_addr);

class RDMAMessageListener {
 public:
  uint8_t volatile *local_write_dest_;
  uint64_t local_write_dest_length_;
  uint8_t *remote_write_src_;
  uint64_t remote_write_src_length_;
  int send_flags_;
  RDMAAddrInfo const addr_info_;
  RDMALinker const listener_;
  RDMAListenForQueuePairBlocking const qp_;
  RDMAWriteDestMemoryRegistration const write_dest_reg_;
  RDMABufferLocationInfo local_write_dest_loc_;
  RDMASendMemoryRegistration const sender_;
  RDMABufferLocationInfo volatile remote_write_dest_loc_setup_;
  RDMARecvMemoryRegistration const receiver_;
  RDMAAcceptanceScope const acceptance_;
  RDMABufferLocationInfo remote_write_dest_loc_;
  RDMAWriteSrcMemoryRegistration const write_src_reg_;
  RDMAMessageListener(char *port, int send_flags,
                      void volatile *local_write_dest,
                      uint64_t local_write_dest_length, void *remote_write_src,
                      uint64_t remote_write_src_length);

 private:
  RDMAMessageListener(RDMAMessageListener const &_);
  RDMAMessageListener &operator=(RDMAMessageListener const &_);
};

class RDMAMessageConnector {
 public:
  uint8_t volatile *local_write_dest_;
  uint64_t local_write_dest_length_;
  uint8_t *remote_write_src_;
  uint64_t remote_write_src_length_;
  int send_flags_;
  RDMAAddrInfo const addr_info_;
  RDMALinker const connector_;
  RDMAConnectorQueuePair const qp_;
  RDMAWriteDestMemoryRegistration const write_dest_reg_;
  RDMABufferLocationInfo local_write_dest_loc_;
  RDMASendMemoryRegistration const sender_;
  RDMABufferLocationInfo volatile remote_write_dest_loc_setup_;
  RDMARecvMemoryRegistration const receiver_;
  RDMAConnectionScope const connection_;
  RDMABufferLocationInfo remote_write_dest_loc_;
  RDMAWriteSrcMemoryRegistration const write_src_reg_;
  RDMAMessageConnector(char *server, char *port, int send_flags,
                       void volatile *local_write_dest,
                       uint64_t local_write_dest_length, void *remote_write_src,
                       uint64_t remote_write_src_length);

 private:
  RDMAMessageConnector(RDMAMessageConnector const &_);
  RDMAMessageConnector &operator=(RDMAMessageConnector const &_);
};

std::ostream &PrintU8(std::ostream &stream, uint8_t const *buffer,
                      size_t length);
// Output may mix later states of the buffer elements at higher indices.
std::ostream &VolatilePrintU8(std::ostream &stream,
                              uint8_t const volatile *buffer, size_t length);
template <size_t BUF_AND_TAIL_SIZE>
struct RDMABufAndTail {
 public:
  uint8_t buffer_[BUF_AND_TAIL_SIZE];
  uint64_t client_tail_;
  RDMABufAndTail();
};

template <size_t BUF_AND_TAIL_SIZE>
class RDMAMessagePuller {
 public:
  volatile RDMABufAndTail<BUF_AND_TAIL_SIZE> &client_buf_and_tail_;
  uint64_t client_head_;
  RDMAMessageListener messager_;
  RDMAMessagePuller(
      char *port, int send_flags,
      volatile RDMABufAndTail<BUF_AND_TAIL_SIZE> &client_buf_and_tail);
  virtual ~RDMAMessagePuller() { delete &client_buf_and_tail_; }
  bool Pull(void *msg_copy_buf, uint64_t msg_length);
  bool WrapHead();
  friend std::ostream &operator<<(
      std::ostream &os, RDMAMessagePuller<BUF_AND_TAIL_SIZE> const &puller) {
    os << "Puller: ";
    return VolatilePrintU8(os, puller.client_buf_and_tail_.buffer_,
                           sizeof puller.client_buf_and_tail_.buffer_)
           << " "
           << puller.client_buf_and_tail_.client_tail_ -
                  (uint64_t)&puller.client_buf_and_tail_ << " "
           << puller.client_head_ - (uint64_t)&puller.client_buf_and_tail_;
    // return os << "Puller: "
    //           << puller.client_buf_and_tail_.client_tail_ -
    //                  (uint64_t)&puller.client_buf_and_tail_ << " "
    //           << puller.client_head_ -
    //           (uint64_t)&puller.client_buf_and_tail_;
  }
};

template <size_t STAGE_SIZE>
class RDMAMessagePusher {
 public:
  RDMAMessageConnector messager_;
  uint8_t server_msg_stage_[STAGE_SIZE];
  uint64_t const volatile server_head_;
  uint64_t server_tail_;
  RDMAMessagePusher(char *server, char *port, int send_flags);
  bool Push(void *msg, uint64_t msg_length, uint64_t rewind);
  bool PushWithLength(void *msg, uint64_t msg_length);
  bool Push(void *msg, uint64_t msg_length);
  friend std::ostream &operator<<(std::ostream &os,
                                  RDMAMessagePusher<STAGE_SIZE> const &pusher) {
    os << "Pusher: ";
    return PrintU8(os, pusher.server_msg_stage_,
                   sizeof pusher.server_msg_stage_)
           << " "
           << pusher.server_head_ -
                  pusher.messager_.remote_write_dest_loc_.LocalizedAddr() << " "
           << pusher.server_tail_ -
                  pusher.messager_.remote_write_dest_loc_.LocalizedAddr();
    // return os << "Pusher: "
    //           << pusher.server_head_ -
    //                  pusher.messager_.remote_write_dest_loc_.LocalizedAddr()
    //           << " "
    //           << pusher.server_tail_ -
    //                  pusher.messager_.remote_write_dest_loc_.LocalizedAddr();
  }
};

template <size_t BUF_AND_TAIL_SIZE>
bool RDMAMessagePuller<BUF_AND_TAIL_SIZE>::WrapHead() {
  uint64_t buf =
      messager_.local_write_dest_loc_.LocalizedAddr();  // == (uint64_t)buf_ptr
  uint64_t &buf_head = client_head_;
  // xxx buf_tail should probably be a copy since it is remote-writable
  uint64_t buf_tail =
      *(uint64_t *)(messager_.local_write_dest_loc_.LocalizedAddr() +
                    messager_.local_write_dest_loc_.LocalizedLen() -
                    sizeof(uint64_t));  // the last 8 bytes are the client tail
  if (buf_head <= buf_tail) return false;  // don't pass up tail
  buf_head = buf;
  RDMAWriteBlockingCopying(messager_.write_src_reg_, (uint8_t *)&buf_head,
                           sizeof buf_head,
                           messager_.remote_write_dest_loc_.LocalizedAddr());
  return true;
}

template <size_t BUF_AND_TAIL_SIZE>
RDMABufAndTail<BUF_AND_TAIL_SIZE>::RDMABufAndTail()
    : client_tail_((uint64_t)&buffer_) {
  // xxx for debugging, fill with some value:
  memset(buffer_, 3, sizeof buffer_);
}

template <size_t BUF_AND_TAIL_SIZE>
RDMAMessagePuller<BUF_AND_TAIL_SIZE>::RDMAMessagePuller(
    char *port, int send_flags,
    volatile RDMABufAndTail<BUF_AND_TAIL_SIZE> &client_buf_and_tail)
    : client_buf_and_tail_(client_buf_and_tail),
      client_head_((uint64_t)&client_buf_and_tail_.buffer_),
      messager_(port, send_flags, (uint8_t *)&client_buf_and_tail_,
                sizeof client_buf_and_tail_, (uint8_t *)&client_head_,
                sizeof client_head_) {}

template <size_t BUF_AND_TAIL_SIZE>
bool RDMAMessagePuller<BUF_AND_TAIL_SIZE>::Pull(void *msg_copy_buf,
                                                uint64_t msg_length) {
  uint64_t &buf_head = client_head_;
  uint64_t buf =
      messager_.local_write_dest_loc_.LocalizedAddr();  // == (uint64_t)buf_ptr
  uint64_t buf_length =
      messager_.local_write_dest_loc_.LocalizedLen() -
      sizeof(uint64_t);  // the last 8 bytes are the client tail

  // xxx buf_tail should probably be a copy since it is remote-writable
  uint64_t buf_tail =
      *(uint64_t *)(messager_.local_write_dest_loc_.LocalizedAddr() +
                    messager_.local_write_dest_loc_.LocalizedLen() -
                    sizeof(uint64_t));  // the last 8 bytes are the client tail

  if (2 * msg_length > buf_length)
    throw RDMAException(
        "2 * msg_length > dest_length",
        -1);  // Couldn't guarantee successful writes for this size,
              // shouldn't be here.

  if (buf_head + msg_length >= buf + buf_length) {
    // Not enough room between tail and end of buf buffer for msg.  Find it at
    // the beginning instead.
    if (buf_head <= buf_tail)
      return false;  // tail's not wrapped around yet, don't pass it up.
    if (buf_tail < buf_head && buf + msg_length > buf_tail)
      return false;  // tail's not advanced enough from beginning of buf.
    memcpy(msg_copy_buf, (uint8_t *)buf, msg_length);
    buf_head = buf + msg_length;
  } else {
    // Enough room between tail and end of buf buffer for msg.
    if (buf_head <= buf_tail && buf_head + msg_length > buf_tail)
      return false;  // tail's not advanced enough from head.
    memcpy(msg_copy_buf, (uint8_t *)buf_head, msg_length);
    buf_head = buf_head + msg_length;
  }
  RDMAWriteBlockingCopying(messager_.write_src_reg_, (uint8_t *)&buf_head,
                           sizeof buf_head,
                           messager_.remote_write_dest_loc_.LocalizedAddr());
  return true;
}

template <size_t STAGE_SIZE>
RDMAMessagePusher<STAGE_SIZE>::RDMAMessagePusher(char *server, char *port,
                                                 int send_flags)
    : messager_(server, port, send_flags, (uint8_t *)&server_head_,
                sizeof server_head_, server_msg_stage_,
                sizeof server_msg_stage_),
      server_head_(messager_.remote_write_dest_loc_.LocalizedAddr()),
      server_tail_(messager_.remote_write_dest_loc_.LocalizedAddr()) {
  // std::cout << "msg stage: " << server_msg_stage_;
  // std::cout << "msg stage: " << &server_msg_stage_;
  // xxx for debugging, fill staging area with value
  memset(&server_msg_stage_, 4, sizeof server_msg_stage_);
  // queue starts empty, tail = head = start.
}

template <size_t STAGE_SIZE>
bool RDMAMessagePusher<STAGE_SIZE>::Push(void *msg, uint64_t msg_length,
                                         uint64_t rewind) {
  // VLOG(0) << "Attempting RDMA push";
  // PrintU8(std::cerr, (uint8_t *)msg, msg_length) << "Push msg in Push " << std::endl;
  if (rewind > msg_length)
    throw RDMAException("Pushes cannot rewind more data than they provide.",
                        -1);
  uint64_t &dest_tail = server_tail_;
  // std::cout << "Push "
  //           << dest_tail - messager_.remote_write_dest_loc_.LocalizedAddr()
  //           << " ";
  // PrintU8((uint8_t *)msg, msg_length) << std::endl;

  uint64_t dest = messager_.remote_write_dest_loc_.LocalizedAddr();
  uint64_t dest_length =
      messager_.remote_write_dest_loc_.LocalizedLen() -
      sizeof(uint64_t);  // the last 8 bytes are the client tail

  // xxx dest_head should probably be a copy since it is remote-writable
  if (messager_.local_write_dest_length_ != sizeof(uint64_t))
    throw RDMAException(
        "Wrong messager_.local_write_dest_length_(!=sizeof(uint64_t)):",
        messager_.local_write_dest_length_);
  uint64_t dest_head = *(uint64_t *)messager_.local_write_dest_;

  // To ensure that dest_head==dest_tail indicates an empty buffer,
  // never allow a full buffer; stop 1 short of head always.

  // Since we don't wrap individual records, this imposes a stricter
  // message size limit.
  if (2 * msg_length > dest_length) {
    std::cout << msg_length << " " << dest_length << std::endl;
    throw RDMAException(
        "2 * msg_length > dest_length",
        -1);  // Can't guarantee successful writes for this size.
  }

  if (dest_tail + msg_length >= dest + dest_length) {
    // Not enough room between tail and end of dest buffer for src.  Put it at
    // the beginning instead.
    if (dest_tail < dest_head)
      return false;  // head's not wrapped around yet, don't pass it up.
    if (dest_head < dest_tail && dest + msg_length > dest_head - 1)
      return false;  // head's not advanced enough from beginning of dest.
    // Write message to beginning of client buffer.
    RDMAWriteBlockingCopying(messager_.write_src_reg_, (uint8_t *)msg,
                             msg_length, dest);
    dest_tail = dest + msg_length;
  } else {
    // Enough room between tail and end of dest buffer for src.
    if (dest_tail < dest_head && dest_tail + msg_length > dest_head - 1)
      return false;  // head's not advanced enough from tail.
    // Write message to client buffer following the tail.
    RDMAWriteBlockingCopying(messager_.write_src_reg_, (uint8_t *)msg,
                             msg_length, dest_tail);
    dest_tail = dest_tail + msg_length;
  }
  dest_tail = dest_tail - rewind;  // rewind the tail by the specified amount
  // Write to client tail.
  RDMAWriteBlockingCopying(messager_.write_src_reg_, (uint8_t *)&dest_tail,
                           sizeof dest_tail, dest + dest_length);
  return true;
}

template <size_t STAGE_SIZE>
bool RDMAMessagePusher<STAGE_SIZE>::PushWithLength(void *msg,
                                                   uint64_t msg_length) {
  uint64_t rewind = sizeof(uint64_t);
  msg_length = sizeof(uint64_t) + msg_length + sizeof(uint64_t);
  if (rewind > msg_length)
    throw RDMAException("Pushes cannot rewind more data than they provide.",
                        -1);
  uint64_t &dest_tail = server_tail_;
  // std::cout << "Push "
  //           << dest_tail - messager_.remote_write_dest_loc_.LocalizedAddr()
  //           << " ";
  // PrintU8((uint8_t *)msg, msg_length) << std::endl;

  uint64_t dest = messager_.remote_write_dest_loc_.LocalizedAddr();
  uint64_t dest_length =
      messager_.remote_write_dest_loc_.LocalizedLen() -
      sizeof(uint64_t);  // the last 8 bytes are the client tail

  // xxx dest_head should probably be a copy since it is remote-writable
  if (messager_.local_write_dest_length_ != sizeof(uint64_t))
    throw RDMAException(
        "Wrong messager_.local_write_dest_length_(!=sizeof(uint64_t)):",
        messager_.local_write_dest_length_);
  uint64_t dest_head = *(uint64_t *)messager_.local_write_dest_;

  // To ensure that dest_head==dest_tail indicates an empty buffer,
  // never allow a full buffer; stop 1 short of head always.

  // Since we don't wrap individual records, this imposes a stricter
  // message size limit.
  if (2 * msg_length > dest_length) {
    std::cout << msg_length << " " << dest_length << std::endl;
    throw RDMAException(
        "2 * msg_length > dest_length",
        -1);  // Can't guarantee successful writes for this size.
  }

  if (dest_tail + msg_length >= dest + dest_length) {
    // Not enough room between tail and end of dest buffer for src.  Put it at
    // the beginning instead.
    if (dest_tail < dest_head)
      return false;  // head's not wrapped around yet, don't pass it up.
    if (dest_head < dest_tail && dest + msg_length > dest_head - 1)
      return false;  // head's not advanced enough from beginning of dest.
    // Write message to beginning of client buffer.
    RDMAWriteBlockingCopyingWithLength(messager_.write_src_reg_, (uint8_t *)msg,
                                       msg_length, dest);
    dest_tail = dest + msg_length;
  } else {
    // Enough room between tail and end of dest buffer for src.
    if (dest_tail < dest_head && dest_tail + msg_length > dest_head - 1)
      return false;  // head's not advanced enough from tail.
    // Write message to client buffer following the tail.
    RDMAWriteBlockingCopyingWithLength(messager_.write_src_reg_, (uint8_t *)msg,
                                       msg_length, dest_tail);
    dest_tail = dest_tail + msg_length;
  }
  dest_tail = dest_tail - rewind;  // rewind the tail by the specified amount
  // Write to client tail.
  RDMAWriteBlockingCopying(messager_.write_src_reg_, (uint8_t *)&dest_tail,
                           sizeof dest_tail, dest + dest_length);
  return true;
}

template <size_t STAGE_SIZE>
bool RDMAMessagePusher<STAGE_SIZE>::Push(void *msg, uint64_t msg_length) {
  return Push(msg, msg_length, 0);
}

}  // namespace petuum
