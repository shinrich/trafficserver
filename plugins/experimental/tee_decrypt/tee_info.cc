#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <limits.h>
#include <sys/capability.h>
#include "tee_info.h"

struct grehdr {
  uint16_t flags;
  uint16_t protocol;
} __packed;

GreInfo gre_info;

thread_local int Raw_socket = 0;

TeeInfo::TeeInfo(sockaddr const *src_addr, sockaddr const *dst_addr)
{
  if (src_addr->sa_family != AF_INET || dst_addr->sa_family != AF_INET) {
    // Only support IPv4 right now
    fprintf(stderr, "Invalid request. Only support IPv4 so far");
    return;
  }
  struct sockaddr_in *addr = (struct sockaddr_in *)src_addr;
  this->src_port           = addr->sin_port;
  this->src_addr           = addr->sin_addr.s_addr;
  addr                     = (struct sockaddr_in *)dst_addr;
  this->dst_port           = addr->sin_port;
  this->dst_addr           = addr->sin_addr.s_addr;
}

struct tcphdr *
get_tcp_hdr(char *buffer)
{
  return (struct tcphdr *)(buffer + 2 * sizeof(struct iphdr) + sizeof(struct grehdr));
}

int
TeeInfo::build_packet(char *buffer, int payload_size, bool forward)
{
  struct tcphdr *tcph;
  struct iphdr *outter_iphdr, *inner_iphdr;

  outter_iphdr           = (struct iphdr *)(buffer);
  inner_iphdr            = (struct iphdr *)(buffer + sizeof(struct iphdr) + sizeof(struct grehdr));
  struct grehdr *gre_hdr = (struct grehdr *)(buffer + sizeof(struct iphdr));
  gre_hdr->flags         = 0;
  gre_hdr->protocol      = htons(0x0800); // IP

  outter_iphdr->ihl      = 5; /* header length 5 * sizeof(uint32) = 20 bytes – no optional elements*/
  outter_iphdr->version  = 4; /* ip version 4 */
  outter_iphdr->tos      = 0; /* type of service */
  outter_iphdr->tot_len  = htons(2 * sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct tcphdr) + payload_size);
  outter_iphdr->ttl      = 64; /* time to live */
  outter_iphdr->protocol = 47;
  outter_iphdr->saddr    = gre_info.src_addr; /* use loopback address for source */
  outter_iphdr->daddr    = gre_info.dst_addr; /* use loopback address for dest */
  outter_iphdr->check    = 0;

  inner_iphdr->ihl      = 5; /* header length 5 * sizeof(uint32) = 20 bytes – no optional elements*/
  inner_iphdr->version  = 4; /* ip version 4 */
  inner_iphdr->tos      = 0; /* type of service */
  inner_iphdr->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_size);
  inner_iphdr->ttl      = 64; /* time to live */
  inner_iphdr->protocol = IPPROTO_TCP;
  inner_iphdr->saddr    = forward ? this->src_addr : this->dst_addr;
  inner_iphdr->daddr    = forward ? this->dst_addr : this->src_addr;
  inner_iphdr->check    = 0;

  tcph = get_tcp_hdr(buffer);

  // TCP Header
  tcph->source  = forward ? this->src_port : this->dst_port;
  tcph->dest    = forward ? this->dst_port : this->src_port;
  tcph->seq     = 0;
  tcph->ack_seq = 0;
  tcph->doff    = 5; // tcp header size
  tcph->fin     = 0;
  tcph->syn     = 0;
  tcph->rst     = 0;
  tcph->psh     = 0;
  tcph->ack     = 0;
  tcph->urg     = 0;
  tcph->window  = htons(5840); /* maximum allowed window size */
  tcph->check   = 0;           // leave checksum 0 now, filled later by pseudo header
  tcph->urg_ptr = 0;
  return 1;
}

void
GreInfo::init(const char *argv[], int argc)
{
  this->clientaddr.sin_family      = AF_INET;
  this->clientaddr.sin_addr.s_addr = inet_addr("127.0.0.2");
  this->src_addr                   = inet_addr("127.0.0.2");
  this->dst_addr                   = inet_addr("127.1.0.2");
}

int
open_raw_socket()
{
  // Must acquire CAP_NET_RAW capability
  cap_t new_cap_state = cap_get_proc();
  cap_value_t cap_list[1];
  cap_list[0] = CAP_NET_RAW;
  cap_set_flag(new_cap_state, CAP_EFFECTIVE, 1, cap_list, CAP_SET);
  if (cap_set_proc(new_cap_state) != 0) {
    perror("cap_set_proc set");
    cap_free(new_cap_state);
    return 0;
  }
  Raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
  if (Raw_socket < 0) {
    perror("socket() error");
  }
  // Drop the extra privilege
  cap_set_flag(new_cap_state, CAP_EFFECTIVE, 1, cap_list, CAP_CLEAR);
  if (cap_set_proc(new_cap_state) != 0) {
    perror("cap_set_proc clear");
    cap_free(new_cap_state);
    return 0;
  }
  cap_free(new_cap_state);
  return Raw_socket > 0;
}

int
GreInfo::send_packet(char *buffer, struct iovec *ios, int iovec_count)
{
  ssize_t num_bytes;
  // Fetch or create the raw_socket
  if (Raw_socket <= 0) {
    if (!open_raw_socket()) {
      return 0;
    }
  }
  if (iovec_count == 0) {
    num_bytes =
      sendto(Raw_socket, buffer, TeeInfo::full_hdr_size, 0, (struct sockaddr *)&this->clientaddr, sizeof(struct sockaddr_in));
  } else {
    // Use vectoring mechanism to avoid copying payload yet again
    struct msghdr msg;
    msg.msg_name       = &this->clientaddr;
    msg.msg_namelen    = sizeof(struct sockaddr_in);
    msg.msg_iov        = ios;
    msg.msg_iovlen     = iovec_count;
    msg.msg_control    = nullptr;
    msg.msg_controllen = 0;
    msg.msg_flags      = 0;

    num_bytes = sendmsg(Raw_socket, &msg, 0);
  }
  if (num_bytes == -1) {
    perror("sendmsg");
    fprintf(stderr, "unable to send Message\n");
    return 0;
  }
  return 1;
}

int
TeeInfo::send_handshake()
{
  char buffer[TeeInfo::full_hdr_size] = {0};
  this->build_packet(buffer, 0, true);
  struct tcphdr *tcph = get_tcp_hdr(buffer);
  tcph->syn           = 1;
  if (!gre_info.send_packet(buffer, nullptr, 0)) {
    return 0;
  }

  this->build_packet(buffer, 0, false);
  tcph          = get_tcp_hdr(buffer);
  tcph->syn     = 1;
  tcph->ack     = 1;
  tcph->ack_seq = htonl(1);
  if (!gre_info.send_packet(buffer, nullptr, 0)) {
    return 0;
  }

  this->build_packet(buffer, 0, true);
  tcph                = get_tcp_hdr(buffer);
  tcph->ack           = 1;
  tcph->ack_seq       = htonl(1);
  tcph->seq           = htonl(1);
  this->forward_seqno = 1;
  this->reverse_seqno = 1;
  if (!gre_info.send_packet(buffer, nullptr, 0)) {
    return 0;
  }

  return 1;
}

// Returns the next sequence number or -1
int
TeeInfo::send_data(TSIOBufferReader reader, bool forward)
{
  char buffer[TeeInfo::full_hdr_size] = {0};
  struct iovec ios[IOV_MAX];
  int iov_count = 1;

  // How much data?
  int64_t data_len;
  const char *buf;
  int64_t total_size  = 0;
  TSIOBufferBlock blk = TSIOBufferReaderStart(reader);
  while (blk != nullptr && iov_count < IOV_MAX && total_size < 65535) {
    buf                      = TSIOBufferBlockReadStart(blk, reader, &data_len);
    ios[iov_count].iov_base  = const_cast<char *>(buf);
    ios[iov_count++].iov_len = data_len;
    total_size += data_len;
    blk = TSIOBufferBlockNext(blk);
  }
  this->build_packet(buffer, total_size, forward);
  ios[0].iov_base     = buffer;
  ios[0].iov_len      = TeeInfo::full_hdr_size;
  struct tcphdr *tcph = get_tcp_hdr(buffer);
  tcph->seq           = htonl(forward ? this->forward_seqno : this->reverse_seqno);
  tcph->ack_seq       = htonl(!forward ? this->forward_seqno : this->reverse_seqno);
  if (!gre_info.send_packet(nullptr, ios, iov_count)) {
    return 0;
  }

  if (forward) {
    this->forward_seqno += total_size;
  } else {
    this->reverse_seqno += total_size;
  }

  // Send the ACK immediately
  this->build_packet(buffer, 0, !forward);
  tcph          = get_tcp_hdr(buffer);
  tcph->ack_seq = htonl(forward ? this->forward_seqno : this->reverse_seqno);
  tcph->seq     = htonl(!forward ? this->forward_seqno : this->reverse_seqno);
  tcph->ack     = 1;
  if (!gre_info.send_packet(buffer, nullptr, 0)) {
    return 0;
  }

  return 1;
}

int
TeeInfo::send_header(TSMBuffer bufp, TSMLoc hdr, bool forward)
{
  TSIOBuffer iobuffer = TSIOBufferCreate();
  TSHttpHdrPrint(bufp, hdr, iobuffer);
  int retval = this->send_data(TSIOBufferReaderAlloc(iobuffer), forward);
  TSIOBufferDestroy(iobuffer);
  return retval;
}
