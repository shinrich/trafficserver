#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "ts/ts.h"

class TeeInfo
{
public:
  TeeInfo(sockaddr const *src_addr, sockaddr const *dst_addr);
  int build_packet(char *buffer, int payload_size, bool forward);
  int send_data(TSIOBufferReader reader, bool forward = true);
  int send_header(TSMBuffer bufp, TSMLoc hdr, bool forward = true);
  int send_handshake();

  static const int full_hdr_size = 2 * sizeof(struct iphdr) + sizeof(struct tcphdr) + 4;

private:
  uint32_t forward_seqno = 0;
  uint32_t reverse_seqno = 0;
  uint16_t src_port      = 0;
  uint16_t dst_port      = 0;
  in_addr_t src_addr     = 0;
  in_addr_t dst_addr     = 0;
};

class GreInfo
{
public:
  void init(const char *argv[], int argc);
  int send_packet(char *, struct iovec *data, int data_count);
  in_addr_t src_addr = 0;
  in_addr_t dst_addr = 0;

private:
  struct sockaddr_in clientaddr;
};

extern GreInfo gre_info;
