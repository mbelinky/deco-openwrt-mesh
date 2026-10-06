// SPDX-License-Identifier: MIT
/* Native TIPC discovery control. No application payloads or notifications. */
#define _GNU_SOURCE
#include <errno.h>
#include <endian.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/genetlink.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/tipc_netlink.h>
#include <linux/tipc.h>
#include <net/if.h>
#include <signal.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int fd, family, sequence, main_up, status_service;
static uint32_t main_addr;
static int native_receiver, receiver_fd = -1, receiver_bound, receiver_publication, receiver_closed;
static unsigned long long receiver_main, receiver_foreign, receiver_packets, responses_published, requests_sent;
static int receiver_errors;
static int native_request, native_request_sent, native_request_error, main_configuration_service;
static int native_response, response_saved, response_bytes, response_error;
static int native_resident;
static time_t last_request;
static const char *response_path = "/tmp/estudio-tipc-response";
static int capture_fd = -1, packets, incoming_discovery, outgoing_discovery, main_discovery;
static int main_media_deco, main_role_master, main_role_slave, main_role_invalid;
static int main_discovery_requests, main_discovery_replies;
static int own_media_slave, own_media_master, own_media_invalid, own_media_source_match, own_media_interface_match;
static int main_reply_unicast_own, main_reply_multicast, main_reply_foreign;
static int reset_contract_match, reset_source_match, reset_origin_match;
static uint32_t reset_session, reset_redundant, reset_bearer, reset_plane, reset_mtu;
static unsigned char reset_wire_header[40];
static char reset_wire_header_hex[81];
static int reset_wire_observed, reset_wire_changes, reset_name_observed, reset_name_prefix, reset_name_padding_zero;
static unsigned char own_interface_mac[6];
static int main_peer_seen, incoming_link_control, outgoing_link_control;
static uint32_t main_domain, main_caps;
static uint32_t own_discovery_caps, own_discovery_signature, own_discovery_domain;
static int own_discovery_changes, own_discovery_identity_changes;
static uint32_t outgoing_control_type, outgoing_control_header, outgoing_control_size, outgoing_control_destination;
static int main_reset, main_activate, main_state, main_media_seen, outgoing_dest_matches_main;
static unsigned char main_media_mac[6], outgoing_dest_mac[6];
static unsigned char main_source_mac[6];
static int port_fd[4] = {-1, -1, -1, -1}, port_headers[4], port_outgoing[4], port_incoming[4];
static int physical_main_untagged[2], physical_main_vlan1[2], physical_main_other_vlan[2];
static int physical_incoming_own_node[2], physical_node_filter_set;
static int physical_main_source_alias[2];
static int control_filter_set;
static int native_path;
static uint32_t own_addr;
static int tx_status, tx_fd = -1, tx_headers, tx_ack, tx_fail, tx_unclassified, tx_retries;
static unsigned char tx_sta_mac[6];
static const unsigned char tx_main_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x15};
static volatile sig_atomic_t stopping;
static void stop(int unused) { (void)unused; stopping = 1; }
static size_t align4(size_t n) { return (n + 3) & ~3U; }
static size_t attr(char *buf, int type, const void *data, size_t len)
{
    struct nlattr a = {.nla_len = sizeof(a) + len, .nla_type = type};
    memcpy(buf, &a, sizeof(a));
    if (len) memcpy(buf + sizeof(a), data, len);
    memset(buf + a.nla_len, 0, align4(a.nla_len) - a.nla_len);
    return align4(a.nla_len);
}
static struct nlattr *find_attr(char *buf, size_t len, int type)
{
    while (len >= sizeof(struct nlattr)) {
        struct nlattr *a = (void *)buf;
        if (a->nla_len < sizeof(*a) || a->nla_len > len) return NULL;
        if ((a->nla_type & NLA_TYPE_MASK) == type) return a;
        size_t n = align4(a->nla_len);
        if (n > len) return NULL;
        len -= n; buf += n;
    }
    return NULL;
}
static struct nlattr *child(struct nlattr *a, int type)
{
    return a ? find_attr((char *)a + sizeof(*a), a->nla_len - sizeof(*a), type) : NULL;
}
static uint32_t number(struct nlattr *a)
{
    uint32_t n = 0;
    if (a && a->nla_len == sizeof(*a) + sizeof(n)) memcpy(&n, (char *)a + sizeof(*a), sizeof(n));
    return n;
}
static int control_filter(int socket_fd)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x88ca, 0, 13),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 14),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x1e000000),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 7U << 25, 0, 10),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 26),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, main_addr, 7, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, own_addr, 0, 7),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 14),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xffe1ffff),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (2U << 29) | (7U << 25) | (10U << 21) | 56U, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 18),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xe0000000),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1U << 29, 2, 0),
        BPF_STMT(BPF_RET | BPF_K, 62),
        BPF_STMT(BPF_RET | BPF_K, 0),
        BPF_STMT(BPF_RET | BPF_K, 70),
    };
    struct sock_fprog program = {.len = sizeof(filter) / sizeof(filter[0]), .filter = filter};
    return setsockopt(socket_fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program));
}
static int physical_control_filter(int socket_fd)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LDX | BPF_IMM, 0),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x8100, 0, 1),
        BPF_STMT(BPF_LDX | BPF_IMM, 4),
        BPF_STMT(BPF_LD | BPF_H | BPF_IND, 12),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x88ca, 0, 7),
        BPF_STMT(BPF_LD | BPF_W | BPF_IND, 14),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xfe000000),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (2U << 29) | (7U << 25), 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_IND, 26),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, main_addr, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, own_addr, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 66),
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
    struct sock_fprog program = {.len = sizeof(filter) / sizeof(filter[0]), .filter = filter};
    return setsockopt(socket_fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program));
}
/* Only actual mac80211 TX-completion RESET headers reach this socket.
 * Virtual monitoring disables header offload; this is an explicit path trial. */
static int tx_filter(int socket_fd)
{
    struct sock_filter f[512]; unsigned int n = 0;
#define EMIT(c, t, j, v) f[n++] = (struct sock_filter){(c), (t), (j), (v)}
#define REQUIRE(c, v) do { EMIT(BPF_JMP | (c) | BPF_K, 1, 0, (v)); EMIT(BPF_RET | BPF_K, 0, 0, 0); } while (0)
    EMIT(BPF_LD | BPF_B | BPF_ABS, 0, 0, 0); REQUIRE(BPF_JEQ, 0);
    EMIT(BPF_LD | BPF_B | BPF_ABS, 0, 0, 3); REQUIRE(BPF_JEQ, 0);
    EMIT(BPF_LD | BPF_B | BPF_ABS, 0, 0, 2); REQUIRE(BPF_JGE, 11);
    EMIT(BPF_JMP | BPF_JGT | BPF_K, 0, 1, 64); EMIT(BPF_RET | BPF_K, 0, 0, 0);
    EMIT(BPF_MISC | BPF_TAX, 0, 0, 0);
    EMIT(BPF_LD | BPF_B | BPF_ABS, 0, 0, 5); REQUIRE(BPF_JSET, 0x80);
    EMIT(BPF_LD | BPF_B | BPF_IND, 0, 0, 0);
    EMIT(BPF_ALU | BPF_AND | BPF_K, 0, 0, 0x0c); REQUIRE(BPF_JEQ, 8);
    const unsigned char *macs[] = {tx_main_mac, tx_sta_mac};
    for (int m = 0; m < 2; m++) {
        uint32_t word; uint16_t tail;
        memcpy(&word, macs[m], 4); memcpy(&tail, macs[m] + 4, 2);
        EMIT(BPF_LD | BPF_W | BPF_IND, 0, 0, 4 + m * 6); REQUIRE(BPF_JEQ, ntohl(word));
        EMIT(BPF_LD | BPF_H | BPF_IND, 0, 0, 8 + m * 6); REQUIRE(BPF_JEQ, ntohs(tail));
    }
    const unsigned int llc_offsets[] = {24, 26, 30, 32, 34, 38, 40};
    for (unsigned int h = 0; h < sizeof(llc_offsets) / sizeof(llc_offsets[0]); h++) {
        for (int vlan = 0; vlan < 2; vlan++) {
            unsigned int start = n, hlen = llc_offsets[h], payload = hlen + 8 + vlan * 4;
            EMIT(BPF_LD | BPF_W | BPF_IND, 0, 0, hlen);
            EMIT(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 0xaaaa0300);
            EMIT(BPF_LD | BPF_H | BPF_IND, 0, 0, hlen + 4);
            EMIT(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 0);
            EMIT(BPF_LD | BPF_H | BPF_IND, 0, 0, hlen + 6);
            EMIT(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, vlan ? 0x8100 : 0x88ca);
            if (vlan) {
                EMIT(BPF_LD | BPF_H | BPF_IND, 0, 0, hlen + 8);
                EMIT(BPF_ALU | BPF_AND | BPF_K, 0, 0, 0xfff);
                EMIT(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1);
                EMIT(BPF_LD | BPF_H | BPF_IND, 0, 0, hlen + 10);
                EMIT(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 0x88ca);
            }
            EMIT(BPF_LD | BPF_W | BPF_IND, 0, 0, payload);
            EMIT(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, (2U << 29) | (7U << 25) | (10U << 21) | 56);
            EMIT(BPF_LD | BPF_W | BPF_IND, 0, 0, payload + 4);
            EMIT(BPF_ALU | BPF_AND | BPF_K, 0, 0, 0xe0000000);
            EMIT(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1U << 29);
            EMIT(BPF_LD | BPF_W | BPF_IND, 0, 0, payload + 12);
            EMIT(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, own_addr);
            EMIT(BPF_LD | BPF_W | BPF_IND, 0, 0, payload + 28);
            EMIT(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, main_addr);
            EMIT(BPF_MISC | BPF_TXA, 0, 0, 0);
            EMIT(BPF_ALU | BPF_ADD | BPF_K, 0, 0, payload + 40);
            EMIT(BPF_RET | BPF_A, 0, 0, 0);
            for (unsigned int i = start; i < n; i++)
                if (f[i].code == (BPF_JMP | BPF_JEQ | BPF_K)) f[i].jf = n - i - 1;
        }
    }
    EMIT(BPF_RET | BPF_K, 0, 0, 0);
#undef REQUIRE
#undef EMIT
    struct sock_fprog program = {.len = n, .filter = f};
    return setsockopt(socket_fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program));
}
static int tx_open(void)
{
    tx_fd = socket(AF_PACKET, SOCK_RAW, htons(0x0003));
    if (tx_fd < 0) return -1;
    struct ifreq interface = {0}; strcpy(interface.ifr_name, "deco-sixsta");
    if (ioctl(tx_fd, SIOCGIFHWADDR, &interface)) return -1;
    memcpy(tx_sta_mac, interface.ifr_hwaddr.sa_data, 6);
    const unsigned char admitted[] = {2, 3, 0x8e, 0x7c, 0xf4, 0xd3};
    if (memcmp(tx_sta_mac, admitted, 6)) return -1;
    struct sockaddr_ll addr = {.sll_family = AF_PACKET, .sll_protocol = htons(0x0003),
        .sll_ifindex = if_nametoindex("deco-txmon")};
    if (!addr.sll_ifindex || tx_filter(tx_fd) || bind(tx_fd, (void *)&addr, sizeof(addr))) return -1;
    return 0;
}
static void capture_tx(void)
{
    if (tx_fd < 0) return;
    while (tx_headers < 128) {
        unsigned char header[160];
        ssize_t length = recv(tx_fd, header, sizeof(header), MSG_DONTWAIT);
        if (length < 0) break;
        tx_headers++;
        if (length < 11) { tx_unclassified++; continue; }
        uint32_t present; memcpy(&present, header + 4, 4); present = le32toh(present);
        const uint32_t allowed = (1U << 2) | (1U << 15) | (1U << 17) |
            (1U << 19) | (1U << 21) | (1U << 23);
        unsigned int rtlen = header[2] | ((unsigned int)header[3] << 8);
        unsigned int flags_offset = 8 + ((present & (1U << 2)) ? 2 : 0);
        if ((present & ~allowed) || !(present & (1U << 17)) ||
            rtlen <= flags_offset + 2 || rtlen > (unsigned int)length) {
            tx_unclassified++; continue;
        }
        uint16_t flags; memcpy(&flags, header + flags_offset, 2); flags = le16toh(flags);
        if (flags & 1) tx_fail++; else tx_ack++;
        tx_retries += header[flags_offset + 2];
    }
}
static void capture_ports(void)
{
    for (int i = 0; i < 4; i++) {
        while (port_headers[i] < 128) {
            unsigned char header[66]; struct sockaddr_ll peer; socklen_t size = sizeof(peer);
            unsigned char ancillary[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
            struct iovec vector = {.iov_base = header, .iov_len = sizeof(header)};
            struct msghdr message = {.msg_name = &peer, .msg_namelen = size, .msg_iov = &vector,
                .msg_iovlen = 1, .msg_control = ancillary, .msg_controllen = sizeof(ancillary)};
            ssize_t n = recvmsg(port_fd[i], &message, MSG_DONTWAIT);
            if (n < 0) break;
            port_headers[i]++;
            int tagged = n >= 18 && header[12] == 0x81 && header[13] == 0;
            int offset = tagged ? 4 : 0;
            int vlan = tagged ? ((header[14] & 15) << 8) | header[15] : 0;
            int vlan_present = tagged;
            for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
                if (c->cmsg_level == SOL_PACKET && c->cmsg_type == PACKET_AUXDATA &&
                    c->cmsg_len >= CMSG_LEN(sizeof(struct tpacket_auxdata))) {
                    struct tpacket_auxdata auxiliary;
                    memcpy(&auxiliary, CMSG_DATA(c), sizeof(auxiliary));
                    if (!tagged && (auxiliary.tp_status & TP_STATUS_VLAN_VALID)) {
                        vlan = auxiliary.tp_vlan_tci & 0xfff;
                        vlan_present = 1;
                    }
                }
            }
            if (n < 30 + offset) continue;
            uint32_t word; memcpy(&word, header + 14 + offset, 4); word = ntohl(word);
            uint32_t address; memcpy(&address, header + 26 + offset, 4); address = ntohl(address);
            if ((word >> 29) != 2) continue;
            if (((word >> 25) & 15) != 7) continue;
            if (peer.sll_pkttype == PACKET_OUTGOING && address == own_addr) port_outgoing[i]++;
            else if (peer.sll_pkttype != PACKET_OUTGOING &&
                     address == main_addr) {
                port_incoming[i]++;
                if (i >= 2) {
                    if (main_media_seen && memcmp(header + 6, main_source_mac, 6)) physical_main_source_alias[i - 2]++;
                    if (!vlan_present) physical_main_untagged[i - 2]++;
                    else if (vlan == 1) physical_main_vlan1[i - 2]++;
                    else physical_main_other_vlan[i - 2]++;
                }
            } else if (i >= 2 && peer.sll_pkttype != PACKET_OUTGOING && address == own_addr) {
                physical_incoming_own_node[i - 2]++;
            }
        }
    }
}
static void capture(void)
{
    while (packets < 128) {
        unsigned char header[70];
        struct sockaddr_ll peer;
        socklen_t peer_size = sizeof(peer);
        ssize_t n = recvfrom(capture_fd, header, sizeof(header), MSG_DONTWAIT, (void *)&peer, &peer_size);
        if (n < 0) break;
        packets++;
        if (n < 34) continue;
        uint32_t word, address, network, control, domain;
        memcpy(&word, header + 14, 4); word = ntohl(word);
        memcpy(&address, header + 26, 4); address = ntohl(address);
        memcpy(&network, header + 30, 4); network = ntohl(network);
        memcpy(&control, header + 18, 4); control = ntohl(control);
        memcpy(&domain, header + 22, 4); domain = ntohl(domain);
        if ((word >> 29) == 2 && ((word >> 25) & 15) == 7) {
            if (peer.sll_pkttype == PACKET_OUTGOING) {
                if (!outgoing_link_control) {
                    outgoing_control_type = control >> 29;
                    outgoing_control_header = ((word >> 21) & 15) * 4;
                    outgoing_control_size = word & 0x1ffff;
                    if (n >= 46) { memcpy(&outgoing_control_destination, header + 42, 4); outgoing_control_destination = ntohl(outgoing_control_destination); }
                    memcpy(outgoing_dest_mac, header, 6);
                }
                outgoing_link_control++;
                if ((control >> 29) == 1 && n >= 54) {
                    uint32_t origin, destination, link, packet;
                    memcpy(&origin, header + 38, 4); origin = ntohl(origin);
                    memcpy(&destination, header + 42, 4); destination = ntohl(destination);
                    memcpy(&link, header + 34, 4); link = ntohl(link);
                    memcpy(&packet, header + 50, 4); packet = ntohl(packet);
                    reset_session = link >> 16;
                    reset_redundant = (link >> 12) & 1;
                    reset_bearer = (link >> 9) & 7;
                    reset_plane = (link >> 1) & 7;
                    reset_mtu = (packet >> 16) * 4;
                    if (((word >> 21) & 15) == 10 && (word & 0x1ffff) == 56 && address == own_addr) {
                        if (!reset_wire_observed) {
                            memcpy(reset_wire_header, header + 14, 40);
                            for (int j = 0; j < 40; j++) snprintf(reset_wire_header_hex + 2*j, 3, "%02x", reset_wire_header[j]);
                            reset_wire_observed = 1;
                        } else if (memcmp(reset_wire_header, header + 14, 8) || memcmp(reset_wire_header + 12, header + 26, 28)) {
                            reset_wire_changes++;
                        }
                        if (n >= 70) {
                            reset_name_observed++;
                            if (!memcmp(header + 54, "br-lan", 7)) reset_name_prefix++;
                            int zero = 1;
                            for (int j = 61; j < 70; j++) if (header[j]) zero = 0;
                            if (zero) reset_name_padding_zero++;
                        }
                    }
                    if (!memcmp(header + 6, own_interface_mac, 6)) reset_source_match++;
                    if (origin == own_addr) reset_origin_match++;
                    if (((word >> 21) & 15) == 10 && (word & 0x1ffff) == 56 &&
                        address == own_addr && origin == own_addr && destination == main_addr &&
                        !reset_redundant && !reset_bearer && !reset_plane &&
                        reset_mtu >= 128 && reset_mtu <= 1500 &&
                        (!native_path || (n >= 61 && !memcmp(header + 54, "br-lan", 7))))
                        reset_contract_match++;
                }
            } else if (address == main_addr) {
                incoming_link_control++;
                if ((control >> 29) == 0) main_state++;
                if ((control >> 29) == 1) main_reset++;
                if ((control >> 29) == 2) main_activate++;
            }
        }
        if ((word >> 29) != 2 || ((word >> 25) & 15) != 13 || network != 4711) continue;
        if (peer.sll_pkttype == PACKET_OUTGOING) {
            uint32_t caps = (control >> 15) & 0x1fff, signature = control & 0xffff;
            if (!outgoing_discovery) {
                own_discovery_caps = caps; own_discovery_signature = signature; own_discovery_domain = domain;
            } else if (caps != own_discovery_caps || signature != own_discovery_signature || domain != own_discovery_domain) {
                own_discovery_changes++;
            }
            if (outgoing_discovery && (caps != own_discovery_caps || signature != own_discovery_signature)) own_discovery_identity_changes++;
            outgoing_discovery++;
            if (n >= 47) {
                if (header[37] != 5 || header[46] > 1) own_media_invalid++;
                else if (header[46] == 0) own_media_slave++;
                else own_media_master++;
                if (!memcmp(header + 38, header + 6, 6)) own_media_source_match++;
                if (!memcmp(header + 38, own_interface_mac, 6)) own_media_interface_match++;
            }
        }
        else {
            incoming_discovery++;
            if (address == main_addr) {
                if (!main_discovery) { main_domain = domain; main_caps = (control >> 15) & 0x1fff; }
                main_discovery++;
                if ((control >> 29) == 0) main_discovery_requests++;
                if ((control >> 29) == 1) {
                    main_discovery_replies++;
                    if (header[0] & 1) main_reply_multicast++;
                    else if (!memcmp(header, own_interface_mac, 6)) main_reply_unicast_own++;
                    else main_reply_foreign++;
                }
                if (n >= 47) {
                    if (header[37] == 5) main_media_deco++;
                    memcpy(main_media_mac, header + 38, 6); main_media_seen = 1;
                    memcpy(main_source_mac, header + 6, 6);
                    if (header[46] == 1) main_role_master++;
                    else if (header[46] == 0) main_role_slave++;
                    else main_role_invalid++;
                }
            }
        }
    }
}
static void observe(struct nlmsghdr *h, int command)
{
    if (h->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN) return;
    char *data = (char *)h + NLMSG_HDRLEN + GENL_HDRLEN;
    size_t len = h->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
    if (command == CTRL_CMD_GETFAMILY) {
        struct nlattr *a = find_attr(data, len, CTRL_ATTR_FAMILY_ID);
        uint16_t id = 0;
        if (a && a->nla_len == sizeof(*a) + sizeof(id)) memcpy(&id, (char *)a + sizeof(*a), sizeof(id));
        family = id;
    } else if (command == TIPC_NL_NODE_GET) {
        struct nlattr *a = find_attr(data, len, TIPC_NLA_NODE);
        if (number(child(a, TIPC_NLA_NODE_ADDR)) == main_addr) {
            main_peer_seen = 1;
            if (child(a, TIPC_NLA_NODE_UP)) main_up = 1;
        }
    } else if (command == TIPC_NL_NAME_TABLE_GET) {
        struct nlattr *a = child(find_attr(data, len, TIPC_NLA_NAME_TABLE), TIPC_NLA_NAME_TABLE_PUBL);
        if (native_receiver && number(child(a, TIPC_NLA_PUBL_NODE)) == own_addr &&
            number(child(a, TIPC_NLA_PUBL_TYPE)) == 6000 &&
            number(child(a, TIPC_NLA_PUBL_LOWER)) == 100 &&
            number(child(a, TIPC_NLA_PUBL_UPPER)) == 100) receiver_publication = 1;
        if (number(child(a, TIPC_NLA_PUBL_NODE)) == main_addr &&
            number(child(a, TIPC_NLA_PUBL_TYPE)) == 5000 &&
            number(child(a, TIPC_NLA_PUBL_LOWER)) == 100 &&
            number(child(a, TIPC_NLA_PUBL_UPPER)) == 100) main_configuration_service = 1;
        if (number(child(a, TIPC_NLA_PUBL_NODE)) == main_addr &&
            number(child(a, TIPC_NLA_PUBL_TYPE)) == 8001 &&
            number(child(a, TIPC_NLA_PUBL_LOWER)) <= 100 &&
            number(child(a, TIPC_NLA_PUBL_UPPER)) >= 100) status_service = 1;
    }
}
static int request(int type, int command, int dump, char *attrs, size_t len)
{
    char buf[8192] = {0};
    struct nlmsghdr *h = (void *)buf;
    struct genlmsghdr *g = (void *)(buf + NLMSG_HDRLEN);
    h->nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN + len;
    h->nlmsg_type = type; h->nlmsg_seq = ++sequence;
    h->nlmsg_flags = NLM_F_REQUEST | (dump ? NLM_F_DUMP : NLM_F_ACK);
    g->cmd = command; g->version = 1;
    memcpy(buf + NLMSG_HDRLEN + GENL_HDRLEN, attrs, len);
    struct sockaddr_nl dst = {.nl_family = AF_NETLINK};
    if (sendto(fd, buf, h->nlmsg_len, 0, (void *)&dst, sizeof(dst)) < 0) return -errno;
    for (int packet = 0; packet < 128; packet++) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) return -errno;
        for (h = (void *)buf; NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_seq != (unsigned)sequence) continue;
            if (h->nlmsg_type == NLMSG_ERROR) {
                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) return -EPROTO;
                return ((struct nlmsgerr *)NLMSG_DATA(h))->error;
            }
            if (h->nlmsg_type == NLMSG_DONE) return 0;
            observe(h, command);
        }
    }
    return -EOVERFLOW;
}
static int bearer(int enable)
{
    char inner[128] = {0}, outer[160] = {0};
    const char *name = native_path ? (enable ? "deco:br-lan:0" : "deco:br-lan") :
        (enable ? "deco:br-sixbh:0" : "deco:br-sixbh");
    size_t n = attr(inner, TIPC_NLA_BEARER_NAME, name, strlen(name) + 1);
    n = attr(outer, TIPC_NLA_BEARER, inner, n);
    return request(family, enable ? TIPC_NL_BEARER_ENABLE : TIPC_NL_BEARER_DISABLE, 0, outer, n);
}
static int receive_native(void)
{
    for (int batch = 0; batch < 128 && (native_resident || receiver_packets < 128); batch++) {
        if (native_resident) {
            struct stat pending;
            if (!lstat(response_path, &pending)) {
                if (!S_ISREG(pending.st_mode) || pending.st_uid || (pending.st_mode & 077)) return -EPERM;
                return 0; /* The validator owns consumption; leave later datagrams queued. */
            }
            if (errno != ENOENT) return -errno;
        }
        struct sockaddr_tipc sender = {0};
        socklen_t length = sizeof(sender);
        unsigned char data[4096];
        ssize_t size = recvfrom(receiver_fd, data, native_response ? sizeof(data) : 1, MSG_DONTWAIT | MSG_TRUNC,
                                (void *)&sender, &length);
        if (size < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
            receiver_errors++;
            return -errno;
        }
        receiver_packets++;
        if (length == sizeof(sender) && sender.family == AF_TIPC &&
            sender.addrtype == TIPC_SOCKET_ADDR && sender.addr.id.node == main_addr) {
            receiver_main++;
            if (native_response && native_request_sent && (native_resident || !response_saved)) {
                if (size < 2 || size > (ssize_t)sizeof(data) ||
                    data[size - 1] || memchr(data, 0, (size_t)size - 1)) {
                    response_error = EMSGSIZE;
                    return -response_error;
                }
                char temporary[512];
                int count = snprintf(temporary, sizeof(temporary), "%s.new", response_path);
                if (count < 0 || count >= (int)sizeof(temporary)) return -EOVERFLOW;
                int output = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
                if (output < 0) { response_error = errno; return -response_error; }
                ssize_t written = write(output, data, (size_t)size - 1);
                int closed = close(output);
                if (written != size - 1 || closed) {
                    unlink(temporary);
                    response_error = EIO;
                    return -response_error;
                }
                if (link(temporary, response_path)) {
                    response_error = errno;
                    unlink(temporary);
                    return -response_error;
                }
                if (unlink(temporary)) { response_error = errno; return -response_error; }
                response_saved = 1;
                response_bytes = (int)written;
                responses_published++;
            }
        } else receiver_foreign++;
    }
    return 0;
}
static int resident_state(int running)
{
    char body[768];
    int count = snprintf(body, sizeof(body),
        "{\"version\":1,\"pid\":%d,\"observed_at\":%lld,\"running\":%s,\"node_address\":%u,\"main_address\":%u,\"main_link_up\":%s,\"main_configuration_service\":%s,\"receiver_publication\":%s,\"request_sent\":%s,\"response_saved\":%s,\"main_datagrams\":%llu,\"foreign_datagrams\":%llu,\"received_datagrams\":%llu,\"responses_published\":%llu,\"requests_sent\":%llu}\n",
        getpid(), (long long)time(NULL), running ? "true" : "false", own_addr, main_addr,
        main_up ? "true" : "false", main_configuration_service ? "true" : "false",
        receiver_publication ? "true" : "false", native_request_sent ? "true" : "false",
        response_saved ? "true" : "false", receiver_main, receiver_foreign, receiver_packets,
        responses_published, requests_sent);
    if (count < 0 || count >= (int)sizeof(body)) return -EOVERFLOW;
    const char *path = "/tmp/estudio-mesh-resident/tipc-state.json.new";
    int output = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (output < 0) return -errno;
    ssize_t written = write(output, body, (size_t)count);
    int closed = close(output);
    if (written != count || closed) return -EIO;
    return rename(path, "/tmp/estudio-mesh-resident/tipc-state.json") ? -errno : 0;
}
int main(int argc, char **argv)
{
    if (argc < 3 || argc > 5) return 2;
    native_path = argc >= 4;
    if (native_path && strcmp(argv[3], "--native-path")) return 2;
    if (argc == 5) {
        if (!strcmp(argv[4], "--tx-status")) tx_status = 1;
        else if (!strcmp(argv[4], "--native-receiver")) native_receiver = 1;
        else if (!strcmp(argv[4], "--native-request")) native_receiver = native_request = 1;
        else if (!strcmp(argv[4], "--native-response")) native_receiver = native_request = native_response = 1;
        else if (!strcmp(argv[4], "--native-resident")) {
            native_receiver = native_request = native_response = native_resident = 1;
            response_path = "/tmp/estudio-mesh-resident/tipc-response";
        }
        else return 2;
    }
    char *end;
    unsigned long address = strtoul(argv[1], &end, 10);
    if (*end || address > UINT32_MAX || !address) return 2;
    unsigned long master = strtoul(argv[2], &end, 10);
    if (*end || master > UINT32_MAX || !master || master == address) return 2;
    main_addr = master;
    own_addr = address;
    signal(SIGTERM, stop); signal(SIGINT, stop);
    const char *ports[] = {"sixbh.1", "standby.1", "deco-sixsta", "deco-standby"};
    for (int i = 0; !native_resident && i < 4; i++) {
        port_fd[i] = socket(AF_PACKET, SOCK_RAW, htons(0x0003));
        int auxiliary = 1;
        struct sockaddr_ll port_addr = {.sll_family = AF_PACKET, .sll_protocol = htons(0x0003), .sll_ifindex = if_nametoindex(ports[i])};
        if (port_fd[i] < 0 || !port_addr.sll_ifindex ||
            setsockopt(port_fd[i], SOL_PACKET, PACKET_AUXDATA, &auxiliary, sizeof(auxiliary)) ||
            (i < 2 ? control_filter(port_fd[i]) : physical_control_filter(port_fd[i])) ||
            bind(port_fd[i], (void *)&port_addr, sizeof(port_addr))) return 3;
    }
    physical_node_filter_set = !native_resident;
    if (tx_status && tx_open()) return 3;
    if (native_path) {
        int netns = open("/var/run/netns/codex-sixbh-client", O_RDONLY | O_CLOEXEC);
        if (netns < 0 || setns(netns, CLONE_NEWNET)) return 3;
        close(netns);
    }
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (fd < 0) return 3;
    struct timeval timeout = {.tv_sec = 2};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    if (bind(fd, (void *)&local, sizeof(local))) return 3;
    if (!native_resident) {
    capture_fd = socket(AF_PACKET, SOCK_RAW, htons(0x0003));
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x88ca, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 26),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, main_addr, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, address, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 62),
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
    struct sock_fprog program = {.len = sizeof(filter) / sizeof(filter[0]), .filter = filter};
    if (capture_fd < 0 || setsockopt(capture_fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program))) return 3;
    struct sockaddr_ll packet_addr = {.sll_family = AF_PACKET, .sll_protocol = htons(0x0003), .sll_ifindex = if_nametoindex(native_path ? "br-lan" : "br-sixbh")};
    if (capture_fd < 0 || !packet_addr.sll_ifindex || bind(capture_fd, (void *)&packet_addr, sizeof(packet_addr))) return 3;
    struct ifreq interface = {0};
    strcpy(interface.ifr_name, native_path ? "br-lan" : "br-sixbh");
    if (ioctl(capture_fd, SIOCGIFHWADDR, &interface)) return 3;
    memcpy(own_interface_mac, interface.ifr_hwaddr.sa_data, 6);
    }
    char attrs[256] = {0}, inner[128] = {0};
    size_t n = attr(attrs, CTRL_ATTR_FAMILY_NAME, TIPC_GENL_V2_NAME, sizeof(TIPC_GENL_V2_NAME));
    int error = request(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0, attrs, n);
    int enabled = 0, cleanup = 0;
    if (!error && !family) error = -ENOENT;
    if (!error) {
        uint32_t id = 4711, addr = address;
        n = attr(inner, TIPC_NLA_NET_ID, &id, sizeof(id));
        n += attr(inner + n, TIPC_NLA_NET_ADDR, &addr, sizeof(addr));
        n = attr(attrs, TIPC_NLA_NET, inner, n);
        error = request(family, TIPC_NL_NET_SET, 0, attrs, n);
    }
    if (!error && native_receiver) {
        struct sockaddr_tipc service = {.family = AF_TIPC, .addrtype = TIPC_SERVICE_RANGE,
            .scope = TIPC_CLUSTER_SCOPE, .addr.nameseq = {.type = 6000, .lower = 100, .upper = 100}};
        receiver_fd = socket(AF_TIPC, SOCK_RDM | SOCK_NONBLOCK, 0);
        if (receiver_fd < 0 || bind(receiver_fd, (void *)&service, sizeof(service))) error = -errno;
        else receiver_bound = 1;
    }
    if (!error) { error = bearer(1); enabled = !error; }
    for (int i = 0; enabled && !error && !stopping && (native_resident || i < 20); i += !native_resident) {
        if (native_resident) {
            if (!access("/tmp/estudio-mesh-resident/control/stop", F_OK)) break;
            main_up = status_service = main_configuration_service = receiver_publication = 0;
        }
        error = request(family, TIPC_NL_NODE_GET, 1, attrs, 0);
        if (!error) error = request(family, TIPC_NL_NAME_TABLE_GET, 1, attrs, 0);
        struct timespec now = {0};
        if (!error && native_request && clock_gettime(CLOCK_MONOTONIC, &now)) error = -errno;
        if (!error && native_request && (!native_request_sent || (native_resident && now.tv_sec - last_request >= 60)) && !native_request_error &&
            main_up && main_configuration_service && receiver_publication) {
            static const char query[] = "{\"head\":\"tipc_request\",\"content\":\"RE\"}";
            struct sockaddr_tipc target = {.family = AF_TIPC, .addrtype = TIPC_SERVICE_ADDR,
                .scope = TIPC_CLUSTER_SCOPE,
                .addr.name = {.name = {.type = 5000, .instance = 100}, .domain = main_addr}};
            ssize_t sent = sendto(receiver_fd, query, sizeof(query), MSG_DONTWAIT,
                                  (void *)&target, sizeof(target));
            if (sent != (ssize_t)sizeof(query)) native_request_error = sent < 0 ? errno : EIO;
            else { native_request_sent = 1; last_request = now.tv_sec; requests_sent++; }
            if (native_request_error) error = -native_request_error;
        }
        sleep(1);
        if (!native_resident) { capture(); capture_ports(); capture_tx(); }
        if (native_receiver && !error) error = receive_native();
        if (native_resident && !error) error = resident_state(1);
        if (main_media_seen && !control_filter_set) {
            if (control_filter(capture_fd)) error = -errno;
            else control_filter_set = 1;
        }
    }
    capture_tx();
    if (receiver_fd >= 0) {
        receiver_closed = close(receiver_fd) == 0;
        if (!receiver_closed && !error) error = -errno;
    }
    if (enabled) cleanup = bearer(0);
    if (native_resident) resident_state(0);
    if (tx_fd >= 0) close(tx_fd);
    close(fd);
    close(capture_fd);
    for (int i = 0; i < 4; i++) close(port_fd[i]);
    outgoing_dest_matches_main = main_media_seen && outgoing_link_control && !memcmp(main_media_mac, outgoing_dest_mac, 6);
    printf("{\"bearer_enabled\":%s,\"main_link_up\":%s,\"main_status_service\":%s,\"netlink_error\":%d,\"bearer_cleanup_error\":%d,\"interrupted\":%s,\"captured_headers\":%d,\"incoming_discovery\":%d,\"outgoing_discovery\":%d,\"main_discovery\":%d,\"packet_limit_reached\":%s,\"main_media_deco\":%d,\"main_role_master\":%d,\"main_role_slave\":%d,\"main_role_invalid\":%d,\"main_peer_seen\":%s,\"main_domain\":%u,\"main_capabilities\":%u,\"incoming_main_link_control\":%d,\"outgoing_link_control\":%d,\"own_discovery_capabilities\":%u,\"own_discovery_signature\":%u,\"own_discovery_domain\":%u,\"own_discovery_changes\":%d,\"own_discovery_identity_changes\":%d}\n",
           enabled ? "true" : "false", main_up ? "true" : "false", status_service ? "true" : "false", error, cleanup, stopping ? "true" : "false", packets, incoming_discovery, outgoing_discovery, main_discovery, packets == 128 ? "true" : "false", main_media_deco, main_role_master, main_role_slave, main_role_invalid, main_peer_seen ? "true" : "false", main_domain, main_caps, incoming_link_control, outgoing_link_control, own_discovery_caps, own_discovery_signature, own_discovery_domain, own_discovery_changes, own_discovery_identity_changes);
    printf("{\"outgoing_control_type\":%u,\"outgoing_control_header\":%u,\"outgoing_control_size\":%u,\"outgoing_control_destination\":%u,\"outgoing_destination_matches_main_media\":%s,\"reset_contract_match\":%d,\"reset_source_match\":%d,\"reset_origin_match\":%d,\"reset_session\":%u,\"reset_redundant\":%u,\"reset_bearer\":%u,\"reset_plane\":%u,\"reset_mtu\":%u,\"reset_wire_header_hex\":\"%s\",\"reset_wire_observed\":%s,\"reset_wire_changes\":%d,\"reset_name_observed\":%d,\"reset_name_prefix\":%d,\"reset_name_padding_zero\":%d,\"main_reset\":%d,\"main_activate\":%d,\"main_state\":%d,\"control_filter_set\":%s,\"primary_headers\":%d,\"primary_outgoing\":%d,\"primary_main_incoming\":%d,\"standby_headers\":%d,\"standby_outgoing\":%d,\"standby_main_incoming\":%d,\"main_discovery_requests\":%d,\"main_discovery_replies\":%d,\"own_media_slave\":%d,\"own_media_master\":%d,\"own_media_invalid\":%d,\"own_media_source_match\":%d,\"own_media_interface_match\":%d,\"main_reply_unicast_own\":%d,\"main_reply_multicast\":%d,\"main_reply_foreign\":%d,\"physical_source_filter_set\":false,\"physical_node_filter_set\":%s,\"primary_main_source_alias\":%d,\"standby_main_source_alias\":%d,\"physical_discovery_enabled\":false,\"primary_incoming_own_node\":%d,\"standby_incoming_own_node\":%d,\"primary_physical_headers\":%d,\"primary_physical_outgoing\":%d,\"primary_physical_main_incoming\":%d,\"primary_physical_limit_reached\":%s,\"primary_main_untagged\":%d,\"primary_main_vlan1\":%d,\"primary_main_other_vlan\":%d,\"standby_physical_headers\":%d,\"standby_physical_outgoing\":%d,\"standby_physical_main_incoming\":%d,\"standby_physical_limit_reached\":%s,\"standby_main_untagged\":%d,\"standby_main_vlan1\":%d,\"standby_main_other_vlan\":%d}\n",
           outgoing_control_type, outgoing_control_header, outgoing_control_size, outgoing_control_destination, outgoing_dest_matches_main ? "true" : "false", reset_contract_match, reset_source_match, reset_origin_match, reset_session, reset_redundant, reset_bearer, reset_plane, reset_mtu, reset_wire_header_hex, reset_wire_observed ? "true" : "false", reset_wire_changes, reset_name_observed, reset_name_prefix, reset_name_padding_zero, main_reset, main_activate, main_state, control_filter_set ? "true" : "false", port_headers[0], port_outgoing[0], port_incoming[0], port_headers[1], port_outgoing[1], port_incoming[1], main_discovery_requests, main_discovery_replies, own_media_slave, own_media_master, own_media_invalid, own_media_source_match, own_media_interface_match, main_reply_unicast_own, main_reply_multicast, main_reply_foreign, physical_node_filter_set ? "true" : "false", physical_main_source_alias[0], physical_main_source_alias[1], physical_incoming_own_node[0], physical_incoming_own_node[1], port_headers[2], port_outgoing[2], port_incoming[2], port_headers[2] == 128 ? "true" : "false", physical_main_untagged[0], physical_main_vlan1[0], physical_main_other_vlan[0], port_headers[3], port_outgoing[3], port_incoming[3], port_headers[3] == 128 ? "true" : "false", physical_main_untagged[1], physical_main_vlan1[1], physical_main_other_vlan[1]);
    if (tx_status) printf("{\"enabled\":true,\"header_offload_variation\":true,\"reset_tx_completions\":%d,\"main_radio_ack\":%d,\"tx_failed\":%d,\"unclassified\":%d,\"retry_total\":%d,\"packet_limit_reached\":%s}\n",
        tx_headers, tx_ack, tx_fail, tx_unclassified, tx_retries, tx_headers == 128 ? "true" : "false");
    if (native_receiver) printf("{\"enabled\":true,\"bound\":%s,\"publication_seen\":%s,\"closed\":%s,\"service_type\":6000,\"instance\":100,\"main_datagrams\":%llu,\"foreign_datagrams\":%llu,\"receive_errors\":%d,\"receive_limit_reached\":%s,\"payload_retained\":%s,\"response_saved_to_private_ram\":%s,\"response_bytes\":%d,\"response_error\":%d,\"application_messages_sent\":%llu,\"main_configuration_service\":%s,\"configuration_request_sent\":%s,\"request_error\":%d}\n",
        receiver_bound ? "true" : "false", receiver_publication ? "true" : "false",
        receiver_closed ? "true" : "false", receiver_main, receiver_foreign, receiver_errors,
        !native_resident && receiver_packets == 128 ? "true" : "false", response_saved ? "true" : "false",
        response_saved ? "true" : "false", response_bytes, response_error, requests_sent,
        main_configuration_service ? "true" : "false", native_request_sent ? "true" : "false", native_request_error);
    return error || cleanup || stopping || !main_up || !status_service ||
        (native_receiver && (!receiver_bound || !receiver_publication || !receiver_closed)) ||
        (native_request && (!native_request_sent || !receiver_main)) ||
        (native_response && (!response_saved || response_error)) ? 1 : 0;
}
