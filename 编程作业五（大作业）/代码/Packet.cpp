#include "Packet.h"
//创建一个 ARP 数据包。它接受目标 MAC 地址、源 MAC 地址、操作码、目标 IP 地址和源 IP 地址作为参数，然后创建一个 ARP 数据包结构体并填充相关字段
ARPPkt* makeARPPkt(u_char* dstMac, u_char* srcMac, WORD operation, DWORD dstIP, DWORD srcIP) {
    ARPPkt* pkt = new ARPPkt;
    memcpy(pkt->eh.dstMac, dstMac, 6);
    memcpy(pkt->eh.srcMac, srcMac, 6);
    pkt->eh.type = htons(0x0806);
    pkt->ad.hType = htons(0x0001);      // 以太网
    pkt->ad.pType = htons(0x0800);      // IPV4
    pkt->ad.hLen = 6;
    pkt->ad.pLen = 4;
    pkt->ad.op = htons(operation);
    memcpy(pkt->ad.srcMac, srcMac, 6);
    pkt->ad.srcIP = srcIP;
    memcpy(pkt->ad.dstMac, dstMac, 6);
    pkt->ad.dstIP = dstIP;
    return pkt;
}
//用于判断给定的数据包是否为 ARP 数据包
bool isARPPkt(const u_char* pktData) {
    return ntohs(((ARPPkt*)pktData)->eh.type) == 0x0806;
}
//用于判断给定的数据包是否为 IP 数据包
bool isIPPkt(const u_char* pktData) {
    return ntohs(((ARPPkt*)pktData)->eh.type) == 0x0800;
}
//用于计算 IP 数据包的校验和
u_short calIPChecksum(u_short* pktData, int len) {
    u_long sum;
    u_short bac;
    u_short* ori;
    sum = 0;
    bac = ((IPPkt*)pktData)->ih.checksum;
    ori = pktData;
    ((IPPkt*)pktData)->ih.checksum = 0;
    pktData = (u_short*)&(((IPPkt*)pktData)->ih);
    len -= sizeof(EthHeader);
    while (len > 1) {
        sum += *pktData++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(u_char*)pktData;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    pktData = ori;
    ((IPPkt*)pktData)->ih.checksum = bac;
    return (u_short)(~sum);
}
//用于计算 ICMP 数据包的校验和
u_short calICMPChecksum(u_short* pktData, int len) {
    u_long sum;
    u_short bac;
    u_short* ori;
    sum = 0;
    bac = ((ICMPPingPkt*)pktData)->icmpPingData.checksum;
    ori = pktData;
    ((ICMPPingPkt*)pktData)->icmpPingData.checksum = 0;
    pktData = (u_short*)&((ICMPPingPkt*)pktData)->ih;
    len -= sizeof(EthHeader);
    while (len > 1) {
        sum += *pktData++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(u_char*)pktData;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    pktData = ori;
    ((ICMPPingPkt*)pktData)->icmpPingData.checksum = bac;
    return (u_short)(~sum);
}
//函数用于检查 ICMP 数据包是否损坏。它计算 ICMP 数据包的校验和，并与预期的校验和值进行比较
bool isICMPCorrupted(u_short* pktData, int len) {
    u_long sum;
    sum = 0;
    pktData = (u_short*)&((ICMPPingPkt*)pktData)->ih;
    len -= sizeof(EthHeader);
    while (len > 1) {
        sum += *pktData++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(u_char*)pktData;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    if (sum != 0xffff) {
        cout << "【ERR】 ICMP checksum error" << endl;
    }
    return sum != 0xffff;
}
//用于设置 ICMP 数据包的校验和
void setICMPChecksum(u_short* pktData) {
    ((IPPkt*)pktData)->ih.checksum = calIPChecksum(pktData, sizeof(IPPkt));
    ((ICMPPingPkt*)pktData)->icmpPingData.checksum = calICMPChecksum(pktData, sizeof(ICMPPingPkt));
}
//用于创建 Packet 对象。它接受一个 ICMP 数据包指针和时间作为参数，并初始化对象的成员变量。
Packet::Packet(ICMPPingPkt* icmpPingPkt, time_t time) {
    this->icmpPingPkt = icmpPingPkt;
    this->time = time;
    this->discardState = false;
    next = NULL;
}

Packet::~Packet() {}
//用于获取 Packet 对象中的 ICMP 数据包指针
ICMPPingPkt* Packet::getICMPPingPkt() const {
    return icmpPingPkt;
}
//用于获取 Packet 对象中的时间信息
time_t Packet::getTime() const {
    return time;
}
//用于判断是否应该丢弃该 Packet 对象
bool Packet::shouldDiscard() const {
    return this->discardState;
}
//s设置丢弃状态
void Packet::setDiscardState(bool discardState) {
    this->discardState = discardState;
}
//获取下一个对象
Packet* Packet::getNext() {
    return next;
}
//初始化列表
PacketList::PacketList() {
    head = NULL;
    tail = NULL;
    size = 0;
}

PacketList::~PacketList() {
    Packet* p = head;
    while (p != NULL) {
        Packet* tmp = p;
        p = p->next;
        delete tmp;
    }
}
//用于在列表的头部添加一个新的 Packet 对象
void PacketList::addBefore(ICMPPingPkt* icmpPingPkt) {
    Packet* pkt = new Packet(icmpPingPkt, time(NULL));
    if (head == NULL) {
        head = pkt;
        tail = pkt;
    }
    else {
        pkt->next = head;
        head->prev = pkt;
        head = pkt;
    }
    size++;
}
//删除对应的Packet包
Packet* PacketList::del(Packet* packet) {
    Packet* ret;
    ret = packet->next;
    if (packet == head) {
        head = packet->next;
        if (head != NULL) {
            head->prev = NULL;
        }
    }
    else if (packet == tail) {
        tail = packet->prev;
        if (tail != NULL) {
            tail->next = NULL;
        }
    }
    else {
        packet->prev->next = packet->next;
        packet->next->prev = packet->prev;
    }
    delete packet;
    size--;
    return ret;
}
//用于获取列表的头部 Packet 对象
Packet* PacketList::getHead() const {
    return head;
}
//获取列表大小
u_int PacketList::getSize() const {
    return size;
}
