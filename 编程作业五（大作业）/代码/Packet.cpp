#include "Packet.h"
//����һ�� ARP ���ݰ���������Ŀ�� MAC ��ַ��Դ MAC ��ַ�������롢Ŀ�� IP ��ַ��Դ IP ��ַ��Ϊ������Ȼ�󴴽�һ�� ARP ���ݰ��ṹ�岢�������ֶ�
ARPPkt* makeARPPkt(u_char* dstMac, u_char* srcMac, WORD operation, DWORD dstIP, DWORD srcIP) {
    ARPPkt* pkt = new ARPPkt;
    memcpy(pkt->eh.dstMac, dstMac, 6);
    memcpy(pkt->eh.srcMac, srcMac, 6);
    pkt->eh.type = htons(0x0806);
    pkt->ad.hType = htons(0x0001);      // ��̫��
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
//�����жϸ��������ݰ��Ƿ�Ϊ ARP ���ݰ�
bool isARPPkt(const u_char* pktData) {
    return ntohs(((ARPPkt*)pktData)->eh.type) == 0x0806;
}
//�����жϸ��������ݰ��Ƿ�Ϊ IP ���ݰ�
bool isIPPkt(const u_char* pktData) {
    return ntohs(((ARPPkt*)pktData)->eh.type) == 0x0800;
}
//���ڼ��� IP ���ݰ���У���
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
//���ڼ��� ICMP ���ݰ���У���
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
//�������ڼ�� ICMP ���ݰ��Ƿ��𻵡������� ICMP ���ݰ���У��ͣ�����Ԥ�ڵ�У���ֵ���бȽ�
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
        cout << "��ERR�� ICMP checksum error" << endl;
    }
    return sum != 0xffff;
}
//�������� ICMP ���ݰ���У���
void setICMPChecksum(u_short* pktData) {
    ((IPPkt*)pktData)->ih.checksum = calIPChecksum(pktData, sizeof(IPPkt));
    ((ICMPPingPkt*)pktData)->icmpPingData.checksum = calICMPChecksum(pktData, sizeof(ICMPPingPkt));
}
//���ڴ��� Packet ����������һ�� ICMP ���ݰ�ָ���ʱ����Ϊ����������ʼ������ĳ�Ա������
Packet::Packet(ICMPPingPkt* icmpPingPkt, time_t time) {
    this->icmpPingPkt = icmpPingPkt;
    this->time = time;
    this->discardState = false;
    next = NULL;
}

Packet::~Packet() {}
//���ڻ�ȡ Packet �����е� ICMP ���ݰ�ָ��
ICMPPingPkt* Packet::getICMPPingPkt() const {
    return icmpPingPkt;
}
//���ڻ�ȡ Packet �����е�ʱ����Ϣ
time_t Packet::getTime() const {
    return time;
}
//�����ж��Ƿ�Ӧ�ö����� Packet ����
bool Packet::shouldDiscard() const {
    return this->discardState;
}
//s���ö���״̬
void Packet::setDiscardState(bool discardState) {
    this->discardState = discardState;
}
//��ȡ��һ������
Packet* Packet::getNext() {
    return next;
}
//��ʼ���б�
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
//�������б��ͷ�����һ���µ� Packet ����
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
//ɾ����Ӧ��Packet��
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
//���ڻ�ȡ�б��ͷ�� Packet ����
Packet* PacketList::getHead() const {
    return head;
}
//��ȡ�б��С
u_int PacketList::getSize() const {
    return size;
}
