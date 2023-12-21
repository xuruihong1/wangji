#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)
#include "Log.h"

string b2s(DWORD addr) {//��һ�� DWORD ���͵� IP ��ַת��Ϊ���ʮ���Ƶ��ַ�����ʽ
    char addrStr[16] = { 0 };
    sprintf(addrStr, "%d.%d.%d.%d", addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, (addr >> 24) & 0xFF);
    return string(addrStr);
}

string b2s(BYTE* mac) {//��һ�� BYTE ���͵� MAC ��ַת��Ϊ����ð�ŷָ�����ʮ�������ַ�����ʽ��
    char macStr[18] = { 0 };
    sprintf(macStr, "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return string(macStr);
}

string v2s(int value) {//���������͵�ֵת��Ϊ�ַ�����ʽ���� int ���͵�ֵ������ u_int���͵�ֵ��
    char valueStr[10] = { 0 };
    sprintf(valueStr, "%d", value);
    return string(valueStr);
}

string v2s(u_int value) {//���� u_int���͵�ֵ��
    char valueStr[10] = { 0 };
    sprintf(valueStr, "%d", value);
    return string(valueStr);
}

string t2s(time_t time) {//��һ�� time_t ���͵�ʱ���ת��Ϊ��ʽ����ʱ���ַ���
    char timeStr[20] = { 0 };
    strftime(timeStr, 20, "%H:%M:%S", localtime(&time));
    return string(timeStr);
}

bool macCmp(BYTE* mac1, BYTE* mac2) {//���ڱȽ����� MAC ��ַ�Ƿ���ȣ����ز���ֵ��ʾ�ȽϽ����
    if (mac2 == NULL) {
        return memcmp(mac1, "\0\0\0\0\0\0", 6) == 0;
    }
    else {
        return memcmp(mac1, mac2, 6) == 0;
    }
}
//�������ɽ������ݰ���ת�����ݰ�����־��Ϣ������������ת��Ϊ�ַ�����ƴ�ӳ���־��Ϣ��
string recvLog(DWORD srcIP, BYTE* srcMac, DWORD dstIP, BYTE* dstMac, int ttl) {
    string str = "";
    string temp;
    str += "��INF�� Packet Received: \nSrcIP           SrcMac            DstIP           DstMac            TTL\n";
    temp = b2s(srcIP); temp.resize(16, ' '); str += temp;
    temp = b2s(srcMac); temp.resize(18, ' '); str += temp;
    temp = b2s(dstIP); temp.resize(16, ' '); str += temp;
    temp = b2s(dstMac); temp.resize(18, ' '); str += temp;
    temp = v2s(ttl); str += temp;
    return str;
}
string fwrdLog(DWORD dstIP, BYTE* dstMac, int ttl, bool nextHop) {
    string str = "";
    string temp;
    if (nextHop) {
        str += "��INF�� Packet Forwarded: \nNextHop         DstMac            TTL\n";
    }
    else {
        str += "��INF�� Packet Forwarded: \nDstIP           DstMac            TTL\n";
    }
    temp = b2s(dstIP); temp.resize(16, ' '); str += temp;
    temp = b2s(dstMac); temp.resize(18, ' '); str += temp;
    temp = v2s(ttl); str += temp;
    return str;
}
