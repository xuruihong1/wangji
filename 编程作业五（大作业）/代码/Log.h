#ifndef ROUTERAPPLICATION_UTIL_H
#define ROUTERAPPLICATION_UTIL_H

#include <Winsock2.h>
#include <stdio.h>
#include <string>
#include <time.h>
using namespace std;

string b2s(DWORD addr);  // ��DWORD���͵�IP��ַת��Ϊ�ַ���

string b2s(BYTE* mac);   // ��BYTE���͵�MAC��ַת��Ϊ�ַ���

string v2s(int value);  // ��int���͵�ֵת��Ϊ�ַ���

string v2s(u_int value); // ��u_int���͵�ֵת��Ϊ�ַ���

string t2s(time_t time); // ��time_t���͵�ʱ��ת��Ϊ�ַ���

bool macCmp(BYTE* mac1, BYTE* mac2); // �Ƚ�����MAC��ַ�Ƿ���ͬ

string recvLog(DWORD srcIP, BYTE* srcMac, DWORD dstIP, BYTE* dstMac, int ttl); // ��ӡ������־

string fwrdLog(DWORD dstIP, BYTE* dstMac, int ttl, bool nextHop = true); // ��ӡת����־

#endif //ROUTERAPPLICATION_UTIL_H
