#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)
#include "Log.h"

string b2s(DWORD addr) {//将一个 DWORD 类型的 IP 地址转换为点分十进制的字符串形式
    char addrStr[16] = { 0 };
    sprintf(addrStr, "%d.%d.%d.%d", addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, (addr >> 24) & 0xFF);
    return string(addrStr);
}

string b2s(BYTE* mac) {//将一个 BYTE 类型的 MAC 地址转换为带有冒号分隔符的十六进制字符串形式。
    char macStr[18] = { 0 };
    sprintf(macStr, "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return string(macStr);
}

string v2s(int value) {//将整数类型的值转换为字符串形式接受 int 类型的值，接受 u_int类型的值。
    char valueStr[10] = { 0 };
    sprintf(valueStr, "%d", value);
    return string(valueStr);
}

string v2s(u_int value) {//接受 u_int类型的值。
    char valueStr[10] = { 0 };
    sprintf(valueStr, "%d", value);
    return string(valueStr);
}

string t2s(time_t time) {//将一个 time_t 类型的时间戳转换为格式化的时间字符串
    char timeStr[20] = { 0 };
    strftime(timeStr, 20, "%H:%M:%S", localtime(&time));
    return string(timeStr);
}

bool macCmp(BYTE* mac1, BYTE* mac2) {//用于比较两个 MAC 地址是否相等，返回布尔值表示比较结果。
    if (mac2 == NULL) {
        return memcmp(mac1, "\0\0\0\0\0\0", 6) == 0;
    }
    else {
        return memcmp(mac1, mac2, 6) == 0;
    }
}
//用于生成接收数据包和转发数据包的日志信息，将各种数据转换为字符串并拼接成日志信息。
string recvLog(DWORD srcIP, BYTE* srcMac, DWORD dstIP, BYTE* dstMac, int ttl) {
    string str = "";
    string temp;
    str += "【INF】 Packet Received: \nSrcIP           SrcMac            DstIP           DstMac            TTL\n";
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
        str += "【INF】 Packet Forwarded: \nNextHop         DstMac            TTL\n";
    }
    else {
        str += "【INF】 Packet Forwarded: \nDstIP           DstMac            TTL\n";
    }
    temp = b2s(dstIP); temp.resize(16, ' '); str += temp;
    temp = b2s(dstMac); temp.resize(18, ' '); str += temp;
    temp = v2s(ttl); str += temp;
    return str;
}
