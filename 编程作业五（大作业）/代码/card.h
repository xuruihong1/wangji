#ifndef ROUTERAPPLICATION_DEVICE_H
#define ROUTERAPPLICATION_DEVICE_H
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma warning(disable:4996)

#define HAVE_REMOTE
#include <Winsock2.h>
#include <string>
#include <iostream>
#include <pcap.h>
#include "Log.h"

using namespace std;

class CardManager;

class Card {
private:
    string name;    // 设备名称
    string description; // 设备描述
    DWORD ip[2];        // IP地址
    DWORD subnetMask[2];    // 子网掩码
    BYTE mac[6];    // MAC地址
    friend class CardManager;

public:
    Card();
    ~Card();
    DWORD getIP(u_int idx = 0);
    DWORD getSubnetMask(u_int idx = 0);
    BYTE* getMac();
    string toStr();
};

class CardManager {
private:
    u_int deviceNum;
    Card* deviceList;
    Card* openCard;
    pcap_t* openHandle;
    char errbuf[PCAP_ERRBUF_SIZE];

public:
    CardManager();
    ~CardManager();
    u_int getCardNum();
    Card* getOpenCard();
    pcap_t* getOpenHandle();
    string toStr();
    void findCards();         // 查找所有网卡,获取设备信息
    void selCard();           // 选择并打开网卡
    void setMac(BYTE* mac, Card* device);   // 设置特定设备MAC地址
    DWORD findItf(DWORD ip);    // 根据IP地址，查看是否在同一网段，并返回对应接口IP地址
};
#endif