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
    string name;    // �豸����
    string description; // �豸����
    DWORD ip[2];        // IP��ַ
    DWORD subnetMask[2];    // ��������
    BYTE mac[6];    // MAC��ַ
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
    void findCards();         // ������������,��ȡ�豸��Ϣ
    void selCard();           // ѡ�񲢴�����
    void setMac(BYTE* mac, Card* device);   // �����ض��豸MAC��ַ
    DWORD findItf(DWORD ip);    // ����IP��ַ���鿴�Ƿ���ͬһ���Σ������ض�Ӧ�ӿ�IP��ַ
};
#endif