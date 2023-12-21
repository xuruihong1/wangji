#ifndef ROUTERAPPLICATION_ROUTING_TABLE_H
#define ROUTERAPPLICATION_ROUTING_TABLE_H
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma warning(disable:4996)
#include <time.h>
#include <Winsock2.h>
#include <string>
#include "card.h"
#include "Log.h"

class RoutingTable;

class RoutingEntry {
private:
    DWORD dest;         // 目的地址
    DWORD netmask;      // 子网掩码
    DWORD gw;           // 网关地址
    DWORD itf;          // 出接口
    RoutingEntry* prev;
    RoutingEntry* next;
    friend class RoutingTable;

public:
    RoutingEntry(DWORD dest, DWORD netmask, DWORD gw, DWORD itf);
    ~RoutingEntry();
    DWORD getGw();
    string toStr(bool showAttr = true);
};

class RoutingTable {
private:
    Card* openCard;
    RoutingEntry* head;
    RoutingEntry* tail;
    u_int size;

public:
    RoutingTable(Card* openCard);
    ~RoutingTable();
    void add(DWORD dest, DWORD netmask, DWORD gw);
    void add(const char* dest, const char* netmask, const char* gw);
    void del(RoutingEntry* routingEntry);
    RoutingEntry* lookup(DWORD dest);
    RoutingEntry* lookup(char* dest);
    string toStr();
};


#endif