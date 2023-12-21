#include "RoutingTable.h"

RoutingEntry::RoutingEntry(DWORD dest, DWORD netmask, DWORD gw, DWORD itf) {
    this->dest = dest;
    this->netmask = netmask;
    this->gw = gw;
    this->itf = itf;
    this->prev = NULL;
    this->next = NULL;
}

RoutingEntry::~RoutingEntry() {}

DWORD RoutingEntry::getGw() {
    return this->gw;
}
//将路由表条目转换为字符串形式，以便于输出或者其他需要字符串表示的操作。将路由表条目的各个属性转换为字符串并添加到结果字符串中。
string RoutingEntry::toStr(bool showAttr) {
    string str = "";
    string temp;
    if (showAttr) {
        str += "Destination     Netmask         Gateway         Interface\n";
    }         
    temp = b2s(this->dest);  temp.resize(16, ' ');  str += temp;
    temp = b2s(this->netmask);  temp.resize(16, ' ');  str += temp;
    temp = b2s(this->gw);  temp.resize(16, ' ');  str += temp;
    temp = b2s(this->itf);  str += temp;
    return str;
}

RoutingTable::RoutingTable(Card* openCard) {
    this->openCard = openCard;
    this->head = NULL;
    this->tail = NULL;
    this->size = 0;
}

RoutingTable::~RoutingTable() {
    RoutingEntry* routingEntry;
    routingEntry = this->head;
    while (routingEntry != NULL) {
        RoutingEntry* next = routingEntry->next;
        delete routingEntry;
        routingEntry = next;
    }
}

void RoutingTable::add(DWORD dest, DWORD netmask, DWORD gw) {
    RoutingEntry* routingEntry;
    DWORD itf;
    // 避免重复添加
    if ((routingEntry = lookup(dest)) != NULL && (routingEntry->netmask != 0)) {
        return;
    }
    switch (netmask) {
    case 0:
        // 子网掩码为0，添加默认路由，检查接口到下一跳地址的可达性
        if ((openCard->getIP(0) & openCard->getSubnetMask(0)) == (gw & openCard->getSubnetMask(0))) {
            itf = openCard->getIP(0);
        }
        else if ((openCard->getIP(1) & openCard->getSubnetMask(1)) == (gw & openCard->getSubnetMask(1))) {
            itf = openCard->getIP(1);
        }
        else {
            cout << "【ERR】 Add Routing Entry Error: default destination is unreachable" << endl;
            return;
        }
        routingEntry = new RoutingEntry(0, 0, gw, itf);
        break;
    default:
        // 检查接口到下一跳地址的可达性
        if ((openCard->getIP(0) & openCard->getSubnetMask(0)) == (gw & openCard->getSubnetMask(0))) {
            itf = openCard->getIP(0);
        }
        else if ((openCard->getIP(1) & openCard->getSubnetMask(1)) == (gw & openCard->getSubnetMask(1))) {
            itf = openCard->getIP(1);
        }
        else {
            cout << "【ERR】 Add Routing Entry Error: No interface found for this destination." << endl;
            return;
        }
        routingEntry = new RoutingEntry(dest & netmask, netmask, gw, itf);
    }

    if (head == NULL) {
        head = tail = routingEntry;
    }
    else {
        tail->next = routingEntry;
        routingEntry->prev = tail;
        tail = routingEntry;
    }
    size++;
    cout << "【INF】 Routing Entry Added： " << routingEntry->toStr(false) << endl;
}

void RoutingTable::add(const char* dest, const char* netmask, const char* gw) {
    add(inet_addr(dest), inet_addr(netmask), inet_addr(gw));
}

void RoutingTable::del(RoutingEntry* routingEntry) {
    if (routingEntry == NULL) {
        cout << "【ERR】 Delete Routing Entry Error: Routing entry not found." << endl;
        return;
    }
    if (size == 0) {
        cout << "【ERR】 Delete Routing Entry Error: Routing table is empty." << endl;
        return;
    }
    cout << "【INF】 Delete Routing Entry: " << routingEntry->toStr(false) << endl;
    if (routingEntry->prev == NULL) {
        head = routingEntry->next;
    }
    else {
        routingEntry->prev->next = routingEntry->next;
    }
    if (routingEntry->next == NULL) {
        tail = routingEntry->prev;
    }
    else {
        routingEntry->next->prev = routingEntry->prev;
    }
    delete routingEntry;
    size--;
}

RoutingEntry* RoutingTable::lookup(DWORD dest) {
    RoutingEntry* routingEntry;
    RoutingEntry* candidate;
    DWORD maxPrefixNetmask;

    routingEntry = head;
    if (routingEntry == NULL) {
        cout << "【ERR】 Look up Routing Table Error: Routing table is empty." << endl;
        return NULL;
    }
    candidate = NULL;
    maxPrefixNetmask = head->netmask;
    while (routingEntry != NULL) {
        if ((routingEntry->dest & routingEntry->netmask) == (dest & routingEntry->netmask)) {
            if (ntohl(routingEntry->netmask) > ntohl(maxPrefixNetmask)) { // little endian in network
                maxPrefixNetmask = routingEntry->netmask;
                candidate = routingEntry;
            }
            candidate = routingEntry;
        }
        routingEntry = routingEntry->next;
    }
    if (candidate == NULL) {
        cout << "【ERR】 Look up Routing Table Error: Routing entry not found." << endl;
    }
    return candidate;
}
//用于将路由表转换为字符串形式
string RoutingTable::toStr() {
    string str = "";
    RoutingEntry* routingEntry;

    routingEntry = head;
    if (routingEntry == NULL) {
        str += "RoutingTable: None";
    }
    else {
        str += "RoutingTable: \nDestination     Netmask         Gateway         Interface\n";
        while (routingEntry != NULL) {
            str += routingEntry->toStr(false) + "\n";
            routingEntry = routingEntry->next;
        }
    }
    return str;
}