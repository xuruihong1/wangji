#include "card.h"

Card::Card() {
    name = "";
    description = "";
    ip[0] = 0;
    ip[1] = 0;
    subnetMask[0] = 0;
    subnetMask[1] = 0;
    memset(mac, 0, 6);
}

Card::~Card() {}

DWORD Card::getIP(u_int idx) {//用于获取网络接口卡的 IP 地址
    if (idx < 2) {
        if (subnetMask[idx] == DWORD(0)) {
            cout << "【ERR】 Get IP Error: subnetMask[" << idx << "] is not set." << endl;
        }
    }
    else {
        cout << "【ERR】 Get IP Error: idx out of range." << endl;
        exit(1);
    }
    return ip[idx];
}

DWORD Card::getSubnetMask(u_int idx) {//用于获取网络接口卡的子网掩码
    if (idx < 2) {
        if (subnetMask[idx] == 0) {
            cout <<  idx << " is not set." << endl;
        }
    }
    else {
        cout << idx << " out of range." << endl;
        exit(1);
    }
    return subnetMask[idx];
}

BYTE* Card::getMac() {//用于获取网络接口卡的 MAC 地址
    BYTE temp[6];
    memset(temp, 0, 6);
    if (memcmp(mac, temp, 6) == 0) {
        cout << "【ERR】 Get MAC Error: mac is not set." << endl;
        return NULL;
    }
    return mac;
}
//包括网络接口卡的名称、描述、IP 地址、子网掩码和 MAC 地址
string Card::toStr() {//用于将网络接口卡的信息转换为字符串形式
    string str = "";
    str += "Name: " + name + "\nDescription: " + description;
    if (subnetMask[0] != 0) {
        if (subnetMask[1] != 0) {
            str += "\nIP Addr1: " + b2s(ip[0]) + "\tSubnet Mask: " + b2s(subnetMask[0])
                + "\nIP Addr2: " + b2s(ip[1]) + "\tSubnet Mask: " + b2s(subnetMask[1]);
        }
        else {
            str += "\nIP Addr: " + b2s(ip[0]) + "\tSubnet Mask: " + b2s(subnetMask[0]);
        }
    }
    if (memcmp(mac, "\0\0\0\0\0\0", 6) != 0) {
        str += "\nMAC Addr: " + b2s(mac);
    }
    return str;
}

CardManager::CardManager() {
    deviceNum = 0;
    deviceList = NULL;
    openCard = NULL;
    openHandle = NULL;
}

CardManager::~CardManager() {
    if (deviceList != NULL) {
        delete[] deviceList;
    }
}

u_int CardManager::getCardNum() {
    return deviceNum;
}

Card* CardManager::getOpenCard() {
    return openCard;
}

pcap_t* CardManager::getOpenHandle() {
    return openHandle;
}
//用于将网络接口卡管理器的信息转换为字符串形式
string CardManager::toStr() {
    string str = "";
    u_int i;
    if (deviceNum == 0) {
        str += "No device";
    }
    else {
        str += "Card Num: " + v2s(deviceNum) + "\n";
        for (i = 0; i < deviceNum; i++) {
            str += "Card " + v2s(u_int(i + 1)) + ":\n" + deviceList[i].toStr() + "\n";
        }
    }
    return str;
}
//获取设备名和描述；遍历pcap_addr_t链表，获取设备的IP的子网掩码。
void CardManager::findCards() {
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int i, j;
    pcap_addr_t* a;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {  // 获取本机所有网卡列表
        cout << "【ERR】 Error in pcap_findalldevs: " << errbuf << endl;
        exit(1);
    }
    for (d = alldevs; d != NULL; d = d->next) { // 获取设备数量
        deviceNum++;
    }
    if (deviceNum == 0) {
        cout << "【ERR】 No device found! Make sure WinPcap is installed." << endl;
        exit(1);
    }
    deviceList = new Card[deviceNum];
    for (i = 0, d = alldevs; d != NULL; d = d->next, i++) { // 获取设备名和描述
        deviceList[i].name = string(d->name);
        deviceList[i].description = string(d->description);
        for (j = 0, a = d->addresses; j < 2 && a != NULL; a = a->next) {    // 获取设备IP地址
            if (a->addr->sa_family == AF_INET) {
                deviceList[i].ip[j] = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
                deviceList[i].subnetMask[j] = inet_addr(inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
                j++;
            }
        }
    }
    pcap_freealldevs(alldevs);
    cout << "【SUC】 Find Cards Success! Cards： " << endl;
    cout << toStr() << endl;
}
//输入设备序号，选中并打开设备，同时将打开设备指针指向打开设备的信息。
void CardManager::selCard() {
    u_int i;
    cout << "【CMD】 Please input the device index: ";
    cin >> i;
    if (i < 1 || i > deviceNum) {
        cout << "【ERR】 Invalid device index" << endl;
        exit(1);
    }
    i--;
    openCard = &deviceList[i];
    if ((openHandle = pcap_open(openCard->name.c_str(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) ==
        NULL) { // 打开网卡
        cout << "【ERR】 Error in pcap_open_live: " << errbuf << endl;
        exit(1);
    }
    if (pcap_datalink(openHandle) != DLT_EN10MB) { // 判断网卡是否为以太网适用
        cout << "【ERR】 This device is not an Ethernet" << endl;
        exit(1);
    }
    if (pcap_setnonblock(openHandle, 1, errbuf) == -1) { // 设置网卡为非阻塞模式
        cout << "【ERR】 Error in pcap_setnonblock: " << errbuf << endl;
        exit(1);
    }
    cout << "【SUC】 Card opened successfully" << endl;
}
//用于设置网络接口卡的 MAC 地址。它接受要设置的 MAC 地址和要设置的设备，然后检查输入的参数，并将 MAC 地址复制到设备的属性中。
void CardManager::setMac(BYTE* mac, Card* device) {
    if (mac == NULL) {
        cout << "【ERR】 Set MAC Error: mac is NULL." << endl;
        return;
    }
    if (device == NULL) {
        cout << "【ERR】 Set MAC Error: device is NULL." << endl;
    }
    if (device->getMac() != NULL) {
        cout << "【ERR】 Set MAC Error: mac is already set." << endl;
        return;
    }
    memcpy(device->mac, mac, 6);
    
}
//用于查找与指定 IP 地址相匹配的本地接口。它检查当前打开的网卡的 IP 地址和子网掩码，然后与指定的 IP 地址进行比较，以确定是否是本地接口。
DWORD CardManager::findItf(DWORD ip) {
    if (openCard == NULL) {
        cout << "【ERR】 Find Itf Error: openCard is NULL." << endl;
        return 0;
    }
    if (openHandle == NULL) {
        cout << "【ERR】 Find Itf Error: openHandle is NULL." << endl;
        return 0;
    }
    if ((ip & openCard->subnetMask[0]) == (openCard->ip[0] & openCard->subnetMask[0])) {
        return openCard->ip[0];
    }
    if ((ip & openCard->subnetMask[1]) == (openCard->ip[1] & openCard->subnetMask[1])) {
        return openCard->ip[1];
    }
 
    return 0;
}