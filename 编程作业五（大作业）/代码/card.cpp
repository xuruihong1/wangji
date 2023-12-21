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

DWORD Card::getIP(u_int idx) {//���ڻ�ȡ����ӿڿ��� IP ��ַ
    if (idx < 2) {
        if (subnetMask[idx] == DWORD(0)) {
            cout << "��ERR�� Get IP Error: subnetMask[" << idx << "] is not set." << endl;
        }
    }
    else {
        cout << "��ERR�� Get IP Error: idx out of range." << endl;
        exit(1);
    }
    return ip[idx];
}

DWORD Card::getSubnetMask(u_int idx) {//���ڻ�ȡ����ӿڿ�����������
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

BYTE* Card::getMac() {//���ڻ�ȡ����ӿڿ��� MAC ��ַ
    BYTE temp[6];
    memset(temp, 0, 6);
    if (memcmp(mac, temp, 6) == 0) {
        cout << "��ERR�� Get MAC Error: mac is not set." << endl;
        return NULL;
    }
    return mac;
}
//��������ӿڿ������ơ�������IP ��ַ����������� MAC ��ַ
string Card::toStr() {//���ڽ�����ӿڿ�����Ϣת��Ϊ�ַ�����ʽ
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
//���ڽ�����ӿڿ�����������Ϣת��Ϊ�ַ�����ʽ
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
//��ȡ�豸��������������pcap_addr_t������ȡ�豸��IP���������롣
void CardManager::findCards() {
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int i, j;
    pcap_addr_t* a;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {  // ��ȡ�������������б�
        cout << "��ERR�� Error in pcap_findalldevs: " << errbuf << endl;
        exit(1);
    }
    for (d = alldevs; d != NULL; d = d->next) { // ��ȡ�豸����
        deviceNum++;
    }
    if (deviceNum == 0) {
        cout << "��ERR�� No device found! Make sure WinPcap is installed." << endl;
        exit(1);
    }
    deviceList = new Card[deviceNum];
    for (i = 0, d = alldevs; d != NULL; d = d->next, i++) { // ��ȡ�豸��������
        deviceList[i].name = string(d->name);
        deviceList[i].description = string(d->description);
        for (j = 0, a = d->addresses; j < 2 && a != NULL; a = a->next) {    // ��ȡ�豸IP��ַ
            if (a->addr->sa_family == AF_INET) {
                deviceList[i].ip[j] = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
                deviceList[i].subnetMask[j] = inet_addr(inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
                j++;
            }
        }
    }
    pcap_freealldevs(alldevs);
    cout << "��SUC�� Find Cards Success! Cards�� " << endl;
    cout << toStr() << endl;
}
//�����豸��ţ�ѡ�в����豸��ͬʱ�����豸ָ��ָ����豸����Ϣ��
void CardManager::selCard() {
    u_int i;
    cout << "��CMD�� Please input the device index: ";
    cin >> i;
    if (i < 1 || i > deviceNum) {
        cout << "��ERR�� Invalid device index" << endl;
        exit(1);
    }
    i--;
    openCard = &deviceList[i];
    if ((openHandle = pcap_open(openCard->name.c_str(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) ==
        NULL) { // ������
        cout << "��ERR�� Error in pcap_open_live: " << errbuf << endl;
        exit(1);
    }
    if (pcap_datalink(openHandle) != DLT_EN10MB) { // �ж������Ƿ�Ϊ��̫������
        cout << "��ERR�� This device is not an Ethernet" << endl;
        exit(1);
    }
    if (pcap_setnonblock(openHandle, 1, errbuf) == -1) { // ��������Ϊ������ģʽ
        cout << "��ERR�� Error in pcap_setnonblock: " << errbuf << endl;
        exit(1);
    }
    cout << "��SUC�� Card opened successfully" << endl;
}
//������������ӿڿ��� MAC ��ַ��������Ҫ���õ� MAC ��ַ��Ҫ���õ��豸��Ȼ��������Ĳ��������� MAC ��ַ���Ƶ��豸�������С�
void CardManager::setMac(BYTE* mac, Card* device) {
    if (mac == NULL) {
        cout << "��ERR�� Set MAC Error: mac is NULL." << endl;
        return;
    }
    if (device == NULL) {
        cout << "��ERR�� Set MAC Error: device is NULL." << endl;
    }
    if (device->getMac() != NULL) {
        cout << "��ERR�� Set MAC Error: mac is already set." << endl;
        return;
    }
    memcpy(device->mac, mac, 6);
    
}
//���ڲ�����ָ�� IP ��ַ��ƥ��ı��ؽӿڡ�����鵱ǰ�򿪵������� IP ��ַ���������룬Ȼ����ָ���� IP ��ַ���бȽϣ���ȷ���Ƿ��Ǳ��ؽӿڡ�
DWORD CardManager::findItf(DWORD ip) {
    if (openCard == NULL) {
        cout << "��ERR�� Find Itf Error: openCard is NULL." << endl;
        return 0;
    }
    if (openHandle == NULL) {
        cout << "��ERR�� Find Itf Error: openHandle is NULL." << endl;
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