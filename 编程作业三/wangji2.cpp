#include <Winsock2.h>
#include<Windows.h>
#include<iostream>
#include <ws2tcpip.h>
#include "pcap.h"
#include "stdio.h"
#include<time.h>
#include <string>
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning( disable : 4996 )
#define _WINSOCK_DEPRECATED_NO_WARNINGS
using namespace std;
void coutM(BYTE MAC[6]);
void coutI(DWORD IP);
#pragma pack(1)
struct FHeader //帧首部
{
	BYTE DMAC[6];  //目的地址
	BYTE SMAC[6];  //源地址
	WORD Type;  //帧类型
};
struct ARP               //ARP帧
{
	FHeader FrameHeader;
	WORD HType;//指示硬件地址的类型
	WORD PType;//指示上层协议的类型
	BYTE HLen;//指示硬件地址的长度
	BYTE PLen;//指示协议地址的长度
	WORD Operation;//操作码，ARP请求或ARP应答
	BYTE SendM[6];
	DWORD SendIP;
	BYTE RecvM[6];
	DWORD RecvIP;
};
#pragma pack()        //恢复缺省对齐方式
int main()
{
	pcap_if_t* adevs;//指向设备列表首部的指针
	pcap_if_t* ptr;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区
	ARP ARP_;
	ARP* IPPacket;
	struct pcap_pkthdr* p_header;//存储数据包头部信息
	const u_char* p_data;
	int j = 0;
	DWORD SendIP;
	DWORD RevIP;
	//获得本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &adevs, errbuf) == -1)
	{
		cout << "获取网络接口时发生错误:" << errbuf << endl;
		return 0;
	}
	//显示接口列表
	for (ptr = adevs; ptr != NULL; ptr = ptr->next)
	{
		cout << "网卡" << j + 1 << "\t" << ptr->name << endl;
		for (a = ptr->addresses; a != NULL; a = a->next)
		{
			if (a->addr->sa_family == AF_INET)
			{
				cout << "  IP地址：" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
			}
		}
		j++;
	}

	int num;
	cout << "请选网卡号：";
	cin >> num;
	ptr = adevs;
	for (int i = 1; i < num; i++)
	{
		ptr = ptr->next;
	}
	pcap_t* pcap_d = pcap_open(ptr->name, 1024, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);//打开网卡
	if (pcap_d == NULL)
	{
		cout << "发生错误：" << errbuf << endl;
		return 0;
	}
	else
	{
		cout << "成功打开" << endl;
	}
	//编译过滤器，只捕获ARP包
	u_int netmask;
	netmask = ((sockaddr_in*)(ptr->addresses->netmask))->sin_addr.S_un.S_addr;//获取网络掩码
	bpf_program fcode;
	char p_filter[] = "ether proto \\arp";
	pcap_compile(pcap_d, &fcode, p_filter, 1, netmask);
	pcap_setfilter(pcap_d, &fcode);
	//组装报文
	for (int i = 0; i < 6; i++)
	{
		ARP_.FrameHeader.DMAC[i] = 0xFF;//255.255.255.255.255.255
		ARP_.FrameHeader.SMAC[i] = 0x66;//66-66-66-66-66-66-66
		ARP_.RecvM[i] = 0;//设置为0
		ARP_.SendM[i] = 0x66;
	}
	ARP_.FrameHeader.Type = htons(0x0806);//帧类型为ARP
	ARP_.HType = htons(0x0001);//硬件类型为以太网
	ARP_.PType = htons(0x0800);//协议类型为IP
	ARP_.HLen = 6;//硬件地址长度为6
	ARP_.PLen = 4; // 协议地址长为4
	ARP_.Operation = htons(0x0001);//操作为ARP请求
	SendIP = ARP_.SendIP = htonl(0x70707070);//112.112.112.112.112.112
	//将所选择的网卡的IP设置为请求的IP地址
	for (a = ptr->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			RevIP = ARP_.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
		}
	} 
	pcap_sendpacket(pcap_d, (u_char*)&ARP_, sizeof(ARP)); 
	pcap_next_ex(pcap_d, &p_header, &p_data); 
	IPPacket = (ARP*)p_data; 
	cout << "获取成功" << endl;
	cout << "请输入IP地址:";
	char str[15];
	cin >> str;
	RevIP = ARP_.RecvIP = inet_addr(str);
	SendIP = ARP_.SendIP = IPPacket->SendIP; //将本机IP赋值给数据报的源IP 
	for (int i = 0; i < 6; i++)
	{
		ARP_.SendM[i] = ARP_.FrameHeader.SMAC[i] = IPPacket->SendM[i];//mac地址也赋值给源MAC地址
	} 
	pcap_sendpacket(pcap_d, (u_char*)&ARP_, sizeof(ARP));
	cout << "ARP请求发送成功" << endl;
	while (true)
	{
		pcap_next_ex(pcap_d, &p_header, &p_data);
        IPPacket = (ARP*)p_data;
		if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)//判断是不是一开始发的包
		{

			cout << "IP与其MAC地址对应关系如下：" << endl;
			coutI(IPPacket->SendIP);
			cout << "	---	";
			coutM(IPPacket->SendM);
			cout << endl;
			break;
		}
			
	}
}

void coutM(BYTE MAC[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (i < 5)
			printf("%02x:", MAC[i]);
		else
			printf("%02x", MAC[i]);
	}

};
void coutI(DWORD IP)
{
	BYTE* p = (BYTE*)&IP;
	for (int i = 0; i < 3; i++)
	{
		cout << dec << (int)*p << ".";
		p++;
	}
	cout << dec << (int)*p;
};