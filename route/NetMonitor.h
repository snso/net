#ifndef __NET_MONITOR__H__
#define __NET_MONITOR__H__

#include <stdio.h>
#include <string.h>
#include <iostream>

class EthMonitor
{
	
private:


public:
	EthMonitor();
	~EthMonitor();
	
public:
	int StartMonitor();
	void StopMonitor();
	void monitorBack(void (*fun)(std::string command,std::string ipInfo, int result));

public:
	int setDefaultIP(std::string localip);

	std::string getDefaultIP();
	std::string getLocalIP();
	std::string getGateway();
	int getHexIP(unsigned char hexip[4]);
	int getDevMAC(unsigned char addr[6]);
	int configDefaultIP();
	
};



#endif
