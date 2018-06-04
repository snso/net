#include <stdio.h>
#include <string.h>
#include <iostream>
#include <unistd.h>

#include "NetMonitor.h"

//#include "android/log.h"

//#define printf(fmt,...)  __android_log_print(ANDROID_LOG_DEBUG, "VizumLog--",fmt,##__VA_ARGS__)

using namespace std;

EthMonitor *ethMonitor;
void EthMonitorResult(std::string command,std::string ipInfo, int result)
{
	cout<<"result --:-- " << command << " " << ipInfo << "  " <<result <<endl;
	if("ROUTE" == command){
		cout<<endl;cout<<endl;cout<<endl;cout<<endl;	
	}
	
	if(result == 0){
		printf("重新配置 \n");
		ethMonitor->configDefaultIP();
	}
}


int main(int avgc, char **avgv)
{
	printf("inint  start\n");
	ethMonitor = new EthMonitor();
	ethMonitor->monitorBack(EthMonitorResult);
	ethMonitor->StartMonitor();
	
	int result ;
	if(avgc == 2)
	{
		result = ethMonitor->setDefaultIP(avgv[1]);
	}
	else
	{
		result = ethMonitor->setDefaultIP("192.168.2.65");
	}
	printf("setDefaultIP : %d\n",result);

	while(1)
	{
		getchar();

		string gatewayIp = ethMonitor->getGateway();
		cout<<"gateway ---  "<<gatewayIp<<endl;
	}
	

}
