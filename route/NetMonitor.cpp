/* 
 * NetMonitor.cpp
 */  
#include <stdio.h>  
#include <unistd.h>  
#include <stdlib.h>  
#include <string.h>  
#include <signal.h>  
#include <errno.h>  
#include <sys/types.h>  
#include <asm/types.h>  
#include <arpa/inet.h>  
#include <sys/socket.h>  
#include <linux/netlink.h>  
#include <linux/rtnetlink.h>  
#include <linux/route.h>  
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

#include "NetMonitor.h"
#include "ReadRoute.h"
// #include "ip_route.h"
// #include "detection_route.h"

#define BUFLEN 20480  
  
#define t_assert(x) { \
	if(!(x))  {err = -__LINE__;goto error;} \
} 

#define TRUE 1
#define FALSE 0

#define SINT32 int
#define DEFAULT_ETH "eth0"
#define IP_LENGTH 16

#define WAIT_TIME 2



typedef void(*recvCallBack)(std::string command , std::string ipInfo ,int result);
recvCallBack pcallback;

unsigned char LOCAL_IP[IP_LENGTH] = "";

typedef __u32 u32;

pthread_mutex_t  ipconfigMutex;

int get_ip(unsigned char ip[IP_LENGTH]);
int set_ip(unsigned char ip[IP_LENGTH]);
int set_gateway(unsigned char ip[IP_LENGTH]);

int is_valid_ip(unsigned char ipaddr[IP_LENGTH]);
static int set_addr(unsigned char ip[IP_LENGTH], int flag);
static int get_addr(unsigned char ip[IP_LENGTH], int flag); 
  
/*Ctrl + C 退出*/  
static volatile int keepRunning = 1;  

void intHandler(int dummy)  
{  
	keepRunning = 0;  
}  
 
/*************************************插入线后一定时间没分配IP 配置为默认IP***********************/
//基础定时器
void timer_manage(int signo)
{
	set_ip(LOCAL_IP);
}

void init_timer_manage(int time)
{
	/**初始化时间**/
	//初始化接受超时时间默认为3s
	/**配置定时器*/
	struct itimerval tick;
    
    signal(SIGALRM, timer_manage);
    memset(&tick, 0, sizeof(tick));

    //Timeout to run first time
    tick.it_value.tv_sec = time;
    tick.it_value.tv_usec = 0;

    //After first, the Interval time for clock
    tick.it_interval.tv_sec = time;
    tick.it_interval.tv_usec = 0;

    if(setitimer(ITIMER_REAL, &tick, NULL) < 0)
	{
		printf("Set timer failed!\n");
	}
}


 
/** 
 * 解析RTA,并存入tb 
 */  
void parse_rtattr(struct rtattr **tb, int max, struct rtattr *attr, int len)  
{  
	for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {  
		if (attr->rta_type <= max) {  
			tb[attr->rta_type] = attr;  
		}  
	}  
}  
  
/** 
 * 显示连接信息 
 * 当网卡变动的时候触发这个信息,例如插/拔网线,增/减网卡设备,启用/禁用接口等. 
 */  
void print_ifinfomsg(struct nlmsghdr *nh)  
{  
	int len;  
	struct rtattr *tb[IFLA_MAX + 1];  
	struct ifinfomsg *ifinfo;  
	bzero(tb, sizeof(tb));  
	ifinfo = (ifinfomsg *)NLMSG_DATA(nh);  
	len = nh->nlmsg_len - NLMSG_SPACE(sizeof(*ifinfo));  
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA (ifinfo), len);  
	printf("%s: %s ", (nh->nlmsg_type==RTM_NEWLINK)?"NEWLINK":"DELLINK", (ifinfo->ifi_flags & IFF_LOWER_UP) ? "up" : "down"); 
	if(ifinfo->ifi_flags & IFF_LOWER_UP){
		init_timer_manage(WAIT_TIME);
	}
	if(tb[IFLA_IFNAME]) {  
		printf("%s", (char *)RTA_DATA(tb[IFLA_IFNAME]));  
	}  
	printf("\n");  
}  
  
/** 
 * 显示地址信息 
 * 当地址变动的时候触发这个信息,例如通过DHCP获取到地址后 
 */  
void print_ifaddrmsg(struct nlmsghdr *nh)  
{  
	int len;  
	struct rtattr *tb[IFA_MAX + 1];  
	struct ifaddrmsg *ifaddr;  
	char tmp[256];  
	bzero(tb, sizeof(tb));  
	ifaddr = (ifaddrmsg *)NLMSG_DATA(nh);  
	len = nh->nlmsg_len - NLMSG_SPACE(sizeof(*ifaddr));  
	parse_rtattr(tb, IFA_MAX, IFA_RTA (ifaddr), len);  

	if (tb[IFA_LABEL] != NULL) {  
		if (tb[IFA_ADDRESS] != NULL) {  

			inet_ntop(ifaddr->ifa_family, RTA_DATA(tb[IFA_ADDRESS]), tmp, sizeof(tmp));  

			if(nh->nlmsg_type==RTM_NEWADDR){
				init_timer_manage(0);
				
				memset(LOCAL_IP, 0 , IP_LENGTH);
				memcpy(LOCAL_IP, tmp, strlen(tmp));
	
				usleep(200000);
				unsigned char localip[IP_LENGTH];
				if(TRUE == get_ip(localip))
				{
					if(strcmp((const char *)localip, tmp) == 0)
					{
						pcallback("NEWADDR" , tmp ,1);
					}
					else
					{
						memset(localip, 0 , IP_LENGTH);
						memcpy(localip, tmp, IP_LENGTH);
						set_ip(localip);
					}
				}
				else
				{
					memset(localip, 0 , IP_LENGTH);
					memcpy(localip, tmp, IP_LENGTH);
					set_ip(localip);
					return;
				}
				
				const char * delim = "\\.";			//分隔符字符串
				char* p=strtok(tmp,delim);	//第一次调用strtok
				int ipLen = 3;
				std::string strip = "";
				while(p!=NULL && ipLen--){				//当返回值不为NULL时，继续循环
					// printf("%s\n",p);		//输出分解的字符串
					strip = strip + p + ".";
					p=strtok(NULL,delim);	//继续调用strtok，分解剩下的字符串
				}
				std::string strroute = strip + "0/24";
				
				strip = strip + "1";
				usleep(50000);
				
				pcallback("GETEWAY", strip,set_gateway((unsigned char*)strip.c_str()));
				// cmdroute[4] = (char *)strroute.c_str();

				
				// pcallback("ROUTE",strroute, do_iproute(7, cmdroute + 2) == 0 ? 1: 0 );
				
			}else{
				
			}				
		}				
	}  
}  
  
/** 
 * 显示路由信息 
 * 当路由变动的时候触发这个信息 
 */  
void print_rtmsg(struct nlmsghdr *nh)  
{  
	int len;  
	struct rtattr *tb[RTA_MAX + 1];  
	struct rtmsg *rt;  
	char tmp[256];  
	bzero(tb, sizeof(tb));  
	rt = (rtmsg *)NLMSG_DATA(nh);  
	len = nh->nlmsg_len - NLMSG_SPACE(sizeof(*rt));  
	parse_rtattr(tb, RTA_MAX, RTM_RTA(rt), len);  
	// printf("%s: ", (nh->nlmsg_type==RTM_NEWROUTE)?"-NEWROUT":"-DELROUT"); 
	
	if (tb[RTA_DST] != NULL) {  
		inet_ntop(rt->rtm_family, RTA_DATA(tb[RTA_DST]), tmp, sizeof(tmp));  
		// printf("-RTA_DST %s ", tmp);  
	}  
	if (tb[RTA_SRC] != NULL) {  
		inet_ntop(rt->rtm_family, RTA_DATA(tb[RTA_SRC]), tmp, sizeof(tmp));  
		// printf("-RTA_SRC %s ", tmp);  
	}  
	if (tb[RTA_GATEWAY] != NULL) {  
		inet_ntop(rt->rtm_family, RTA_DATA(tb[RTA_GATEWAY]), tmp, sizeof(tmp));  
		// printf("-RTA_GATEWAY %s ", tmp); 
		
		usleep(200);
		if(nh->nlmsg_type==RTM_DELROUTE){
			pcallback("GETEWAYDEL", tmp,1);
			set_gateway((unsigned char *)tmp);
		}else if(nh->nlmsg_type==RTM_NEWROUTE){
			pcallback("GETEWAYADD", tmp,1);	
		}
	}    
} 

int get_ip(unsigned char ip[IP_LENGTH])
{
    return get_addr(ip, SIOCGIFADDR);
}


int get_ip_netmask(unsigned char ip[IP_LENGTH])
{
    return get_addr(ip, SIOCGIFNETMASK);
}

int get_mac(unsigned char addr[18])
{
    return get_addr(addr, SIOCGIFHWADDR);
}

static int get_addr(unsigned char *addr, int flag)
{
    SINT32 sockfd = 0;
    struct sockaddr_in *sin;
    struct ifreq ifr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket error!\n");
        return FALSE;
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, (sizeof(ifr.ifr_name) - 1), "%s", DEFAULT_ETH);

    if(ioctl(sockfd, flag, &ifr) < 0 )
    {
        // perror("ioctl error!\n");
        close(sockfd);
        return FALSE;
    }
    close(sockfd);

    if (SIOCGIFHWADDR == flag){
        memcpy((void *)addr, (const void *)&ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);
        // sprintf((char *)addr,"%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x", addr[0],addr[1],addr[2],addr[3],addr[4],addr[5]);
    }else{
        sin = (struct sockaddr_in *)&ifr.ifr_addr;
        snprintf((char *)addr, IP_LENGTH, "%s", inet_ntoa(sin->sin_addr));
    }

    return TRUE;
}

int is_valid_ip(unsigned char ipaddr[IP_LENGTH])
{
    int ret = 0;
    struct in_addr inp;
    ret = inet_aton((const char*)ipaddr, &inp);
    if (0 == ret)
    {
        return FALSE;
    }
    else
    {
        // printf("inet_aton:ip=%lu\n",ntohl(inp.s_addr));
    }

    return TRUE;
}

/*
 * 先验证是否为合法IP，然后将掩码转化成32无符号整型，取反为000...00111...1，
 * 然后再加1为00...01000...0，此时为2^n，如果满足就为合法掩码
 *
 * */
int is_valid_netmask(unsigned char netmask[IP_LENGTH])
{
    if(is_valid_ip(netmask) > 0)
    {
        unsigned int b = 0, i, n[4];
        sscanf((char*)netmask, "%u.%u.%u.%u", (int*)(&n[3]), (int*)(&n[2]), (int*)(&n[1]), (int*)(&n[0]));
        for(i = 0; i < 4; ++i) //将子网掩码存入32位无符号整型
            b += n[i] << (i * 8);
        b = ~b + 1;
        if((b & (b - 1)) == 0) //判断是否为2^n
            return TRUE;
    }

    return FALSE;
}


int set_ip_netmask(unsigned char ip[IP_LENGTH])
{
    return set_addr(ip, SIOCSIFNETMASK);
}

int set_ip(unsigned char ip[IP_LENGTH])
{
    return set_addr(ip, SIOCSIFADDR);
}

static int set_addr(unsigned char ip[IP_LENGTH], int flag)
{
    struct ifreq ifr;
    struct sockaddr_in sin;
    int sockfd;

    pthread_mutex_lock(&ipconfigMutex);

    if (is_valid_ip(ip) < 0)
    {
        // printf("ip was invalid!\n");
        pthread_mutex_unlock(&ipconfigMutex);
        return FALSE;
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd == -1){
        fprintf(stderr, "Could not get socket.\n");;
        pthread_mutex_unlock(&ipconfigMutex);
        return FALSE;
    }

    snprintf(ifr.ifr_name, (sizeof(ifr.ifr_name) - 1), "%s", DEFAULT_ETH);

    /* Read interface flags */
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "ifdown: shutdown ");
        perror(ifr.ifr_name);
        pthread_mutex_unlock(&ipconfigMutex);
        return FALSE;
    }

    memset(&sin, 0, sizeof(struct sockaddr));
    sin.sin_family = AF_INET;
    inet_aton((const char*)ip, (in_addr*)(&sin.sin_addr.s_addr));
    memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
    if (ioctl(sockfd, flag, &ifr) < 0){
        fprintf(stderr, "Cannot set IP address. ");
        perror(ifr.ifr_name);
        pthread_mutex_unlock(&ipconfigMutex);
        return FALSE;
    }
	pthread_mutex_unlock(&ipconfigMutex);
    return TRUE;
}

int set_gateway(unsigned char ip[IP_LENGTH])
{
    int sockFd;
    struct sockaddr_in sockaddr;
    struct rtentry rt;

    pthread_mutex_lock(&ipconfigMutex);

    if (is_valid_ip(ip) < 0)
    {
        // printf("gateway was invalid!\n")
        pthread_mutex_unlock(&ipconfigMutex);
        return FALSE;
    }

    sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0)
    {
        perror("Socket create error.\n");
        pthread_mutex_unlock(&ipconfigMutex);
        return FALSE;
    }

    memset(&rt, 0, sizeof(struct rtentry));
    memset(&sockaddr, 0, sizeof(struct sockaddr_in));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = 0;
    if(inet_aton((const char*)ip, &sockaddr.sin_addr)<0)
    {
        perror("inet_aton error\n" );
        close(sockFd);
        pthread_mutex_unlock(&ipconfigMutex);
        return FALSE;
    }

    memcpy ( &rt.rt_gateway, &sockaddr, sizeof(struct sockaddr_in));
    ((struct sockaddr_in *)&rt.rt_dst)->sin_family=AF_INET;
    ((struct sockaddr_in *)&rt.rt_genmask)->sin_family=AF_INET;
    rt.rt_flags = RTF_GATEWAY;
    if (ioctl(sockFd, SIOCADDRT, &rt)<0)
    {
        perror("ioctl(SIOCADDRT) error in set_default_route\n");
        close(sockFd);
        pthread_mutex_unlock(&ipconfigMutex);
        return FALSE;
    }

	pthread_mutex_unlock(&ipconfigMutex);
    return TRUE;
}
 
void* soc_thread(void *arg)
{
	int socket_fd;  
	int err = 0;
	int read_r;  
	struct sockaddr_nl sa;  
	struct nlmsghdr *nh;  
  
  
	int len = BUFLEN;  
	char buff[2048];  
	// signal(SIGINT, intHandler);  
  
	/*打开NetLink Socket*/  
	socket_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);  
	t_assert(socket_fd > 0);  
	t_assert(!setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &len, sizeof(len)));  
  
	/*设定接收类型并绑定Socket*/  
	bzero(&sa, sizeof(sa));  
	sa.nl_family = AF_NETLINK;  
	sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE;  
	t_assert(!bind(socket_fd, (struct sockaddr *) &sa, sizeof(sa))); 
  
  	pthread_mutex_unlock(&ipconfigMutex);

	while (keepRunning) {  
		read_r = read(socket_fd, buff, sizeof(buff));  
		for (nh = (struct nlmsghdr *) buff; NLMSG_OK(nh, read_r); nh = NLMSG_NEXT(nh, read_r)) {  
			switch (nh->nlmsg_type) {  
			default:  
				/*收到些奇怪的信息*/  
				printf(" 收到些奇怪的信息 nh->nlmsg_type = %d\n", nh->nlmsg_type);  
				break;  
			case NLMSG_DONE:  
			case NLMSG_ERROR:  
				break;  
			case RTM_NEWLINK:  
			case RTM_DELLINK:  
				print_ifinfomsg(nh);  
				break;  
			case RTM_NEWADDR:  
			case RTM_DELADDR:  
				print_ifaddrmsg(nh);  
				break;  
			case RTM_NEWROUTE:  
			case RTM_DELROUTE:  
				print_rtmsg(nh);  
				break;  
			}  

		}   
	}  
  
	close(socket_fd);  
  
error:  
	if (err < 0) {  
		printf("Error at line %d\nErrno=%d\n", -err, errno);  
	} 

	return NULL;
}
 
 
EthMonitor::EthMonitor()
{
	pthread_mutex_init(&ipconfigMutex, NULL);
}

EthMonitor::~EthMonitor()
{	

}

void EthMonitor::monitorBack(void (*fun)(std::string command,std::string ipInfo, int result))
{
	pcallback = fun;
}

/**
设置默认IP
*/
int EthMonitor::setDefaultIP(std::string localip)
{
	if(getLocalIP() == localip)
	{
		return -1;
	}
	else
	{
		if(TRUE == is_valid_ip((unsigned char*)localip.c_str()))
		{
			memcpy(LOCAL_IP, localip.c_str(), localip.length());
			LOCAL_IP[localip.length()] = '\0';
			configDefaultIP();
			return 0;
		}else
		{
			return -1;
		}
	}
	
}


/**
配置默认IP
*/
int EthMonitor::configDefaultIP()
{
	if(strcmp(getLocalIP().c_str(),(const char *)LOCAL_IP) == 0)
	{
		return -1;
	}
	return set_ip(LOCAL_IP);
}

/**
获取默认IP
*/
std::string EthMonitor::getDefaultIP()
{
	return (const char*)LOCAL_IP;
}

/***
获取当前设备IP
*/
std::string EthMonitor::getLocalIP()
{
	unsigned char localip[IP_LENGTH];
	if(TRUE == get_ip(localip))
	{
		return (const char*)localip;
	}else{
		return "";
	}
}

/***
获取当前设备gateway
*/
std::string EthMonitor::getGateway()
{
	unsigned char gatewayip[IP_LENGTH];
    unsigned char interface[IP_LENGTH];
	if(0 == getGatewayAndIface((char *)gatewayip , (char *)interface))
	{
		return (const char*)gatewayip;
	}else{
		return "";
	}
}

int EthMonitor::getHexIP(unsigned char hexip[4])
{
	unsigned char ip[IP_LENGTH];
	int result = get_addr(ip, SIOCGIFADDR);
	if(result && is_valid_ip(ip)){
		const char * delim = "\\.";			//分隔符字符串
		char* p = strtok((char *)ip,delim);	//第一次调用strtok
		int index = 3;
		while(p != NULL && index >= 0){				//当返回值不为NULL时，继续循环
			hexip[index] = atoi(p);
			index--;
			p=strtok(NULL,delim);	//继续调用strtok，分解剩下的字符串
		}
		return TRUE;
	}else{
		return FALSE;
	}
}

/**
获取设备MAC
*/
int EthMonitor::getDevMAC(unsigned char addr[6])
{
	return get_mac(addr);
}

int EthMonitor::StartMonitor()  
{  
	pthread_t id;
	pthread_mutex_lock(&ipconfigMutex);
    return pthread_create(&id, NULL, soc_thread, NULL);
}  

void EthMonitor::StopMonitor() 
{
	keepRunning = 0;
}
