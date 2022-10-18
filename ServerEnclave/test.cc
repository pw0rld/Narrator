#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    int sockfd;
    struct ifconf ifconf;
    struct ifreq *ifreq;
    char buf[512]; //缓冲区
    //初始化ifconf
    ifconf.ifc_len = 512;
    ifconf.ifc_buf = buf;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");
        exit(1);
    }
    ioctl(sockfd, SIOCGIFCONF, &ifconf); //获取所有接口信息

    //接下来一个一个的获取IP地址
    ifreq = (struct ifreq *)ifconf.ifc_buf;
    printf("ifconf.ifc_len:%d\n", ifconf.ifc_len);
    printf("sizeof (struct ifreq):%d\n", sizeof(struct ifreq));

    for (int i = (ifconf.ifc_len / sizeof(struct ifreq)); i > 0; i--)
    {
        if (ifreq->ifr_flags == AF_INET)
        { // for ipv4
            printf("name =[%s]\n", ifreq->ifr_name);
            printf("local addr = [%s]\n", inet_ntoa(((struct sockaddr_in *)&(ifreq->ifr_addr))->sin_addr));
            ifreq++;
        }
    }

    return 0;
}