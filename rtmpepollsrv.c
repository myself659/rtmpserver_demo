

/* 
a epoll demo for rtmp server 

*/

/* 头文件 */
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>

#include <signal.h>
#include <getopt.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/epoll.h>

#include <assert.h>

#include "librtmp/rtmp_sys.h"
#include "librtmp/log.h"
#include "librtmp/rtmp.h"
#include "thread.h"
#include <errno.h>

#include <linux/netfilter_ipv4.h>
#include <stddef.h>  
#include <linux/kernel.h>







enum
{
  STREAMING_ACCEPTING,
  STREAMING_IN_PROGRESS,
  STREAMING_STOPPING,
  STREAMING_STOPPED
};


typedef enum tagRTMPSERVER_STATE
{
	RTMPSERVER_STATE_INIT  = 0,
	RTMPSERVER_STATE_SUCCESS,
	RTMPSERVER_STATE_BUTT
}RTMPSERVER_STATE_E;

/* 数据结构定义  */
 
typedef struct
{
  int socket;
  int state;
  int streamID;
  int arglen;
  int argc;
  uint32_t filetime;	/* time of last download we started */
  AVal filename;	/* name of last download */
  char *connect;
  int  handshake; 
  RTMP *prtmp;
  RTMPPacket *pPkt;
} RTMP_SESSION;

typedef struct
{
  char *hostname;
  int rtmpport;
  int protocol;
  int bLiveStream;		// is it a live stream? then we can't seek/resume

  long int timeout;		// timeout connection afte 300 seconds
  uint32_t bufferTime;

  char *rtmpurl;
  AVal playpath;
  AVal swfUrl;
  AVal tcUrl;
  AVal pageUrl;
  AVal app;
  AVal auth;
  AVal swfHash;
  AVal flashVer;
  AVal subscribepath;
  uint32_t swfSize;

  uint32_t dStartOffset;
  uint32_t dStopOffset;
  uint32_t nTimeStamp;
} RTMP_REQUEST;

/* 定义epoll 回调处理函数 */

typedef int (* EpollCallBack_PF)(int iFd,int iEvent, void *pContext);


typedef struct 
{
	int iFd; 
	EpollCallBack_PF pfHandle;
	void  *pContext;
}EPOLL_CTX;

#define SAVC(x) static const AVal av_##x = AVC(#x)

SAVC(app);
SAVC(connect);
SAVC(flashVer);
SAVC(swfUrl);
SAVC(pageUrl);
SAVC(tcUrl);
SAVC(fpad);
SAVC(capabilities);
SAVC(audioCodecs);
SAVC(videoCodecs);
SAVC(videoFunction);
SAVC(objectEncoding);
SAVC(_result);
SAVC(createStream);
SAVC(getStreamLength);
SAVC(play);
SAVC(fmsVer);
SAVC(mode);
SAVC(level);
SAVC(code);
SAVC(description);
SAVC(secureToken);

#define  RTMP_EPOLLSRV_INVALIDFD (-1)
#define  RTMP_EPOLLSRV_MAXEPOLL   (16)

#define  ERROR_OK         (0x0)
#define  ERROR_FAILED     (-1)

/* 内部函数声明  */
int epoll_op(int iEpollFd, int iOp, int iFd, int iEvent,  EPOLL_CTX *pCtx);


/* 全局变量 */
static int g_iEpollFd = RTMP_EPOLLSRV_INVALIDFD; 
static int g_iListenFd = RTMP_EPOLLSRV_INVALIDFD;

static char *g_cRtmpSrvAddr = "0.0.0.0";
static unsigned short g_usRtmpSrvPort = 8080;




void  RtmpSessionFini(RTMP_SESSION *pSession)
{
	if(NULL != pSession->prtmp)
	{
		RTMP_Free(pSession->prtmp);
		pSession->prtmp = NULL;
	}

	if(NULL != pSession->pPkt)
	{
		RTMPPacket_Free(pSession->pPkt);
		free(pSession->pPkt);
		pSession->pPkt = NULL;
	}
	
	return ;	
}

int RtmpSessionHandshake(RTMP_SESSION *pSession)
{
	int iRet;
	RTMPPacket *pPkt = (RTMPPacket *)malloc(sizeof(RTMPPacket));
	if(NULL == pPkt)
	{
		return ERROR_FAILED;	
	}
	pSession->pPkt = pPkt;
	RTMP *rtmp = RTMP_Alloc(); 
	if(NULL == rtmp )
	{
		return ERROR_FAILED;
	}

	RTMP_Init(rtmp);
	rtmp->m_sb.sb_socket =  pSession->socket;
	pSession->prtmp = rtmp;

	pSession->state = STREAMING_IN_PROGRESS;

	/* 进行握手处理 */
	iRet = RTMP_Serve(rtmp);
	if( 0 == iRet)
	{
		pSession->handshake = 1;
		pSession->arglen = 0;
	}
	
	return iRet;
}


void RtmpEPOLLCTXFini(EPOLL_CTX *pCtx)
{
	/* 从epoll 删除fd */
	(void)epoll_op(g_iEpollFd, EPOLL_CTL_DEL, pCtx->iFd, EPOLLIN|EPOLLERR|EPOLLHUP, NULL);
	close(pCtx->iFd);
	
	free(pCtx->pContext);

	free(pCtx);
	
	return ;
}



int RtmpPktHandle(RTMP_SESSION *pSession)
{
	RTMP *pRtmp  =  pSession->prtmp;
	RTMPPacket *pPkt = pSession->pPkt;

	if(!RTMP_IsConnected(pRtmp)  || 
	   !RTMP_ReadPacket(pRtmp, pPkt) ||
	   !(RTMPPacket_IsReady(pPkt)))
	{
		return -1;
	}
	
	/* 处理报文 */	
	RTMP_Log(RTMP_LOGDEBUG, "%s, received packet type %02X, size %u bytes", __FUNCTION__,
pPkt->m_packetType, pPkt->m_nBodySize);
	switch(pPkt->m_packetType)
	{
		case RTMP_PACKET_TYPE_CHUNK_SIZE:
		{
			break;
		}

		case RTMP_PACKET_TYPE_BYTES_READ_REPORT:
		{
			break;
		}

		case RTMP_PACKET_TYPE_CONTROL:
		{
			break;
		}

		case RTMP_PACKET_TYPE_SERVER_BW:
		{
			break;
		}

		case RTMP_PACKET_TYPE_CLIENT_BW:
		{
			break;
		}
		case RTMP_PACKET_TYPE_AUDIO:
		{
			break;
		}

		case RTMP_PACKET_TYPE_VIDEO:
		{
			break;
		}
		
		default:
		{
			break;
		}
	}
    
    
    
	RTMPPacket_Free(pPkt);

	return 0;
}

int RtmpSessionHandle(int iFd, int iEvent, void *pContext)
{
	int iRet;
	RTMP_SESSION *pSession = (RTMP_SESSION *)pContext;
	EPOLL_CTX *pCtx;
	
	if(iEvent|EPOLLIN )
	{
		if(0 == pSession->handshake)
		{
			iRet = RtmpSessionHandshake(pSession);		
  			if(0 != iRet)
  			{
				RtmpSessionFini(pSession);
				//pCtx = container_of(&pSession, EPOLL_CTX, pContext);
				//RtmpEPOLLCTXFini(pCtx);
  			}
		}
		else
		{
			iRet = 	RtmpPktHandle(pSession);
		}
	}

		
	return iRet;
}




int ListenHandle(int iFd, int iEvent, void *pContext)
{
	int iNewFd;
	int iRet = 0;
	struct sockaddr tmpAddr;
	memset(&tmpAddr, 0, sizeof(tmpAddr));
	int iSocketSize = sizeof(tmpAddr);
	EPOLL_CTX *pCtx; 
	RTMP_SESSION *pServer;
	
	if(iEvent|EPOLLIN)
	{
		iNewFd =  accept(iFd, &tmpAddr, (socklen_t *)&iSocketSize); 
		if(RTMP_EPOLLSRV_INVALIDFD < iNewFd)	
		{
			pServer = (RTMP_SESSION *)malloc(sizeof(RTMP_SESSION));
			if(NULL == pServer)
			{
				return -1;
			}
			pServer->handshake  = 0; 
			pCtx = (EPOLL_CTX *)malloc(sizeof(EPOLL_CTX));
			if(NULL == pCtx)
			{
				free(pServer);
				return -1;
			}
			pServer->socket = iNewFd;
			pCtx->iFd = iNewFd;
			pCtx->pContext = pServer;
			pCtx->pfHandle = RtmpSessionHandle;
			/* 加入epoll */
			iRet = epoll_op(g_iEpollFd, EPOLL_CTL_ADD, iNewFd,  EPOLLIN|EPOLLERR|EPOLLHUP,  pCtx);
			
		}
		else
		{
			printf("accept errno:%s",strerror(errno));
		}
	}

	return iRet;
}


int epoll_op(int iEpollFd, int iOp, int iFd, int iEvent,  EPOLL_CTX *pCtx)
{
	int iRet;
	struct epoll_event ev;

	ev.events = iEvent;
	ev.data.ptr = pCtx;
	
	iRet = epoll_ctl(iEpollFd, iOp, iFd, &ev);
	
	return iRet;
}


int epoll_loop(int iEpollFd)
{
	int iNum;
	struct epoll_event astEpEvent[RTMP_EPOLLSRV_MAXEPOLL];
	int i;
	EpollCallBack_PF pfHandle;
	EPOLL_CTX *pCtx;
	for( ;  ;)
	{
		iNum= epoll_wait(iEpollFd, &astEpEvent[0],	RTMP_EPOLLSRV_MAXEPOLL, -1);
		if( 0 < iNum)
		{
			for(i = 0; i < iNum; i++)
			{
				pCtx = (EPOLL_CTX *)astEpEvent[i].data.ptr;
				pfHandle = pCtx->pfHandle;
				(void)pfHandle(pCtx->iFd, astEpEvent[i].events, pCtx->pContext);
			}
		}
		else
		{
			printf("epoll_wait failed\r\n");
		}
	}

	return 0;
}

int main(void)
{
	int iFd;
	struct sockaddr_in addr;
	
	printf("in the main\r\n");
	/* 初始化epoll */
	g_iEpollFd = epoll_create(200);
	if(RTMP_EPOLLSRV_INVALIDFD >= g_iEpollFd)
	{
		printf("create epoll failed\r\n");
		return  -1;
	}

	
	/* 创建侦听端口 */
	iFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(RTMP_EPOLLSRV_INVALIDFD >= iFd)
	{
		printf("create listen socket failed\r\n");
		return  -1;
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(g_cRtmpSrvAddr);
	addr.sin_port = htons(g_usRtmpSrvPort);

	if( 0 != bind(iFd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)))
	{
		return  -1;	 
	}


	if( 0 != listen(iFd, 200))
	{
		return  -1;
	}

	EPOLL_CTX *pEpollCtx = (EPOLL_CTX *)malloc(sizeof(EPOLL_CTX));
	if(NULL == pEpollCtx)
	{
		return -1;
	}

	pEpollCtx->iFd = iFd;
	pEpollCtx->pfHandle = ListenHandle;
	pEpollCtx->pContext = NULL;
	/* 加入epoll */
	if(0 != epoll_op(g_iEpollFd, EPOLL_CTL_ADD, iFd, EPOLLIN|EPOLLERR|EPOLLHUP, pEpollCtx))
	{
		return -1;
	}

	g_iListenFd = iFd;

	epoll_loop(g_iEpollFd);
	

	
	return  0;
	
}










