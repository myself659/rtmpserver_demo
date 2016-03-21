

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
#include <unistd.h>
#include <fcntl.h>

#include <assert.h>

#include "librtmp/rtmp_sys.h"
#include "librtmp/log.h"
#include "librtmp/rtmp.h"
#include "thread.h"
#include <errno.h>

#include <linux/netfilter_ipv4.h>
#include <stddef.h>  
#include <linux/kernel.h>
#include <stddef.h>


typedef enum tagRTMPSESSION_STATE
{
 RTMPSESSION_INIT = 0, 
 RTMPSESSION_C0 ,
 RTMPSESSION_C1,
 RTMPSESSION_S0,
 RTMPSESSION_S1,
 RTMPSESSION_C2,
 RTMPSESSION_S2,
 RTMPSESSION_CONNECTOK
}RTMPSESSION_STATE_E;





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

typedef int (*EpollCallBack_PF)(int iFd,int iEvent, void *pContext);


typedef struct 
{
	int iFd; 
	EpollCallBack_PF pfHandle;
	void  *pContext;
}EPOLL_CTX;

#define SAVC(x) static const AVal av_##x = AVC(#x)

#define RTMPEPOLLSRV_DUPTIME  5000
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
SAVC(publish); 

#define  RTMP_EPOLLSRV_INVALIDFD (-1)
#define  RTMP_EPOLLSRV_MAXEPOLL   (16)

#define  ERROR_OK         (0x0)
#define  ERROR_FAILED     (-1)
#define  STR2AVAL(av,str)  av.av_val = str; av.av_len = strlen(av.av_val)

/* 内部函数声明  */
int epoll_op(int iEpollFd, int iOp, int iFd, int iEvent,  EPOLL_CTX *pCtx);
static 
int RtmpPktHandle(RTMP_SESSION *pSession);


/* 全局变量 */
static int g_iEpollFd = RTMP_EPOLLSRV_INVALIDFD; 
static int g_iListenFd = RTMP_EPOLLSRV_INVALIDFD;

static char *g_cRtmpSrvAddr = "0.0.0.0";
static unsigned short g_usRtmpSrvPort = 8080;

static const AVal av_dquote = AVC("\"");
static const AVal av_escdquote = AVC("\\\"");

static 
int SetNonBlocking(int nSocket)
{
     int opts;
     opts=fcntl(nSocket, F_GETFL);
     if(opts<0)
     {
          return -1;
     }
     opts = opts|O_NONBLOCK;
     opts = opts|O_NDELAY;
     if(fcntl(nSocket,F_SETFL,opts)<0)
     {
          return -1;
     }
 	
     int on = 1;
     setsockopt(nSocket, SOL_TCP, TCP_NODELAY,  &on, sizeof(on));
     
	 return 0;
}


static int
countAMF(AMFObject *obj, int *argc)
{
  int i, len;

  for (i = 0, len = 0; i < obj->o_num; i++)
  {
    AMFObjectProperty *p = &obj->o_props[i];
    len += 4;
    (*argc) += 2;
    if (p->p_name.av_val)
      len += 1;
    len += 2;
    if (p->p_name.av_val)
      len += p->p_name.av_len + 1;
    switch (p->p_type)
    {
    case AMF_BOOLEAN:
      len += 1;
      break;
    case AMF_STRING:
      len += p->p_vu.p_aval.av_len;
      break;
    case AMF_NUMBER:
      len += 40;
      break;
    case AMF_OBJECT:
      len += 9;
      len += countAMF(&p->p_vu.p_object, argc);
      (*argc) += 2;
      break;
    case AMF_NULL:
    default:
      break;
    }
  }
  return len;
}


static void
spawn_dumper(int argc, AVal *av, char *cmd)
{
#ifdef WIN32
  STARTUPINFO si = {0};
  PROCESS_INFORMATION pi = {0};

  si.cb = sizeof(si);
  if (CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL,
                    &si, &pi))
  {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  }
#else
  /* reap any dead children */
  while (waitpid(-1, NULL, WNOHANG) > 0);

  if (fork() == 0) {
    char **argv = malloc((argc + 1) * sizeof(char *));
    int i;

    for (i = 0; i < argc; i++) {
      argv[i] = av[i].av_val;
      argv[i][av[i].av_len] = '\0';
    }
    argv[i] = NULL;
    if ((i = execvp(argv[0], argv)))
      _exit(i);
  }
#endif
}

static char *
dumpAMF(AMFObject *obj, char *ptr, AVal *argv, int *argc)
{
  int i, len, ac = *argc;
  const char opt[] = "NBSO Z";

  for (i = 0, len = 0; i < obj->o_num; i++)
  {
    AMFObjectProperty *p = &obj->o_props[i];
    argv[ac].av_val = ptr + 1;
    argv[ac++].av_len = 2;
    ptr += sprintf(ptr, " -C ");
    argv[ac].av_val = ptr;
    if (p->p_name.av_val)
      *ptr++ = 'N';
    *ptr++ = opt[p->p_type];
    *ptr++ = ':';
    if (p->p_name.av_val)
      ptr += sprintf(ptr, "%.*s:", p->p_name.av_len, p->p_name.av_val);
    switch (p->p_type)
    {
    case AMF_BOOLEAN:
      *ptr++ = p->p_vu.p_number != 0 ? '1' : '0';
      argv[ac].av_len = ptr - argv[ac].av_val;
      break;
    case AMF_STRING:
      memcpy(ptr, p->p_vu.p_aval.av_val, p->p_vu.p_aval.av_len);
      ptr += p->p_vu.p_aval.av_len;
      argv[ac].av_len = ptr - argv[ac].av_val;
      break;
    case AMF_NUMBER:
      ptr += sprintf(ptr, "%f", p->p_vu.p_number);
      argv[ac].av_len = ptr - argv[ac].av_val;
      break;
    case AMF_OBJECT:
      *ptr++ = '1';
      argv[ac].av_len = ptr - argv[ac].av_val;
      ac++;
      *argc = ac;
      ptr = dumpAMF(&p->p_vu.p_object, ptr, argv, argc);
      ac = *argc;
      argv[ac].av_val = ptr + 1;
      argv[ac++].av_len = 2;
      argv[ac].av_val = ptr + 4;
      argv[ac].av_len = 3;
      ptr += sprintf(ptr, " -C O:0");
      break;
    case AMF_NULL:
    default:
      argv[ac].av_len = ptr - argv[ac].av_val;
      break;
    }
    ac++;
  }
  *argc = ac;
  return ptr;
}

static int
SendConnectResult(RTMP *r, double txn)
{
  RTMPPacket packet;
  char pbuf[384], *pend = pbuf + sizeof(pbuf);
  AMFObject obj;
  AMFObjectProperty p, op;
  AVal av;

  packet.m_nChannel = 0x03;     // control channel (invoke)
  packet.m_headerType = 1; /* RTMP_PACKET_SIZE_MEDIUM; */
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av__result);
  enc = AMF_EncodeNumber(enc, pend, txn);
  *enc++ = AMF_OBJECT;

  STR2AVAL(av, "FMS/3,5,1,525");
  enc = AMF_EncodeNamedString(enc, pend, &av_fmsVer, &av);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_capabilities, 31.0);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_mode, 1.0);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  *enc++ = AMF_OBJECT;

  STR2AVAL(av, "status");
  enc = AMF_EncodeNamedString(enc, pend, &av_level, &av);
  STR2AVAL(av, "NetConnection.Connect.Success");
  enc = AMF_EncodeNamedString(enc, pend, &av_code, &av);
  STR2AVAL(av, "Connection succeeded.");
  enc = AMF_EncodeNamedString(enc, pend, &av_description, &av);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_objectEncoding, r->m_fEncoding);
#if 0
  STR2AVAL(av, "58656322c972d6cdf2d776167575045f8484ea888e31c086f7b5ffbd0baec55ce442c2fb");
  enc = AMF_EncodeNamedString(enc, pend, &av_secureToken, &av);
#endif
  STR2AVAL(p.p_name, "version");
  STR2AVAL(p.p_vu.p_aval, "3,5,1,525");
  p.p_type = AMF_STRING;
  obj.o_num = 1;
  obj.o_props = &p;
  op.p_type = AMF_OBJECT;
  STR2AVAL(op.p_name, "data");
  op.p_vu.p_object = obj;
  enc = AMFProp_Encode(&op, enc, pend);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, FALSE);
}

static int
SendResultNumber(RTMP *r, double txn, double ID)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x03;     // control channel (invoke)
  packet.m_headerType = 1; /* RTMP_PACKET_SIZE_MEDIUM; */
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av__result);
  enc = AMF_EncodeNumber(enc, pend, txn);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeNumber(enc, pend, ID);

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, FALSE);
}

SAVC(onStatus);  /* 增加发布回应处理 */
SAVC(status);
static const AVal av_NetStream_Play_Start = AVC("NetStream.Play.Start");
static const AVal av_Started_playing = AVC("Started playing");
static const AVal av_NetStream_Play_Stop = AVC("NetStream.Play.Stop");
static const AVal av_Stopped_playing = AVC("Stopped playing");
static const AVal av_NetStream_Publish_Start = AVC("NetStream.Publish.Start");
static const AVal av_NetStream_Publish_Desc = AVC("Started publishing stream");

SAVC(details);
SAVC(clientid);
static const AVal av_NetStream_Authenticate_UsherToken = AVC("NetStream.Authenticate.UsherToken");

static void
AVreplace(AVal *src, const AVal *orig, const AVal *repl)
{
  char *srcbeg = src->av_val;
  char *srcend = src->av_val + src->av_len;
  char *dest, *sptr, *dptr;
  int n = 0;

  /* count occurrences of orig in src */
  sptr = src->av_val;
  while (sptr < srcend && (sptr = strstr(sptr, orig->av_val)))
  {
    n++;
    sptr += orig->av_len;
  }
  if (!n)
    return;

  dest = malloc(src->av_len + 1 + (repl->av_len - orig->av_len) * n);

  sptr = src->av_val;
  dptr = dest;
  while (sptr < srcend && (sptr = strstr(sptr, orig->av_val)))
  {
    n = sptr - srcbeg;
    memcpy(dptr, srcbeg, n);
    dptr += n;
    memcpy(dptr, repl->av_val, repl->av_len);
    dptr += repl->av_len;
    sptr += orig->av_len;
    srcbeg = sptr;
  }
  n = srcend - srcbeg;
  memcpy(dptr, srcbeg, n);
  dptr += n;
  *dptr = '\0';
  src->av_val = dest;
  src->av_len = dptr - dest;
}

static int SendPublishStart(RTMP * r)
{

	RTMPPacket packet;
	char pbuf[512], *pend = pbuf + sizeof(pbuf);
	
	packet.m_nChannel = 0x03;     // control channel (invoke)
    packet.m_headerType = 1; /* RTMP_PACKET_SIZE_MEDIUM; */
    packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = 0;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;
    
	char *enc = packet.m_body;
	enc = AMF_EncodeString(enc, pend, &av_onStatus);
	enc = AMF_EncodeNumber(enc, pend, 0);
	*enc++ = AMF_OBJECT;

	enc = AMF_EncodeNamedString(enc, pend, &av_level, &av_status);
	enc = AMF_EncodeNamedString(enc, pend, &av_code, &av_NetStream_Publish_Start);
	enc = AMF_EncodeNamedString(enc, pend, &av_description, &av_NetStream_Publish_Desc); 
	enc = AMF_EncodeNamedString(enc, pend, &av_clientid, &av_clientid);
	*enc++ = 0;
	*enc++ = 0;
	*enc++ = AMF_OBJECT_END;

	packet.m_nBodySize = enc - packet.m_body;
	return RTMP_SendPacket(r, &packet, FALSE);

}

static int
SendPlayStart(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[512], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x03;     // control channel (invoke)
  packet.m_headerType = 1; /* RTMP_PACKET_SIZE_MEDIUM; */
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_onStatus);
  enc = AMF_EncodeNumber(enc, pend, 0);
  *enc++ = AMF_OBJECT;

  enc = AMF_EncodeNamedString(enc, pend, &av_level, &av_status);
  enc = AMF_EncodeNamedString(enc, pend, &av_code, &av_NetStream_Play_Start);
  enc = AMF_EncodeNamedString(enc, pend, &av_description, &av_Started_playing);
  enc = AMF_EncodeNamedString(enc, pend, &av_details, &r->Link.playpath);
  enc = AMF_EncodeNamedString(enc, pend, &av_clientid, &av_clientid);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  packet.m_nBodySize = enc - packet.m_body;
  return RTMP_SendPacket(r, &packet, FALSE);
}

static int
SendPlayStop(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[512], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x03;     // control channel (invoke)
  packet.m_headerType = 1; /* RTMP_PACKET_SIZE_MEDIUM; */
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_onStatus);
  enc = AMF_EncodeNumber(enc, pend, 0);
  *enc++ = AMF_OBJECT;

  enc = AMF_EncodeNamedString(enc, pend, &av_level, &av_status);
  enc = AMF_EncodeNamedString(enc, pend, &av_code, &av_NetStream_Play_Stop);
  enc = AMF_EncodeNamedString(enc, pend, &av_description, &av_Stopped_playing);
  enc = AMF_EncodeNamedString(enc, pend, &av_details, &r->Link.playpath);
  enc = AMF_EncodeNamedString(enc, pend, &av_clientid, &av_clientid);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  packet.m_nBodySize = enc - packet.m_body;
  return RTMP_SendPacket(r, &packet, FALSE);
}



// Returns 0 for OK/Failed/error, 1 for 'Stop or Complete'
int
SessionInvoke(RTMP_SESSION *server,  RTMPPacket *packet, unsigned int offset)
{
  const char *body;
  unsigned int nBodySize;
  RTMP *pRtmp = server->prtmp;
  int ret = 0, nRes;

  body = packet->m_body + offset;
  nBodySize = packet->m_nBodySize - offset;

  if (body[0] != 0x02)    // make sure it is a string method name we start with
  {
    RTMP_Log(RTMP_LOGWARNING, "%s, Sanity failed. no string method in invoke packet",
             __FUNCTION__);
    return 0;
  }

  AMFObject obj;
  nRes = AMF_Decode(&obj, body, nBodySize, FALSE);
  if (nRes < 0)
  {
    RTMP_Log(RTMP_LOGERROR, "%s, error decoding invoke packet", __FUNCTION__);
    return 0;
  }

  AMF_Dump(&obj);
  AVal method;
  AMFProp_GetString(AMF_GetProp(&obj, NULL, 0), &method);
  double txn = AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 1));
  RTMP_Log(RTMP_LOGDEBUG, "%s, client invoking <%s>", __FUNCTION__, method.av_val);

  if (AVMATCH(&method, &av_connect)) /* 建立连接 */
  {
    AMFObject cobj;
    AVal pname, pval;
    int i;

    server->connect = packet->m_body;
    packet->m_body = NULL;

    AMFProp_GetObject(AMF_GetProp(&obj, NULL, 2), &cobj);
    for (i = 0; i < cobj.o_num; i++)
    {
      pname = cobj.o_props[i].p_name;
      pval.av_val = NULL;
      pval.av_len = 0;
      if (cobj.o_props[i].p_type == AMF_STRING)
        pval = cobj.o_props[i].p_vu.p_aval;
      if (AVMATCH(&pname, &av_app))
      {
        pRtmp->Link.app = pval;
        pval.av_val = NULL;
        if (!pRtmp->Link.app.av_val)
          pRtmp->Link.app.av_val = "";
        server->arglen += 6 + pval.av_len;
        server->argc += 2;
      }
      else if (AVMATCH(&pname, &av_flashVer))
      {
        pRtmp->Link.flashVer = pval;
        pval.av_val = NULL;
        server->arglen += 6 + pval.av_len;
        server->argc += 2;
      }
      else if (AVMATCH(&pname, &av_swfUrl))
      {
        pRtmp->Link.swfUrl = pval;
        pval.av_val = NULL;
        server->arglen += 6 + pval.av_len;
        server->argc += 2;
      }
      else if (AVMATCH(&pname, &av_tcUrl))
      {
        pRtmp->Link.tcUrl = pval;
        pval.av_val = NULL;
        server->arglen += 6 + pval.av_len;
        server->argc += 2;
      }
      else if (AVMATCH(&pname, &av_pageUrl))
      {
        pRtmp->Link.pageUrl = pval;
        pval.av_val = NULL;
        server->arglen += 6 + pval.av_len;
        server->argc += 2;
      }
      else if (AVMATCH(&pname, &av_audioCodecs))
      {
        pRtmp->m_fAudioCodecs = cobj.o_props[i].p_vu.p_number;
      }
      else if (AVMATCH(&pname, &av_videoCodecs))
      {
        pRtmp->m_fVideoCodecs = cobj.o_props[i].p_vu.p_number;
      }
      else if (AVMATCH(&pname, &av_objectEncoding))
      {
        pRtmp->m_fEncoding = cobj.o_props[i].p_vu.p_number;
      }
    }
    /* Still have more parameters? Copy them */
    if (obj.o_num > 3)
    {
      int i = obj.o_num - 3;
      pRtmp->Link.extras.o_num = i;
      pRtmp->Link.extras.o_props = malloc(i * sizeof(AMFObjectProperty));
      memcpy(pRtmp->Link.extras.o_props, obj.o_props + 3, i * sizeof(AMFObjectProperty));
      obj.o_num = 3;
      server->arglen += countAMF(&pRtmp->Link.extras, &server->argc);
    }
    SendConnectResult(pRtmp, txn);
  }
  else if (AVMATCH(&method, &av_createStream)) /* 创建流 */
  {
    SendResultNumber(pRtmp, txn, ++server->streamID); 
  }
  else  if(AVMATCH(&method, &av_publish))
  {
	SendPublishStart(pRtmp);
  }
  else if (AVMATCH(&method, &av_getStreamLength))
  {
    SendResultNumber(pRtmp, txn, 10.0);
  }
  else if (AVMATCH(&method, &av_NetStream_Authenticate_UsherToken))
  {
    AVal usherToken;
    AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &usherToken);
    AVreplace(&usherToken, &av_dquote, &av_escdquote);
    server->arglen += 6 + usherToken.av_len;
    server->argc += 2;
    pRtmp->Link.usherToken = usherToken;
  }
  else if (AVMATCH(&method, &av_play))  /* play  */
  {
    char *file, *p, *q, *cmd, *ptr;
    AVal *argv, av;
    int len, argc;
    uint32_t now;
    RTMPPacket pc = {0};
    AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &pRtmp->Link.playpath);
    /*
    pRtmp->Link.seekTime = AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 4));
    if (obj.o_num > 5)
    pRtmp->Link.length = AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 5));
    */
    if (pRtmp->Link.tcUrl.av_len)
    {
      len = server->arglen + pRtmp->Link.playpath.av_len + 4 +
            sizeof("rtmpdump") + pRtmp->Link.playpath.av_len + 12;
      server->argc += 5;

      cmd = malloc(len + server->argc * sizeof(AVal));
      ptr = cmd;
      argv = (AVal *)(cmd + len);
      argv[0].av_val = cmd;
      argv[0].av_len = sizeof("rtmpdump") - 1;
      ptr += sprintf(ptr, "rtmpdump");
      argc = 1;

      argv[argc].av_val = ptr + 1;
      argv[argc++].av_len = 2;
      argv[argc].av_val = ptr + 5;
      ptr += sprintf(ptr, " -pRtmp \"%s\"", pRtmp->Link.tcUrl.av_val);
      argv[argc++].av_len = pRtmp->Link.tcUrl.av_len;

      if (pRtmp->Link.app.av_val)
      {
        argv[argc].av_val = ptr + 1;
        argv[argc++].av_len = 2;
        argv[argc].av_val = ptr + 5;
        ptr += sprintf(ptr, " -a \"%s\"", pRtmp->Link.app.av_val);
        argv[argc++].av_len = pRtmp->Link.app.av_len;
      }
      if (pRtmp->Link.flashVer.av_val)
      {
        argv[argc].av_val = ptr + 1;
        argv[argc++].av_len = 2;
        argv[argc].av_val = ptr + 5;
        ptr += sprintf(ptr, " -f \"%s\"", pRtmp->Link.flashVer.av_val);
        argv[argc++].av_len = pRtmp->Link.flashVer.av_len;
      }
      if (pRtmp->Link.swfUrl.av_val)
      {
        argv[argc].av_val = ptr + 1;
        argv[argc++].av_len = 2;
        argv[argc].av_val = ptr + 5;
        ptr += sprintf(ptr, " -W \"%s\"", pRtmp->Link.swfUrl.av_val);
        argv[argc++].av_len = pRtmp->Link.swfUrl.av_len;
      }
      if (pRtmp->Link.pageUrl.av_val)
      {
        argv[argc].av_val = ptr + 1;
        argv[argc++].av_len = 2;
        argv[argc].av_val = ptr + 5;
        ptr += sprintf(ptr, " -p \"%s\"", pRtmp->Link.pageUrl.av_val);
        argv[argc++].av_len = pRtmp->Link.pageUrl.av_len;
      }
      if (pRtmp->Link.usherToken.av_val)
      {
        argv[argc].av_val = ptr + 1;
        argv[argc++].av_len = 2;
        argv[argc].av_val = ptr + 5;
        ptr += sprintf(ptr, " -j \"%s\"", pRtmp->Link.usherToken.av_val);
        argv[argc++].av_len = pRtmp->Link.usherToken.av_len;
        free(pRtmp->Link.usherToken.av_val);
        pRtmp->Link.usherToken.av_val = NULL;
        pRtmp->Link.usherToken.av_len = 0;
      }
      if (pRtmp->Link.extras.o_num) {
        ptr = dumpAMF(&pRtmp->Link.extras, ptr, argv, &argc);
        AMF_Reset(&pRtmp->Link.extras);
      }
      argv[argc].av_val = ptr + 1;
      argv[argc++].av_len = 2;
      argv[argc].av_val = ptr + 5;
      ptr += sprintf(ptr, " -y \"%.*s\"",
                     pRtmp->Link.playpath.av_len, pRtmp->Link.playpath.av_val);
      argv[argc++].av_len = pRtmp->Link.playpath.av_len;

      av = pRtmp->Link.playpath;
      /* strip trailing URL parameters */
      q = memchr(av.av_val, '?', av.av_len);
      if (q)
      {
        if (q == av.av_val)
        {
          av.av_val++;
          av.av_len--;
        }
        else
        {
          av.av_len = q - av.av_val;
        }
      }
      /* strip leading slash components */
      for (p = av.av_val + av.av_len - 1; p >= av.av_val; p--)
        if (*p == '/')
        {
          p++;
          av.av_len -= p - av.av_val;
          av.av_val = p;
          break;
        }
      /* skip leading dot */
      if (av.av_val[0] == '.')
      {
        av.av_val++;
        av.av_len--;
      }
      file = malloc(av.av_len + 5);

      memcpy(file, av.av_val, av.av_len);
      file[av.av_len] = '\0';
      for (p = file; *p; p++)
        if (*p == ':')
          *p = '_';

      /* Add extension if none present */
      if (file[av.av_len - 4] != '.')
      {
        av.av_len += 4;
      }
      /* Always use flv extension, regardless of original */
      if (strcmp(file + av.av_len - 4, ".flv"))
      {
        strcpy(file + av.av_len - 4, ".flv");
      }
      argv[argc].av_val = ptr + 1;
      argv[argc++].av_len = 2;
      argv[argc].av_val = file;
      argv[argc].av_len = av.av_len;
      ptr += sprintf(ptr, " -o %s", file);
      now = RTMP_GetTime();
      if (now - server->filetime < RTMPEPOLLSRV_DUPTIME && AVMATCH(&argv[argc], &server->filename))
      {
        printf("Duplicate request, skipping.\n");
        free(file);
      }
      else
      {
        printf("\n%s\n\n", cmd);
        fflush(stdout);
        server->filetime = now;
        free(server->filename.av_val);
        server->filename = argv[argc++];
        spawn_dumper(argc, argv, cmd);
      }

      free(cmd);
    }
    pc.m_body = server->connect;
    server->connect = NULL;
    RTMPPacket_Free(&pc);
    ret = 1;
    RTMP_SendCtrl(pRtmp, 0, 1, 0);
    SendPlayStart(pRtmp);
    RTMP_SendCtrl(pRtmp, 1, 1, 0);
    SendPlayStop(pRtmp);
  }
  AMF_Reset(&obj);
  return ret;
}



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

void RTMPPacket_Init(RTMPPacket *p)
{
  p->m_headerType = 0;
  p->m_packetType = 0;
  p->m_nChannel = 0;
  p->m_nTimeStamp = 0;
  p->m_nInfoField2 = 0;
  p->m_hasAbsTimestamp = FALSE;
  p->m_nBodySize = 0;
  p->m_nBytesRead = 0;
  p->m_chunk  = NULL;
  p->m_body = NULL;
}

int RtmpSessionHandshake(RTMP_SESSION *pSession)
{
	int iRet = 0;
	RTMPPacket *packet = (RTMPPacket *)malloc(sizeof(RTMPPacket));
	if(NULL == packet)
	{
		
		return ERROR_FAILED;
	}
	RTMPPacket_Init(packet);
	pSession->pPkt = packet;
	
	RTMP *rtmp = RTMP_Alloc(); 
	if(NULL == rtmp )
	{
		return ERROR_FAILED;
	}

	RTMP_Init(rtmp);
	rtmp->m_sb.sb_socket =  pSession->socket;
	pSession->prtmp = rtmp;

	pSession->state = RTMPSERVER_STATE_INIT;
	
	/* 进行握手处理 */
	if(RTMP_Serve(rtmp))
	{
		RTMPPacket_Free(pSession->pPkt);
		RTMPPacket_Init(pSession->pPkt);
		pSession->handshake = 1;
		pSession->arglen = 0;
		SetNonBlocking(pSession->socket);
	}
	else
	{
		iRet = -1;
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

static 
void  RtmpDispatchPkt(RTMP_SESSION *pSession, RTMPPacket *pPkt)
{
	RTMP *pRtmp  =  pSession->prtmp;
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
		case RTMP_PACKET_TYPE_FLEX_STREAM_SEND:
		{
    		break;
    	}

 		case RTMP_PACKET_TYPE_FLEX_SHARED_OBJECT:
 		{
    		break;
		}
  		case RTMP_PACKET_TYPE_FLEX_MESSAGE:
	  	{
		    RTMP_Log(RTMP_LOGDEBUG, "%s, flex message, size %u bytes, not fully supported",
		             __FUNCTION__, pPkt->m_nBodySize);
		    
		    if (SessionInvoke(pSession, pPkt, 1))
		      RTMP_Close(pSession->prtmp);
		    break;
	  	}
  		case RTMP_PACKET_TYPE_INFO:
  		{
    		break;
		}
  		case RTMP_PACKET_TYPE_SHARED_OBJECT:
  		{
    		break;
		}
  		case RTMP_PACKET_TYPE_INVOKE:
  		{
		    RTMP_Log(RTMP_LOGDEBUG, "%s, received: invoke %u bytes", __FUNCTION__,
		             pPkt->m_nBodySize);
		   
		    if (SessionInvoke(pSession, pPkt, 0))
		      RTMP_Close(pRtmp);
		    break;
		}
  		case RTMP_PACKET_TYPE_FLASH_VIDEO:
  		{
   			break;
   		}
	  	default:
	  	{
	    	RTMP_Log(RTMP_LOGDEBUG, "%s, unknown packet type received: 0x%02x", __FUNCTION__,
	            pPkt->m_packetType);
			#ifdef _DEBUG
			RTMP_LogHex(RTMP_LOGDEBUG, pPkt->m_body, pPkt->m_nBodySize);
			#endif
	  	}
	}

    RTMPPacket_Free(pPkt);
    RTMPPacket_Init(pPkt);
}


static 
int RtmpPktHandle(RTMP_SESSION *pSession)
{
	RTMP *pRtmp  =  pSession->prtmp;
	RTMPPacket *pPkt = pSession->pPkt;
	int readok = FALSE;

	if(!RTMP_IsConnected(pRtmp))
	{
		return  -1;
	}
	
	/* 收包逻辑处理 */
	while(readok = RTMP_ReadPacket(pRtmp, pPkt))
	{
		if(pPkt->m_nBodySize != pPkt->m_nBytesRead)
		{
			continue;
		}
		
		RtmpDispatchPkt(pSession, pPkt);		
	}
	  
	return 0;
}

void  RtmpSessionHandleFin(RTMP_SESSION *pSession)
{
	EPOLL_CTX *pCtx;
	RtmpSessionFini(pSession);
	pCtx = pSession - offsetof( EPOLL_CTX, pContext);
	RtmpEPOLLCTXFini(pCtx);

	return ;
}
int RtmpSessionHandle(int iFd, int iEvent, void *pContext)
{
	int iRet;
	RTMP_SESSION *pSession = (RTMP_SESSION *)pContext;
	
	if(iEvent&EPOLLIN )
	{
		if(0 == pSession->handshake)
		{
			iRet = RtmpSessionHandshake(pSession);		
  			if(0 != iRet)
  			{
				RtmpSessionHandleFin(pSession);	
  			}
		}
		else
		{	
			iRet = 	RtmpPktHandle(pSession);
		}
	}
	if(iEvent & (EPOLLERR |EPOLLHUP) )
	{
		RtmpSessionHandleFin(pSession);
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
		iNewFd = accept(iFd, &tmpAddr, (socklen_t *)&iSocketSize); 
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







