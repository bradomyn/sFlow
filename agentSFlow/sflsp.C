/* Copyright (c) 2002-2006 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

/* $Header: /root/InMon_Agent-5.7/RCS/sflsp.C,v 1.13 2007/05/23 03:26:52 root Exp root $ */

/* $Description: This program links with the inmon_api code and with libpcap.a to create a rudimentary host-based sampling agent. */

extern "C" {

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <netdb.h>
#include <sys/utsname.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <assert.h>

#include "sflow_api.h"

#define YES 1
#define NO 0

typedef struct _SflSp {
  int verbose;
  char *device;
  u_int32_t ifIndex;
  int ifType;
  u_int64_t ifSpeed;
  int ifDirection;
  int promiscuous;
  u_int32_t samplingRate;
  u_int32_t counterSamplingInterval;

  SFLAddress collectorAddress;
  struct sockaddr_in6 collectorSocket;
  int collectorPort;

  SFLAddress agentAddress;
  struct sockaddr_in6 agentSocket;
  
  u_int32_t agentSubId;
  int snaplen;
  int timeout_ms;
  int batch;
  pcap_t *pcap;
  
  // counters for each direction
#define SFL_DIRECTION_IN 0
#define SFL_DIRECTION_OUT 1
  u_int32_t frames[2];
  u_int64_t bytes[2];
  u_int32_t multicasts[2];
  u_int32_t broadcasts[2];
  
  
  struct in_addr interfaceIP;
  struct in6_addr interfaceIP6;
  char interfaceMAC[6];
  char pad[2];
  int gotInterfaceMAC;
  
  SFLAgent *agent;
  SFLSampler *sampler;
  
  int testMode;
  
} SflSp;
  

/*_______________---------------------------__________________
 ________________       lookupAddress       __________________
 ----------------___________________________------------------
*/

int lookupAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family)
{
  struct addrinfo *info = NULL;
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM; // constrain this so we don't get lots of answers
  hints.ai_family = family; // PF_INET, PF_INET6 or 0
  int err = getaddrinfo(name, NULL, &hints, &info);
  if(err) {
    switch(err) {
    case EAI_NONAME: break;
    case EAI_NODATA: break;
    case EAI_AGAIN: break; // loop and try again?
    default: fprintf(stderr, "getaddrinfo() error: %s\n", gai_strerror(err)); break;
    }
    return NO;
  }
  
  if(info == NULL) return NO;
  
  if(info->ai_addr) {
    // answer is now in info - a linked list of answers with sockaddr values.
    // extract the address we want from the first one.
    switch(info->ai_family) {
    case PF_INET:
      {
	struct sockaddr_in *ipsoc = (struct sockaddr_in *)info->ai_addr;
	addr->type = SFLADDRESSTYPE_IP_V4;
	addr->address.ip_v4 = ipsoc->sin_addr;
	memcpy(sa, info->ai_addr, info->ai_addrlen);
      }
      break;
    case PF_INET6:
      {
	struct sockaddr_in6 *ip6soc = (struct sockaddr_in6 *)info->ai_addr;
	addr->type = SFLADDRESSTYPE_IP_V6;
	addr->address.ip_v6 = ip6soc->sin6_addr;
	  memcpy(sa, info->ai_addr, info->ai_addrlen);
      }
      break;
    default:
      fprintf(stderr, "get addrinfo: unexpected address family: %d\n", info->ai_family);
      return NO;
      break;
    }
  }
  // free the dynamically allocated data before returning
  freeaddrinfo(info);
  return YES;
}
  
/*_______________---------------------------__________________
  _______________      getDeviceInfo        __________________
  ---------------___________________________------------------
*/

#define GETDEV_FOUND_DEV 1
#define GETDEV_FOUND_IP 2
#define GETDEV_FOUND_IP6 4
#define GETDEV_FOUND_MAC 8
#define GETDEV_FOUND_IFINDEX 16
int getDeviceInfo(char *device, struct in_addr *ipAddr, struct in6_addr *ip6Addr, char *macAddr, u_int32_t *ifIndex)
{
  struct ifconf ifc; // holds IOCTL return value for SIOCGIFCONF
  int return_val, fd = -1, numreqs = 30,  n;
  struct ifreq *ifr; // points to one interface returned from ioctl
  int answer = 0;
  
  fd = socket (PF_INET, SOCK_DGRAM, 0);
  
  if (fd < 0) {
    fprintf (stderr, "error opening socket: %d (%s)\n", errno, strerror(errno));
    exit(1);
  }
  
  memset (&ifc, 0, sizeof(ifc));
  
  ifc.ifc_buf = NULL;
  ifc.ifc_len =  sizeof(struct ifreq) * numreqs;
  ifc.ifc_buf = (char *)malloc(ifc.ifc_len);
  
  // This code attempts to handle an arbitrary number of interfaces,
  // it keeps trying the ioctl until it comes back OK and the size
  // returned is less than the size we sent it.
  
  for (;;) {
    ifc.ifc_len = sizeof(struct ifreq) * numreqs;
    ifc.ifc_buf = (char *)realloc(ifc.ifc_buf, ifc.ifc_len);
    
    if ((return_val = ioctl(fd, SIOCGIFCONF, &ifc)) < 0) {
      perror("SIOCGIFCONF");
      break;
    }
    if ((u_int)ifc.ifc_len == sizeof(struct ifreq) * (u_int)numreqs) {
      /* assume it overflowed and try again */
      numreqs += 10;
      continue;
    }
    break;
  }
  
  if (return_val < 0) {
    fprintf (stderr, "got ioctl error %d (%s)\n", errno, strerror(errno));
    exit(1);
  }
  
  /* loop through interfaces returned from SIOCGIFCONF */
  ifr=ifc.ifc_req;
  for (n=0; n < ifc.ifc_len; n+=sizeof(struct ifreq)) {
    if(strcmp(device, ifr->ifr_name) == 0) {
      answer |= GETDEV_FOUND_DEV;
      /* Get the IP address for this interface */
      if((return_val = ioctl(fd,SIOCGIFADDR, ifr)) != 0) perror("Get addr failed");
      else {
	if (ipAddr && ifr->ifr_addr.sa_family == AF_INET) {
	  struct sockaddr_in *s = (struct sockaddr_in *)&ifr->ifr_addr;
	  *ipAddr = s->sin_addr;
	  answer |= GETDEV_FOUND_IP;
	}
	else if (ip6Addr && ifr->ifr_addr.sa_family == AF_INET6) {
	  // not sure this ever happens - on a linux system IPv6 addresses
	  // are picked up from a file under /proc/net
	  struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ifr->ifr_addr;
	  *ip6Addr = s->sin6_addr;
	  answer |= GETDEV_FOUND_IP6;
	}
      }
      
      if(macAddr) {
	/* Get the MAC Address for this interface */
	if((return_val = ioctl(fd,SIOCGIFHWADDR, ifr)) != 0) perror("Get hwaddr failed");
	else {
	  memcpy(macAddr, &ifr->ifr_hwaddr.sa_data, 6);
	  answer |= GETDEV_FOUND_MAC;
	}
      }
      
      if(ifIndex) {
	/* Get the ifIndex for this interface */
	if((return_val = ioctl(fd,SIOCGIFINDEX, ifr)) != 0) perror("Get ifIndex failed");
	else {
	  *ifIndex = ifr->ifr_ifindex;
	  answer |= GETDEV_FOUND_IFINDEX;
	}
      }
      
      /* we have the one we want, so jump out */
      break;
    }
    
    /* check the next entry returned */
    ifr++;
  }
  
  /* we don't need this memory any more */
  free (ifc.ifc_buf);
  close (fd);
  
  return answer;
}

/*_________________---------------------------__________________
  _________________     setDefaults           __________________
  -----------------___________________________------------------
*/

  static void setDefaults(SflSp *sp)
  {
    sp->device = NULL;
    sp->ifIndex = 1;
    sp->ifType = 6; // ethernet_csmacd 
    sp->ifSpeed = 100000000L;  // assume 100 MBit
    sp->ifDirection = 1; // assume full duplex 
    sp->samplingRate = SFL_DEFAULT_SAMPLING_RATE;
    sp->counterSamplingInterval = 20;
    sp->promiscuous = 0;
    sp->timeout_ms = 100;
    sp->batch = 100;
    sp->snaplen = 128;
    lookupAddress("localhost", (sockaddr *)&sp->collectorSocket, &sp->collectorAddress, 0);
    sp->collectorPort = SFL_DEFAULT_COLLECTOR_PORT;

    // get my agent ip with a lookup on the hostname
    struct utsname uts;
    if(uname(&uts) == -1) {
      fprintf(stderr, "uname() failed");
      exit(-2);
    }
    lookupAddress(uts.nodename, (sockaddr *)&sp->agentSocket, &sp->agentAddress, 0);

    sp->agentSubId = 0;
  }

  /*_________________---------------------------__________________
    _________________     agent callbacks       __________________
    -----------------___________________________------------------
  */

  static void *agentCB_alloc(void *magic, SFLAgent *agent, size_t bytes)
  {
    return calloc(1, bytes);
  }

  static int agentCB_free(void *magic, SFLAgent *agent, void *obj)
  {
    free(obj);
    return 0;
  }

  static void agentCB_error(void *magic, SFLAgent *agent, char *msg)
  {
    fprintf(stderr, "sflow agent error: %s\n", msg);
  }

  void agentCB_getCounters(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
  {
    SflSp *sp = (SflSp *)magic;
    if(sp->verbose) fprintf(stderr, "agentCB_getCounters\n");

    // build a counters sample
    SFLCounters_sample_element genElem;
    memset(&genElem, 0, sizeof(genElem));
    genElem.tag = SFLCOUNTERS_GENERIC;
    // don't need to set the length here (set by the encoder)
    genElem.counterBlock.generic.ifIndex = sp->ifIndex;
    genElem.counterBlock.generic.ifType = sp->ifType;
    genElem.counterBlock.generic.ifSpeed = sp->ifSpeed;
    genElem.counterBlock.generic.ifDirection = sp->ifDirection;
    genElem.counterBlock.generic.ifStatus = 0x03; // adminStatus = up, operStatus = up
    genElem.counterBlock.generic.ifPromiscuousMode = sp->promiscuous;
    // these counters would normally be a snapshot the hardware interface counters - the
    // same ones that the SNMP agent uses to answer SNMP requests to the ifTable.  To ease
    // the portability of this program, however, I am just using some counters that were
    // added up in software:
    genElem.counterBlock.generic.ifInOctets = sp->bytes[SFL_DIRECTION_IN];
    genElem.counterBlock.generic.ifInUcastPkts = sp->frames[SFL_DIRECTION_IN];
    genElem.counterBlock.generic.ifInMulticastPkts = sp->multicasts[SFL_DIRECTION_IN];
    genElem.counterBlock.generic.ifInBroadcastPkts = sp->broadcasts[SFL_DIRECTION_IN];
    genElem.counterBlock.generic.ifOutOctets = sp->bytes[SFL_DIRECTION_OUT];
    genElem.counterBlock.generic.ifOutUcastPkts = sp->frames[SFL_DIRECTION_OUT];
    genElem.counterBlock.generic.ifOutMulticastPkts = sp->multicasts[SFL_DIRECTION_OUT];
    genElem.counterBlock.generic.ifOutBroadcastPkts = sp->broadcasts[SFL_DIRECTION_OUT];

    // add this counter block to the counter sample that we are building
    SFLADD_ELEMENT(cs, &genElem);

    if(sp->testMode) {
      SFLCounters_sample_element ethElem;
      memset(&ethElem, 0, sizeof(ethElem)); // especially import for nxt field to be NULL
      ethElem.tag = SFLCOUNTERS_ETHERNET;
      // pretend we're getting one collision per second
      ethElem.counterBlock.ethernet.dot3StatsSingleCollisionFrames = time(NULL);
      SFLADD_ELEMENT(cs, &ethElem);
    }

    // pass these counters down to be encoded and included with the next sFlow datagram
    sfl_poller_writeCountersSample(poller, cs);
  }

  /*_________________---------------------------__________________
    _________________         init_agent        __________________
    -----------------___________________________------------------
  */

  static void init_agent(SflSp *sp)
  {
    if(sp->verbose) printf("creating sfl agent\n");

    assert(sp->agentAddress.type);
    assert(sp->collectorAddress.type);

    time_t now = time(NULL);
    sp->agent = (SFLAgent *)calloc(1, sizeof(SFLAgent));
    sfl_agent_init(sp->agent, &sp->agentAddress, sp->agentSubId, now, now, sp, agentCB_alloc, agentCB_free, agentCB_error, NULL);

    // add a receiver
    SFLReceiver *receiver = sfl_agent_addReceiver(sp->agent);

    // define the data source
    SFLDataSource_instance dsi;
    SFL_DS_SET(dsi, 0, sp->ifIndex, 0);  // ds_class = 0, ds_index = <ifIndex>, ds_instance = 0

    // create a sampler for it
    sfl_agent_addSampler(sp->agent, &dsi);
    // and a poller too
    sfl_agent_addPoller(sp->agent, &dsi, sp, agentCB_getCounters);

    // now configure it just as if it were as series of SNMP SET operations through the MIB interface...

    // claim the receiver slot
    sfl_receiver_set_sFlowRcvrOwner(receiver, "my owner string $$$");

    // set the timeout to infinity
    sfl_receiver_set_sFlowRcvrTimeout(receiver, 0xFFFFFFFF);

    // new scheme - write the whole socket in (scope_id included) and after that we
    // can override the port selectively.
    if(sp->collectorAddress.type == SFLADDRESSTYPE_IP_V6) {
      receiver->receiver6 = sp->collectorSocket;
    }
    else {
      memcpy(&receiver->receiver4, &sp->collectorSocket, sizeof(receiver->receiver4));
    }
    sfl_receiver_set_sFlowRcvrAddress(receiver, &sp->collectorAddress);

    // collector port
    sfl_receiver_set_sFlowRcvrPort(receiver, sp->collectorPort);

    // set the sampling rate
    sfl_sampler_set_sFlowFsPacketSamplingRate(sfl_agent_getSampler(sp->agent, &dsi), sp->samplingRate);

    // set the counter interval
    sfl_poller_set_sFlowCpInterval(sfl_agent_getPoller(sp->agent, &dsi), sp->counterSamplingInterval);

    // point the sampler to the receiver
    sfl_sampler_set_sFlowFsReceiver(sfl_agent_getSampler(sp->agent, &dsi), 1);

    // point the poller to the receiver
    sfl_poller_set_sFlowCpReceiver(sfl_agent_getPoller(sp->agent, &dsi), 1);

    // cache the sampler pointer for performance reasons...
    sp->sampler = sfl_agent_getSampler(sp->agent, &dsi);
  }


  /*_________________---------------------------__________________
    _________________       readPacket          __________________
    -----------------___________________________------------------
  */

  static void readPacket(u_char *magic, const struct pcap_pkthdr *pkthdr, const u_char *buf)
  {
    SflSp *sp = (SflSp *)magic;
    if(sp->verbose > 1) printf("readPacket: %02x%02x%02x%02x%02x%02x -> %02x%02x%02x%02x%02x%02x (len = %d, captured = %d)\n",
			       buf[6],
			       buf[7],
			       buf[8],
			       buf[9],
			       buf[10],
			       buf[11],
			       buf[0],
			       buf[1],
			       buf[2],
			       buf[3],
			       buf[4],
			       buf[5],
			       pkthdr->len,
			       pkthdr->caplen);

    // test the src mac address to know the direction.  Anything with src = interfaceMAC
    // will be counted as output, and everything else can be counted as input.  (There may
    // be a way to get this info from the pcap library,  but I don't know the incantation.
    // (If you know how to do that, please let me know).
    int direction = memcmp(sp->interfaceMAC, buf + 6, 6) ? SFL_DIRECTION_IN : SFL_DIRECTION_OUT;

    // maintain some counters in software - just to ease portability
    sp->bytes[direction] += pkthdr->len;
    if(buf[0] & 0x01) {
      if(buf[0] == 0xff &&
	 buf[1] == 0xff &&
	 buf[2] == 0xff &&
	 buf[3] == 0xff &&
	 buf[4] == 0xff &&
	 buf[5] == 0xff) sp->broadcasts[direction]++;
      else sp->multicasts[direction]++;
    }
    else sp->frames[direction]++;

    // test to see if we want to sample this packet
    if(sfl_sampler_takeSample(sp->sampler)) {

      // Yes. Build a flow sample and send it off...
      SFL_FLOW_SAMPLE_TYPE fs;
      memset(&fs, 0, sizeof(fs));

      // Since we are an end host, we are not switching or routing
      // this packet.  On a switch or router this is just like a
      // packet going to or from the management agent.  That means
      // the local interface index should be filled in as the special
      // value 0x3FFFFFFF, which is defined in the sFlow spec as
      // an "internal" interface.
      fs.input = (direction == SFL_DIRECTION_IN) ? sp->ifIndex : 0x3FFFFFFF;
      fs.output = (direction == SFL_DIRECTION_IN) ? 0x3FFFFFFF : sp->ifIndex;

      SFLFlow_sample_element hdrElem;
      memset(&hdrElem, 0, sizeof(hdrElem));

      hdrElem.tag = SFLFLOW_HEADER;
      hdrElem.flowType.header.header_protocol = SFLHEADER_ETHERNET_ISO8023;
      u_int32_t FCS_bytes = 4;
      // the FCS trailing bytes should be counted in the frame_length
      // but they should also be recorded in the "stripped" field.
      // assume that libpcap is not giving us the FCS
      u_int32_t frame_len = pkthdr->len;
      hdrElem.flowType.header.frame_length = frame_len + FCS_bytes;
      hdrElem.flowType.header.stripped = FCS_bytes;
      u_int32_t header_len = pkthdr->caplen;
      if(header_len > frame_len) header_len = frame_len;
      if(header_len > (u_int32_t)sp->snaplen) header_len = sp->snaplen;
      hdrElem.flowType.header.header_length = header_len;
      hdrElem.flowType.header.header_bytes = (u_int8_t *)buf;
      SFLADD_ELEMENT(&fs, &hdrElem);

      if(sp->testMode) {
	// exercise some of the extended data fields with made-up data
	SFLFlow_sample_element gwElem;
	memset(&gwElem, 0, sizeof(gwElem));
	gwElem.tag = SFLFLOW_EX_GATEWAY;
	gwElem.flowType.gateway.nexthop.type = SFLADDRESSTYPE_IP_V4;
	gwElem.flowType.gateway.nexthop.address.ip_v4.s_addr = 0x0a0b0c0d;
	gwElem.flowType.gateway.as = 65001;
	gwElem.flowType.gateway.src_as = 123;
	gwElem.flowType.gateway.src_peer_as = 999;
	gwElem.flowType.gateway.dst_as_path_segments = 3;
	SFLExtended_as_path_segment seg[3];
	u_int32_t seq1[] = { 123, 456, 789 };
	u_int32_t set1[] = { 11111, 22222, 33333 };
	u_int32_t seq2[] = { 777, 888, 999 };
	u_int32_t comms[] = { 12, 13 };
	seg[0].type = SFLEXTENDED_AS_SEQUENCE;
	seg[0].length = 3;
	seg[0].as.seq = seq1;
	seg[1].type = SFLEXTENDED_AS_SET;
	seg[1].length = 3;
	seg[1].as.set = set1;
	seg[2].type = SFLEXTENDED_AS_SEQUENCE;
	seg[2].length = 3;
	seg[2].as.set = seq2;
	gwElem.flowType.gateway.dst_as_path = seg;
	gwElem.flowType.gateway.communities_length = 2;
	gwElem.flowType.gateway.communities = comms;
	gwElem.flowType.gateway.localpref = 432;
	SFLADD_ELEMENT(&fs, &gwElem);

	SFLFlow_sample_element userElem;
	memset(&userElem, 0, sizeof(userElem));
	userElem.tag = SFLFLOW_EX_USER;
	userElem.flowType.user.src_charset = 106; // 106 = UTF-8 (see RFC 2978)
	userElem.flowType.user.dst_charset = 106;
	userElem.flowType.user.src_user.str = "source user";
	userElem.flowType.user.dst_user.str = "destination user";
	userElem.flowType.user.src_user.len = strlen(userElem.flowType.user.src_user.str);
	userElem.flowType.user.dst_user.len = strlen(userElem.flowType.user.dst_user.str);
	SFLADD_ELEMENT(&fs, &userElem);

	SFLFlow_sample_element urlElem;
	memset(&urlElem, 0, sizeof(urlElem));
	urlElem.tag = SFLFLOW_EX_URL;
	urlElem.flowType.url.direction = SFLEXTENDED_URL_SRC;
	urlElem.flowType.url.url.str = "http://www.sflow.org";
	urlElem.flowType.url.url.len = strlen(urlElem.flowType.url.url.str);
	urlElem.flowType.url.host.str = "host1.sflow.org";
	urlElem.flowType.url.host.len = strlen(urlElem.flowType.url.host.str);
	SFLADD_ELEMENT(&fs, &urlElem);
      }

      // submit the sample to be encoded and sent out - that's all there is to it(!)
      sfl_sampler_writeFlowSample(sp->sampler, &fs);
    }
  }

  /*_________________---------------------------__________________
    _________________      instructions         __________________
    -----------------___________________________------------------
  */

  static void instructions(char *command)
  {
    fprintf(stderr,"Usage: %s [-d device] [-C collectorIP] [-c collectorPort] [-s samplingRate] [-v] [-i ifIndex] [-S ifSpeed] [-A agentIP] [-a agentSubId] [-P] [-T] \n", command);
    fprintf(stderr,"\n\
      -d device:  the interface to monitor, e.g 'eth0'\n\
 -C collectorIP:  the collector to send sFlow to\n\
-s samplingRate:  1-in-N packet sampling\n\
             -v:  verbose - log output (-vv for more detail)\n\
     -i ifIndex:  override ifIndex number\n\
     -S ifSpeed:  override ifSpeed (e.g. 1000000000)\n\
     -A agentIP:  override sFlow agent address\n\
  -a agentSubId:  set sFlow agent subId\n\
             -P:  kick interface into promiscuous mode\n\
             -T:  test mode - include some made-up structs\n");
    exit(-3);
  }

  /*_________________---------------------------__________________
    _________________   process_command_line    __________________
    -----------------___________________________------------------
  */

  static void process_command_line(SflSp *sp, int argc, char *argv[])
  {
    int in;
    while ((in = getopt(argc, argv, "d:i:A:a:C:c:s:PvTS:")) != -1) {
      switch(in) {
      case 'd': sp->device = strdup(optarg); break;
      case 'i': sp->ifIndex = atoi(optarg); break;
      case 'A': lookupAddress(optarg, (sockaddr *)&sp->agentSocket, &sp->agentAddress, 0); break;
      case 'a': sp->agentSubId = atoi(optarg); break;
      case 'C': lookupAddress(optarg, (sockaddr *)&sp->collectorSocket, &sp->collectorAddress, 0); break;
      case 'c': sp->collectorPort = atoi(optarg); break;
      case 's': sp->samplingRate = atoi(optarg); break;
      case 'P': sp->promiscuous = 1; break;
      case 'v': sp->verbose++; break;
      case 'T': sp->testMode++; break;
      case 'S': sp->ifSpeed = strtoll(optarg, NULL, 0); break;
      case '?':
      case 'h':
      default: instructions(*argv);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________         main              __________________
    -----------------___________________________------------------
  */

  int main(int argc, char *argv[])
  {
    SflSp sp;
    memset(&sp, 0, sizeof(sp));
    char pcap_errbuf[1000];

    // init
    setDefaults(&sp);

    // read the command line
    process_command_line(&sp, argc, argv);

    if(sp.device == NULL) {
      // no device specified - choose the default
      if((sp.device = pcap_lookupdev(pcap_errbuf)) == NULL) {
	fprintf(stderr, "error in pcap_lookupdev(): %s\n", pcap_errbuf);
      }
    }

    // get the addresses for the interface we are going to monitor
    int getDevFlags = getDeviceInfo(sp.device,
				    &sp.interfaceIP,
				    &sp.interfaceIP6,
				    sp.interfaceMAC,
				    &sp.ifIndex);

    // remember if we got a mac address, so we can use it to infer direction
    sp.gotInterfaceMAC = ((getDevFlags & GETDEV_FOUND_MAC) != 0);

    // if we weren't given an agent-address (or couldn't get one from our hostname) then set it
    // to be the same as the ip address of the interface we are monitoring:
    if(sp.agentAddress.type == 0 && sp.interfaceIP.s_addr) {
      sp.agentAddress.type = SFLADDRESSTYPE_IP_V4;
      sp.agentAddress.address.ip_v4 = sp.interfaceIP;
    }

    // create the agent and sampler objects
    init_agent(&sp);

    if(sp.testMode) {
      // exercise the sfl_agent_getSamplerByIfIndex() jump table
      SFLSampler *test = sfl_agent_getSamplerByIfIndex(sp.agent, sp.ifIndex);
      if(test == NULL || test != sp.sampler) {
	fprintf(stderr, "sfl_agent_getSamplerByIfIndex(agent, 1) failed! (returned %p)\n", test);
	exit(-1);
      }
    }

    // open the pcap socket
    if(sp.verbose) printf("calling pcap_open_live(dev=%s, snaplen=%d, promisc=%d, to_ms=%d, errbuf)\n",
			  sp.device,
			  sp.snaplen,
			  sp.promiscuous,
			  sp.timeout_ms);
    if((sp.pcap = pcap_open_live(sp.device, sp.snaplen, sp.promiscuous, sp.timeout_ms, pcap_errbuf)) == NULL) {
      fprintf(stderr, "error in pcap_open_live(): %s\n", pcap_errbuf);
    }

    // initialize the clock so we can detect second boundaries
    time_t clk = time(NULL);

    // now loop forever
    while(1) {

      // read some packets (or time out)
      if(sp.verbose > 1) printf("calling pcap_dispatch()\n");
      if((pcap_dispatch(sp.pcap, sp.batch, readPacket, (u_char *)&sp)) == -1) {
	fprintf(stderr, "error in pcap_dispatch(): %s\n", pcap_geterr(sp.pcap));
	break;
      }
      // check for second boundaries and generate ticks
      if(sp.verbose > 1) printf("check clock\n");
      time_t test_clk = time(NULL);
      while(clk < test_clk) {
	if(sp.verbose) printf("sending tick\n");
	sfl_agent_tick(sp.agent, clk++);
      }
    }

    pcap_close(sp.pcap);
    return -1;  // error if we get here - should have looped forever
  }


}
