#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>

#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/socket.h>

/* SHOULD THIS INCLUDE BE ON A SEPARATE LINE?????*/
#include <netinet/in.h>
#include <netinet/ip_var.h>

#include "metrics.h"
#include "log.h"

struct ip_modpriv {
	struct ipstat stats;
	struct metric *pktSenRec, *pktCkSum, *pktFrgmt, *pktErr;
};

struct metric_ops ip_metric_ops = {
	.mo_collect = NULL,
	.mo_free = NULL
};

static void
ip_register(struct registry *r, void **modpriv)
{
	struct ip_modpriv *priv;

	priv = calloc(1, sizeof(struct ip_modpriv));
	*modpriv = priv;

	priv->pktSenRec = metric_new(r, "ip_packets_sent_received",
	    "Total ip packets sent/received/forwarded",
	    METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &ip_metric_ops,
	    metric_label_new("type", METRIC_VAL_STRING),
	    NULL);
	
	priv->pktCkSum = metric_new(r, "ip_packets_checksummed",
	    "Ip packets which have been checksummed",
	    METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &ip_metric_ops,
	    metric_label_new("pkt type", METRIC_VAL_STRING),
	    NULL);
	
	priv->pktFrgmt = metric_new(r, "ip_fragments",
	    "Ip packet fragments",
	    METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &ip_metric_ops,
	    metric_label_new("reason", METRIC_VAL_STRING),
	    NULL);

	priv->pktErr = metric_new(r, "ip_packet_errors",
	    "Any ip packet errors",
	    METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &ip_metric_ops, 
	    metric_label_new("reason", METRIC_VAL_STRING),
	    NULL);


}

static int
ip_collect(void *modpriv)
{
	struct ip_modpriv *priv = modpriv;
	int mib[] = { CTL_NET, PF_INET, IPPROTO_IP, IPCTL_STATS };
	size_t size = sizeof(priv->stats);
	
	if ((sysctl(mib, sizeof(mib)/sizeof(mib[0]), 
	    &(priv->stats), &size, NULL, 0)) == -1) {
		tslog("failed to get ip stats: %s", strerror(errno));
		return (0);
	}

	/* Packet send/receive labels */
	metric_update(priv->pktSenRec, "total rec", priv->stats.ips_total);
	metric_update(priv->pktSenRec, "for host", priv->stats.ips_delivered);
	metric_update(priv->pktSenRec, "sent from host", 
	    priv->stats.ips_localout);
	metric_update(priv->pktSenRec, "redirects", 
	    priv->stats.ips_redirectsent);
	metric_update(priv->pktSenRec, "forwarded", priv->stats.ips_forward);
	
	/* Packets checksummed */
	metric_update(priv->pktCkSum, "input dgram", priv->stats.ips_inswcsum);
	metric_update(priv->pktCkSum, "output dgram",
	    priv->stats.ips_outswcsum);

	/* Packet fragments */
	metric_update(priv->pktFrgmt, "created", priv->stats.ips_ofragments);
	metric_update(priv->pktFrgmt, "rec", priv->stats.ips_fragments);
	metric_update(priv->pktFrgmt, "dropped", priv->stats.ips_fragdropped);
	metric_update(priv->pktFrgmt, "malformed", priv->stats.ips_badfrags);
	metric_update(priv->pktFrgmt, "timeout", priv->stats.ips_fragtimeout);
	metric_update(priv->pktFrgmt, "floods", priv->stats.ips_rcvmemdrop);
	metric_update(priv->pktFrgmt, "output dgram", 
	    priv->stats.ips_fragmented);
	metric_update(priv->pktFrgmt, "dgrams can't be fragmented", 
	    priv->stats.ips_cantfrag); 
	metric_update(priv->pktFrgmt, "reassembled (ok)", 
	    priv->stats.ips_reassembled);
	
	/* Packet errors */

	metric_update(priv->pktErr, "bad checksum", priv->stats.ips_badsum);
	metric_update(priv->pktErr, "smaller than min", 
	    priv->stats.ips_toosmall);
	metric_update(priv->pktErr, "data size < data len", 
	    priv->stats.ips_tooshort);
	metric_update(priv->pktErr, "header len < data size", 
	    priv->stats.ips_tooshort);
	metric_update(priv->pktErr, "data len < header len", 
	    priv->stats.ips_badlen);
	metric_update(priv->pktErr, "bad options", priv->stats.ips_badoptions);
	metric_update(priv->pktErr, "incorrect version num", 
	    priv->stats.ips_badvers);
	metric_update(priv->pktErr, "wrong interface", priv->stats.ips_wrongif);
	metric_update(priv->pktErr, "unknown protocol", 
	    priv->stats.ips_noproto);
	metric_update(priv->pktErr, "not forwardable", 
	    priv->stats.ips_cantforward);
	metric_update(priv->pktErr, "no bufs", priv->stats.ips_odropped);
	metric_update(priv->pktErr, "no route", priv->stats.ips_noroute);
	metric_update(priv->pktErr, "multicast no join", 
	    priv->stats.ips_notmember);
	metric_update(priv->pktErr, "bad addr", priv->stats.ips_badaddr);
	metric_update(priv->pktErr, "ip len > max ip packet size", 
	    priv->stats.ips_toolong);
	metric_update(priv->pktErr, "fabricated header", 
	    priv->stats.ips_rawout);
	metric_update(priv->pktErr, "no gif", priv->stats.ips_nogif);

	return (0);
}

static void
ip_free(void *modpriv)
{
	struct ip_modpriv *priv = modpriv;
	free(priv);
}

struct metrics_module_ops collect_ip_ops = {
	.mm_register = ip_register,
	.mm_collect = ip_collect,
	.mm_free = ip_free
};