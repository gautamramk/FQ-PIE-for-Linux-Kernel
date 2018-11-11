/*
 * Fair Queue Pie
 *
 *  Copyright (C) 2012,2015 Eric Dumazet <edumazet@google.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "utils.h"
#include "tc_util.h"

static void explain(void)
{
	fprintf(stderr, "Usage: ... fq_pie [ limit PACKETS ] [ flows NUMBER ]\n");
    fprintf(stderr, "                  [alpha NUMBER] [beta NUMBER]        ");
	fprintf(stderr, "                    [ target TIME us] [tupdate TIME us]\n");
	fprintf(stderr, "                    [bytemode] [ quantum BYTES ] [ [no]ecn ]\n");
}

#define ALPHA_MAX 32
#define BETA_MAX 32

static int fq_pie_parse_opt(struct qdisc_util *qu, int argc, char **argv,
			      struct nlmsghdr *n, const char *dev)
{
	unsigned int limit = 0;
	unsigned int flows = 0;
	unsigned int target = 0;
	unsigned int quantum = 0;
	unsigned int alpha = 0;
    unsigned int beta = 0;
    unsigned int tupdate = 0;
    int bytemode = -1;
	int ecn = -1;
	struct rtattr *tail;

	while (argc > 0) {
        if (strcmp(*argv, "alpha") == 0) {
			NEXT_ARG();
			if (get_unsigned(&alpha, *argv, 0) ||
			    (alpha > ALPHA_MAX)) {
				fprintf(stderr, "Illegal \"alpha\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "beta") == 0) {
			NEXT_ARG();
			if (get_unsigned(&beta, *argv, 0) ||
			    (beta > BETA_MAX)) {
				fprintf(stderr, "Illegal \"beta\"\n");
				return -1;
			}
		}else if (strcmp(*argv, "limit") == 0) {
			NEXT_ARG();
			if (get_unsigned(&limit, *argv, 0)) {
				fprintf(stderr, "Illegal \"limit\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "flows") == 0) {
			NEXT_ARG();
			if (get_unsigned(&flows, *argv, 0)) {
				fprintf(stderr, "Illegal \"flows\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "quantum") == 0) {
			NEXT_ARG();
			if (get_unsigned(&quantum, *argv, 0)) {
				fprintf(stderr, "Illegal \"quantum\"\n");
				return -1;
			}
		}else if (strcmp(*argv, "tupdate") == 0) {
			NEXT_ARG();
			if (get_time(&tupdate, *argv)) {
				fprintf(stderr, "Illegal \"tupdate\"\n");
				return -1;
			}
		}  else if (strcmp(*argv, "bytemode") == 0) {
			bytemode = 1;
		}  else if (strcmp(*argv, "nobytemode") == 0) {
			bytemode = 0;
		}  else if (strcmp(*argv, "target") == 0) {
			NEXT_ARG();
			if (get_time(&target, *argv)) {
				fprintf(stderr, "Illegal \"target\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "ecn") == 0) {
			ecn = 1;
		} else if (strcmp(*argv, "noecn") == 0) {
			ecn = 0;
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--; argv++;
	}

	tail = addattr_nest(n, 1024, TCA_OPTIONS);
	if (limit)
		addattr_l(n, 1024, TCA_FQ_PIE_LIMIT, &limit, sizeof(limit));
	if (flows)
		addattr_l(n, 1024, TCA_FQ_PIE_FLOWS, &flows, sizeof(flows));
	if (quantum)
		addattr_l(n, 1024, TCA_FQ_PIE_QUANTUM, &quantum, sizeof(quantum));
	if (target)
		addattr_l(n, 1024, TCA_FQ_PIE_TARGET, &target, sizeof(target));
	if (ecn != -1)
		addattr_l(n, 1024, TCA_FQ_PIE_ECN, &ecn, sizeof(ecn));
    if (alpha)
        addattr_l(n, 1024, TCA_FQ_PIE_ALPHA, &alpha, sizeof(alpha));
    if (beta)
        addattr_l(n, 1024, TCA_FQ_PIE_BETA, &beta, sizeof(beta));
    if (tupdate)
        addattr_l(n, 1024, TCA_FQ_PIE_TUPDATE, &tupdate, sizeof(tupdate));
    if (bytemode)
        addattr_l(n, 1024, TCA_FQ_PIE_BYTEMODE, &bytemode, sizeof(bytemode));
	addattr_nest_end(n, tail);
	return 0;
}

static int fq_pie_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_FQ_PIE_MAX + 1];
	unsigned int limit = 0;
	unsigned int flows = 0;
	unsigned int target = 0;
	unsigned int quantum = 0;
	unsigned int alpha = 0;
    unsigned int beta = 0;
    unsigned int tupdate = 0;
    int bytemode = -1;
	int ecn = -1;

	SPRINT_BUF(b1);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_FQ_PIE_MAX, opt);

	if (tb[TCA_FQ_PIE_LIMIT] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PIE_LIMIT]) >= sizeof(__u32)) {
		limit = rta_getattr_u32(tb[TCA_FQ_CODEL_LIMIT]);
		print_uint(PRINT_ANY, "limit", "limit %up ", limit);
	}
	if (tb[TCA_FQ_PIE_FLOWS] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PIE_FLOWS]) >= sizeof(__u32)) {
		flows = rta_getattr_u32(tb[TCA_FQ_PIE_FLOWS]);
		print_uint(PRINT_ANY, "flows", "flows %u ", flows);
	}
    if (tb[TCA_FQ_PIE_ALPHA] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PIE_ALPHA]) >= sizeof(__u32)) {
		alpha = rta_getattr_u32(tb[TCA_FQ_PIE_ALPHA]);
		print_uint(PRINT_ANY, "alpha", "alpha %u ", alpha);
	}
    if (tb[TCA_FQ_PIE_BETA] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PIE_BETA]) >= sizeof(__u32)) {
		beta = rta_getattr_u32(tb[TCA_FQ_PIE_BETA]);
		print_uint(PRINT_ANY, "beta", "beta %u ", beta);
	}
	if (tb[TCA_FQ_PIE_QUANTUM] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PIE_QUANTUM]) >= sizeof(__u32)) {
		quantum = rta_getattr_u32(tb[TCA_FQ_PIE_QUANTUM]);
		print_uint(PRINT_ANY, "quantum", "quantum %u ", quantum);
	}
	if (tb[TCA_FQ_PIE_TARGET] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PIE_TARGET]) >= sizeof(__u32)) {
		target = rta_getattr_u32(tb[TCA_FQ_PIE_TARGET]);
		print_uint(PRINT_JSON, "target", NULL, target);
		print_string(PRINT_FP, NULL, "target %s ",
			     sprint_time(target, b1));
	}
	if (tb[TCA_FQ_PIE_ECN] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PIE_ECN]) >= sizeof(__u32)) {
		ecn = rta_getattr_u32(tb[TCA_FQ_PIE_ECN]);
		if (ecn)
			print_bool(PRINT_ANY, "ecn", "ecn ", true);
	}
    if (tb[TCA_FQ_PIE_TUPDATE] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PIE_TUPDATE]) >= sizeof(__u32)) {
		tupdate = rta_getattr_u32(tb[TCA_FQ_PIE_TUPDATE]);
        print_uint(PRINT_JSON, "tupdate", NULL, tupdate);
		print_string(PRINT_FP, NULL, "tupdate %s ",
			     sprint_time(target, b1));
	}
    if (tb[TCA_FQ_PIE_BYTEMODE] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PIE_BYTEMODE]) >= sizeof(__u32)) {
		bytemode = rta_getattr_u32(tb[TCA_FQ_PIE_BYTEMODE]);
		if (bytemode)
			print_bool(PRINT_ANY, "bytemode", "bytemode ", true);
	}

	return 0;
}

static int fq_pie_print_xstats(struct qdisc_util *qu, FILE *f,
				 struct rtattr *xstats)
{
	struct tc_fq_pie_xstats _st = {}, *st;

	SPRINT_BUF(b1);

	if (xstats == NULL)
		return 0;

	st = RTA_DATA(xstats);
	if (RTA_PAYLOAD(xstats) < sizeof(*st)) {
		memcpy(&_st, st, RTA_PAYLOAD(xstats));
		st = &_st;
	}
	 
    fprintf(f, "pkts_in %u overlimit %u dropped %u ecn_mark %u new_flow_count %u new_flows_len %u old_flows_len %u\n",
		st->packets_in, st->overlimit, st->dropped,
		st->ecn_mark, st->new_flow_count, st->new_flows_len, st->old_flows_len);
	return 0;

}

struct qdisc_util fq_pie_qdisc_util = {
	.id		= "fq_pie",
	.parse_qopt	= fq_pie_parse_opt,
	.print_qopt	= fq_pie_print_opt,
	.print_xstats	= fq_pie_print_xstats,
};
