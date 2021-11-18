/*
 *
 * Copyright 2020 The University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#if !defined(_METRICS_H)
#define _METRICS_H

#include <stdint.h>
#include <stdio.h>

struct metric;
struct label;
struct registry;

/*
 * Callbacks implemented by a collection module (new modules need to have one
 * of these, added to the list in metrics.c)
 */
struct metrics_module_ops {
	/*
	 * If the module needs any private data (e.g. a struct for its internal
	 * state), it should allocate it in mm_register and set *modprivate to
	 * a pointer to it. This pointer will be provided as the second argument
	 * to mm_collect and mm_free.
	 */
	void (*mm_register)(struct registry *db, void **modprivate);
	int (*mm_collect)(void *modprivate);
	void (*mm_free)(void *modprivate);
};

/*
 * Set of per-metric callbacks, given to metric_new(). The "private" opaque
 * pointer is the "priv" argument to metric_new().
 */
struct metric_ops {
	int (*mo_collect)(struct metric *, void *private);
	void (*mo_free)(void *private);
};

enum metric_val_type {
				/* type needed in metric_update() etc args */
	METRIC_VAL_STRING,	/* const char * */
	METRIC_VAL_INT64,	/* int64_t */
	METRIC_VAL_UINT64,	/* uint64_t */
	METRIC_VAL_DOUBLE	/* double */
};

enum metric_type {
	METRIC_GAUGE,
	METRIC_COUNTER
};

/* Creates a new label which can be later passed to metric_new */
struct label *metric_label_new(const char *name, enum metric_val_type type);

/*
 * Creates a new metric.
 *
 *   r: the registry to create the metric in
 *   name: the name of the metric (e.g. requests_total)
 *   help: the help text for the metric
 *   type: the type of metric (as opposed to type of the value)
 *   vtype: the type of the value for this metric
 *   priv: an opaque pointer, passed back to mo_collect/mo_free() if "ops" is
 *         non-NULL
 *   ops: optional metric_ops callbacks to hook into collection/cleanup
 *   labels: after "ops", give struct label * pointers for each label this
 *           metric should have. end the list with NULL. the values for these
 *           labels must be provided later to metric_push/update etc in the same
 *           order.
 */
struct metric *metric_new(struct registry *r, const char *name,
	const char *help, enum metric_type type, enum metric_val_type vtype,
	void *priv, const struct metric_ops *ops,
	... /* struct label *, NULL */);

/* Removes all metric values, new and old. */
void metric_clear(struct metric *m);

/*
 * Removes all metric values which have not been updated in the current
 * collection cycle (i.e. since registry_collect() was called).
 *
 * Calling metric_update() first and then metric_clear_old_values() is often
 * better than using metric_clear(): metric_update() will re-use the old
 * memory allocations associated with matching sets of labels, avoiding having
 * to free all of them only to re-allocate the same ones.
 */
void metric_clear_old_values(struct metric *m);

/* Pushes a metric value, assuming no other value with the same labels exists */
int metric_push(struct metric *m, ... /* label values, metric value */);

/* Increments a metric value */
int metric_inc(struct metric *m, ... /* label values */);
/* Updates a metric value to a new value */
int metric_update(struct metric *m, ... /* label values, metric value */);

/* Builds a metric registry containing all the compiled-in collector modules. */
struct registry *registry_build(void);
/* Builds a completely empty metric registry. */
struct registry *registry_new_empty(void);

void registry_free(struct registry *);

/*
 * Carries out the collection cycle on a registry, giving each metric module a
 * chance to update any periodically collected metrics.
 */
int registry_collect(struct registry *r);

/* Prints a metric in Prometheus text format. */
void print_metric(FILE *f, const struct metric *m);
/* Iterates through a registry, calling print_metric() on each metric. */
void print_registry(FILE *f, const struct registry *r);

#endif /* _METRICS_H */
