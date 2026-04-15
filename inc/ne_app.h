#ifndef NE_APP_H
#define NE_APP_H

struct ne_app;

struct ne_app *ne_app_create(void);
void ne_app_destroy(struct ne_app *a);

/* Returns 0 on success. bpf_path may be NULL → NE_DEFAULT_BPF */
int ne_app_setup(struct ne_app *a, const char *ingress_ifname, const char *bpf_path);

/* Blocks until SIGINT/SIGTERM; prints stats */
void ne_app_run_until_signal(struct ne_app *a);

#endif
