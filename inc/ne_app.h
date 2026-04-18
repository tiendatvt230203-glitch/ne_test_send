#ifndef NE_APP_H
#define NE_APP_H

struct ne_app;

struct ne_app *ne_app_create(void);
void ne_app_destroy(struct ne_app *a);

int ne_app_setup(struct ne_app *a, const char *ingress_ifname, const char *bpf_path);

void ne_app_run_until_signal(struct ne_app *a);

#endif
