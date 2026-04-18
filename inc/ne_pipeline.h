#ifndef NE_PIPELINE_H
#define NE_PIPELINE_H

int ne_pipeline_run(const char *ingress_if, const char *wan_if, const char *ingress_bpf,
		    const char *wan_bpf);

#endif
