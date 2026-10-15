# Worker veth run, 2026-10-14

This was a short comparison on the existing EKS worker. A C sender in a network namespace sent 64-byte Ethernet IPv4/UDP frames through a disposable veth pair. The real Shield program ran in generic mode for its two cases. No traffic reached either ENA interface, and no AWS resources were added.

The worker was a `c7i.large` with two vCPUs, Amazon Linux 2023, and kernel `6.18.51-120.163.amzn2023.x86_64`. The generator and receive path shared that worker. Each case had one 20,000-packet warm-up followed by five runs of 100,000 packets. The CSV keeps each measured run.

| Case | Hook | Median ingress completion rate | Min–max | Evidence |
| --- | --- | ---: | ---: | --- |
| PASS, no filter | none | 415,445 pps | 392,956–416,866 | veth receive counter |
| Shield drop | generic XDP | 1,163,581 pps | 1,154,175–1,173,775 | 500,000 XDP drops |
| nftables drop | input hook | 489,237 pps | 485,367–494,062 | 500,000 nftables drops |
| Shield with telemetry | generic XDP | 376,279 pps | 371,342–378,238 | 7,891 events; 0 lost |

Rates are packet counts divided by the time from starting the sender to observing the expected packet count on the receiving veth. This includes local process startup and the host's virtual network path. It is a same-worker software-path comparison, not ENA throughput. The generator and target share CPU, background EKS work was not isolated, and `perf`/`mpstat` were unavailable, so CPU and cycle counts are omitted. Shield's pass counter included one extra frame in XDP DROP repetition 4 and telemetry repetition 3, beyond the 100,000 generated UDP packets in each run. Each run's veth receive counter matched the expected UDP count; the extra frames were not attributed.

The traffic runs used `udp_burst.c` and `veth_trial.py`. The temporary benchmark Pod closed its link at shutdown; afterward `bpftool net show` listed only the pre-existing `enp39s0` generic attachment. The benchmark veth, namespace, nftables table, and temporary files were removed. The long-run, direct-VPC protocol remains a separate experiment and is not represented by these figures.
