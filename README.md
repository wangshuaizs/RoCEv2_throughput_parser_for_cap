# RoCEv2_throughput_parser_for_cap

This .py script supports to parse throughput of arbitrary RoCE v2 flows. ```sip_list``` includes source ips, and ```dip_list``` includes destination ips. And they are corelated with each other. For example, the setting

```
sip_list =["192.168.79.54", "192.168.79.54"]
dip_list =["192.168.79.55", "192.168.79.56"]
```

will parse 2 flows, one from ```192.168.79.54``` to ```192.168.79.55``` and another from ```192.168.79.54``` to ```192.168.79.56```.

Noting: ```*``` represents wildcard.
