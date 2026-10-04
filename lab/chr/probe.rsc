# DISPOSABLE CHR ONLY. Preconditions: container package installed using graceful reboot,
# device-mode container=yes physically confirmed, no preexisting mc-* objects.
# Serve .cache on HOST loopback:18081; QEMU guest reaches HOST as 10.0.2.2.
/interface/veth/add name=mc-probe address=172.30.0.2/24 gateway=172.30.0.1
/interface/bridge/add name=mc-bridge
/interface/bridge/port/add bridge=mc-bridge interface=mc-probe
/ip/address/add address=172.30.0.1/24 interface=mc-bridge
/tool/fetch url="http://10.0.2.2:18081/probe-image.tar" dst-path=probe-image.tar
/container/add file=probe-image.tar interface=mc-probe root-dir=mc-probe-root logging=yes user=0:0
# Wait for extraction; inspect /container/print detail and /log/print.
# Start by its discovered unique name (numeric console indices require a preceding print), then:
# /tool/fetch url="http://172.30.0.2:9099/" output=user
# Compare normal vs privileged ONLY on >=7.24 if normal TUN creation fails.
# /container/set <exact-probe-ID> privileged=yes
