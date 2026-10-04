# DISPOSABLE CHR 7.24.5 LAB ONLY. Import and native stop/recovery TESTED; zero-loss boot ordering unproved.
# Assumes disabled, uniquely commented route + TCP/UDP DNS NAT from instance lab.
# Dedicated root readiness listener: 172.30.0.2:9099. 200 means applied generation
# and engine/DNS/TUN ingress are ready; remote-proxy readiness remains a gate.
# Exact object allowlist; do not expand to all mikrocentauri:* objects.
# One-shot install: abort if any watchdog object already exists.
:if ([:len [/system/script/find where name="mc-lab-down"]] != 0) do={ :error "mc-lab-down already exists" }
:if ([:len [/system/script/find where name="mc-lab-up"]] != 0) do={ :error "mc-lab-up already exists" }
:if ([:len [/system/scheduler/find where name="mc-lab-boot-direct"]] != 0) do={ :error "mc-lab-boot-direct already exists" }
:if ([:len [/tool/netwatch/find where comment="mikrocentauri:lab:netwatch:readiness"]] != 0) do={ :error "lab watchdog already exists" }

/system/script/add name=mc-lab-down policy=read,write,test source={
    /ip/firewall/nat/disable [find where comment="mikrocentauri:lab:nat:dns-tcp"]
    /ip/firewall/nat/disable [find where comment="mikrocentauri:lab:nat:dns-udp"]
    /ip/route/disable [find where comment="mikrocentauri:lab:route:fakeip"]
    :log warning "MC_LAB_DIRECT: DNS interception and FakeIP steering disabled"
}

/system/script/add name=mc-lab-up policy=read,write,test source={
    :local r [/ip/route/find where comment="mikrocentauri:lab:route:fakeip"]
    :local t [/ip/firewall/nat/find where comment="mikrocentauri:lab:nat:dns-tcp"]
    :local u [/ip/firewall/nat/find where comment="mikrocentauri:lab:nat:dns-udp"]
    :if (([:len $r] != 1) || ([:len $t] != 1) || ([:len $u] != 1)) do={
        /system/script/run mc-lab-down
        :error "MC_LAB_NOT_READY: missing or duplicate generation objects"
    }
    :if (([/ip/route/get $r dst-address] != "198.18.0.0/15") || ([/ip/route/get $r gateway] != "172.30.0.2") || ([/ip/route/get $r routing-table] != "main")) do={
        /system/script/run mc-lab-down
        :error "MC_LAB_NOT_READY: unexpected route generation"
    }
    :foreach n in=($t,$u) do={
        :if (([/ip/firewall/nat/get $n chain] != "dstnat") || ([/ip/firewall/nat/get $n action] != "dst-nat") || ([/ip/firewall/nat/get $n in-interface] != "bridge-lan") || ([/ip/firewall/nat/get $n dst-address] != "192.168.88.1") || ([/ip/firewall/nat/get $n dst-port] != "53") || ([/ip/firewall/nat/get $n to-addresses] != "172.30.0.2") || ([/ip/firewall/nat/get $n to-ports] != "5353")) do={
            /system/script/run mc-lab-down
            :error "MC_LAB_NOT_READY: unexpected DNS generation"
        }
    }
    :if (([/ip/firewall/nat/get $t protocol] != "tcp") || ([/ip/firewall/nat/get $u protocol] != "udp")) do={
        /system/script/run mc-lab-down
        :error "MC_LAB_NOT_READY: unexpected DNS protocols"
    }
    /ip/route/enable $r
    /ip/firewall/nat/enable $t
    /ip/firewall/nat/enable $u
    :log info "MC_LAB_SELECTED: validated lab generation enabled"
}

# Guard deliberately needs no network. Startup sequence still requires boot capture.
/system/scheduler/add name=mc-lab-boot-direct start-time=startup interval=0s policy=read,write,test on-event="/system/script/run mc-lab-down"
/system/script/run mc-lab-down
/tool/netwatch/add comment="mikrocentauri:lab:netwatch:readiness" host=172.30.0.2 type=http-get port=9099 http-codes=200 interval=2s timeout=1s thr-http-time=1s start-delay=1s startup-delay=10s ignore-initial-up=no ignore-initial-down=no up-script="/system/script/run mc-lab-up" down-script="/system/script/run mc-lab-down"
