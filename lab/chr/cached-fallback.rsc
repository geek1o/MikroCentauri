# DISPOSABLE CHR 7.24.5 ONLY. One static lab mapping, not a dynamic FakeIP allocator.
# Replaces sources of the EXISTING watchdog; never installs a competing monitor.
# Precondition: selected.test is pinned to FakeIP 198.18.0.2 and real 10.77.0.20.
# No global conntrack flush. Test NEW connections to a SAVED FakeIP separately.
:local d [/system/script/find where name="mc-lab-down"]
:local p [/system/script/find where name="mc-lab-up"]
:local b [/system/scheduler/find where name="mc-lab-boot-direct"]
:local w [/tool/netwatch/find where comment="mikrocentauri:lab:netwatch:readiness"]
:if (([:len $d] != 1) || ([:len $p] != 1) || ([:len $b] != 1) || ([:len $w] != 1)) do={ :error "MC_LAB_FALLBACK: expected unique existing watchdog" }
:if (([:tostr [/tool/netwatch/get $w host]] != "172.30.0.2") || ([:tostr [/tool/netwatch/get $w type]] != "http-get") || ([/tool/netwatch/get $w port] != 9099)) do={ :error "MC_LAB_FALLBACK: unexpected watchdog shape" }
:if ([:len [/ip/firewall/nat/find where comment="mikrocentauri:lab:nat:cached-selected"]] != 0) do={ :error "MC_LAB_FALLBACK: mapping already exists" }

# Installation is fail-safe but not atomic: a failed import needs operator repair.
/tool/netwatch/disable $w
/ip/firewall/nat/disable [find where comment="mikrocentauri:lab:nat:dns-tcp"]
/ip/firewall/nat/disable [find where comment="mikrocentauri:lab:nat:dns-udp"]
/ip/route/disable [find where comment="mikrocentauri:lab:route:fakeip"]
/ip/firewall/nat/add chain=dstnat action=dst-nat in-interface=bridge-lan src-address=192.168.88.0/24 dst-address=198.18.0.2 to-addresses=10.77.0.20 disabled=no comment="mikrocentauri:lab:nat:cached-selected"

/system/script/set $d policy=read,write,test dont-require-permissions=no source={
    # Stop issuance before changing the old synthetic destination's packet path.
    /ip/firewall/nat/disable [find where comment="mikrocentauri:lab:nat:dns-tcp"]
    /ip/firewall/nat/disable [find where comment="mikrocentauri:lab:nat:dns-udp"]
    :local f [/ip/firewall/nat/find where comment="mikrocentauri:lab:nat:cached-selected"]
    :if ([:len $f] != 1) do={
        /ip/route/disable [find where comment="mikrocentauri:lab:route:fakeip"]
        :error "MC_LAB_FALLBACK_INVALID: missing or duplicate mapping"
    }
    :if (([:tostr [/ip/firewall/nat/get $f chain]] != "dstnat") || ([:tostr [/ip/firewall/nat/get $f action]] != "dst-nat") || ([:tostr [/ip/firewall/nat/get $f in-interface]] != "bridge-lan") || ([:tostr [/ip/firewall/nat/get $f src-address]] != "192.168.88.0/24") || ([:tostr [/ip/firewall/nat/get $f dst-address]] != "198.18.0.2") || ([:tostr [/ip/firewall/nat/get $f to-addresses]] != "10.77.0.20") || ([:tostr [/ip/firewall/nat/get $f protocol]] != "") || ([:tostr [/ip/firewall/nat/get $f dst-port]] != "") || ([:tostr [/ip/firewall/nat/get $f to-ports]] != "")) do={
        /ip/firewall/nat/disable $f
        /ip/route/disable [find where comment="mikrocentauri:lab:route:fakeip"]
        :error "MC_LAB_FALLBACK_INVALID: unexpected static mapping shape"
    }
    # DNAT is evaluated before routing: mapped NEW flows go straight to real WAN.
    /ip/firewall/nat/enable $f
    /ip/route/disable [find where comment="mikrocentauri:lab:route:fakeip"]
    :log warning "MC_LAB_CACHED_DIRECT: DNS interception off; static cached-IP fallback on"
}

/system/script/set $p policy=read,write,test dont-require-permissions=no source={
    :local r [/ip/route/find where comment="mikrocentauri:lab:route:fakeip"]
    :local t [/ip/firewall/nat/find where comment="mikrocentauri:lab:nat:dns-tcp"]
    :local u [/ip/firewall/nat/find where comment="mikrocentauri:lab:nat:dns-udp"]
    :local f [/ip/firewall/nat/find where comment="mikrocentauri:lab:nat:cached-selected"]
    :if (([:len $r] != 1) || ([:len $t] != 1) || ([:len $u] != 1) || ([:len $f] != 1)) do={
        /system/script/run mc-lab-down
        :error "MC_LAB_NOT_READY: missing or duplicate owned generation"
    }
    :if (([:tostr [/ip/route/get $r dst-address]] != "198.18.0.0/15") || ([:tostr [/ip/route/get $r gateway]] != "172.30.0.2") || ([:tostr [/ip/route/get $r routing-table]] != "main")) do={
        /system/script/run mc-lab-down
        :error "MC_LAB_NOT_READY: unexpected route generation"
    }
    :foreach n in=($t,$u) do={
        :if (([:tostr [/ip/firewall/nat/get $n chain]] != "dstnat") || ([:tostr [/ip/firewall/nat/get $n action]] != "dst-nat") || ([:tostr [/ip/firewall/nat/get $n in-interface]] != "bridge-lan") || ([:tostr [/ip/firewall/nat/get $n dst-address]] != "192.168.88.1") || ([:tostr [/ip/firewall/nat/get $n dst-port]] != "53") || ([:tostr [/ip/firewall/nat/get $n to-addresses]] != "172.30.0.2") || ([:tostr [/ip/firewall/nat/get $n to-ports]] != "5353")) do={
            /system/script/run mc-lab-down
            :error "MC_LAB_NOT_READY: unexpected DNS generation"
        }
    }
    :if (([:tostr [/ip/firewall/nat/get $t protocol]] != "tcp") || ([:tostr [/ip/firewall/nat/get $u protocol]] != "udp")) do={
        /system/script/run mc-lab-down
        :error "MC_LAB_NOT_READY: unexpected DNS protocols"
    }
    :if (([:tostr [/ip/firewall/nat/get $f chain]] != "dstnat") || ([:tostr [/ip/firewall/nat/get $f action]] != "dst-nat") || ([:tostr [/ip/firewall/nat/get $f in-interface]] != "bridge-lan") || ([:tostr [/ip/firewall/nat/get $f src-address]] != "192.168.88.0/24") || ([:tostr [/ip/firewall/nat/get $f dst-address]] != "198.18.0.2") || ([:tostr [/ip/firewall/nat/get $f to-addresses]] != "10.77.0.20") || ([:tostr [/ip/firewall/nat/get $f protocol]] != "") || ([:tostr [/ip/firewall/nat/get $f dst-port]] != "") || ([:tostr [/ip/firewall/nat/get $f to-ports]] != "")) do={
        /system/script/run mc-lab-down
        :error "MC_LAB_NOT_READY: unexpected static mapping generation"
    }
    # Keep cached destinations reachable until the gateway route has been restored.
    /ip/route/enable $r
    /ip/firewall/nat/disable $f
    /ip/firewall/nat/enable $t
    /ip/firewall/nat/enable $u
    :log info "MC_LAB_SELECTED: validated static fallback generation and TUN steering enabled"
}

/system/scheduler/set $b policy=read,write,test on-event="/system/script/run mc-lab-down"
/system/script/run mc-lab-down
/tool/netwatch/set $w up-script="/system/script/run mc-lab-up" down-script="/system/script/run mc-lab-down" ignore-initial-up=no ignore-initial-down=no
/tool/netwatch/enable $w
