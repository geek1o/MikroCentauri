# DISPOSABLE CHR 7.24.5 ONLY. Migrate the existing Phase-3 watchdog to a
# finite RAM-only readiness lease. Does not install a second competing monitor.
# No production guarantee: native boot captures and lease-expiry tests are required.
# Saved mapping chain must cover every issued alias. Unmapped aliases have no
# fallback promise. Existing conntrack translations do not change with a lease.
# Reserved lease namespace may contain only the single dynamic entry below.
:local d [/system/script/find where name="mc-lab-down"]
:local p [/system/script/find where name="mc-lab-up"]
:local b [/system/scheduler/find where name="mc-lab-boot-direct"]
:local w [/tool/netwatch/find where comment="mikrocentauri:lab:netwatch:readiness"]
:local r [/ip/route/find where comment="mikrocentauri:lab:route:fakeip"]
:local t [/ip/firewall/nat/find where comment="mikrocentauri:lab:nat:dns-tcp"]
:local u [/ip/firewall/nat/find where comment="mikrocentauri:lab:nat:dns-udp"]
:local f [/ip/firewall/nat/find where comment="mikrocentauri:lab:nat:dynamic-jump"]
:if (([:len $d] != 1) || ([:len $p] != 1) || ([:len $b] != 1) || ([:len $w] != 1) || ([:len $r] != 1) || ([:len $t] != 1) || ([:len $u] != 1) || ([:len $f] != 1)) do={ :error "MC_LAB_LEASE: expected unique existing objects" }
:if ([:len [/system/script/find where name="mc-lab-lease-refresh"]] != 0) do={ :error "MC_LAB_LEASE: migration already installed" }
:if ([:len [/ip/firewall/address-list/find where list="mc-lab-up-lease"]] != 0) do={ :error "MC_LAB_LEASE: reserved list occupied" }
:if (([:tostr [/tool/netwatch/get $w host]] != "172.30.0.2") || ([:tostr [/tool/netwatch/get $w type]] != "http-get") || ([/tool/netwatch/get $w port] != 9099) || ([:tostr [/tool/netwatch/get $w http-codes]] != "200")) do={ :error "MC_LAB_LEASE: unexpected watchdog" }
# Validate the legacy selector generation before installing any new predicate.
:do {
    :local r [/ip/route/find where comment="mikrocentauri:lab:route:fakeip"]
    :local t [/ip/firewall/nat/find where comment="mikrocentauri:lab:nat:dns-tcp"]
    :local u [/ip/firewall/nat/find where comment="mikrocentauri:lab:nat:dns-udp"]
    :local f [/ip/firewall/nat/find where comment="mikrocentauri:lab:nat:dynamic-jump"]
    :if (([:len $r] != 1) || ([:len $t] != 1) || ([:len $u] != 1) || ([:len $f] != 1)) do={
        /system/script/run mc-lab-down
        :error "MC_LAB_NOT_READY: missing or duplicate owned generation"
    }
    :if (([:tostr [/ip/route/get $r dst-address]] != "198.18.0.0/15") || ([:tostr [/ip/route/get $r gateway]] != "172.30.0.2") || ([:tostr [/ip/route/get $r routing-table]] != "main")) do={
        /system/script/run mc-lab-down
        :error "MC_LAB_NOT_READY: unexpected route generation"
    }
    :foreach n in=($t,$u) do={
        :if (([:tostr [/ip/firewall/nat/get $n chain]] != "dstnat") || ([:tostr [/ip/firewall/nat/get $n action]] != "dst-nat") || ([:tostr [/ip/firewall/nat/get $n in-interface]] != "bridge-lan") || ([:tostr [/ip/firewall/nat/get $n dst-address]] != "192.168.88.1") || ([:tostr [/ip/firewall/nat/get $n dst-port]] != "53") || ([:tostr [/ip/firewall/nat/get $n to-addresses]] != "172.30.0.2") || ([:tostr [/ip/firewall/nat/get $n to-ports]] != "5353") || ([:tostr [/ip/firewall/nat/get $n src-address-list]] != "")) do={
            /system/script/run mc-lab-down
            :error "MC_LAB_NOT_READY: unexpected DNS generation"
        }
    }
    :if (([:tostr [/ip/firewall/nat/get $t protocol]] != "tcp") || ([:tostr [/ip/firewall/nat/get $u protocol]] != "udp")) do={
        /system/script/run mc-lab-down
        :error "MC_LAB_NOT_READY: unexpected DNS protocols"
    }
    :if (([:tostr [/ip/firewall/nat/get $f chain]] != "dstnat") || ([:tostr [/ip/firewall/nat/get $f action]] != "jump") || ([:tostr [/ip/firewall/nat/get $f jump-target]] != "mc-dynamic-backup") || ([:tostr [/ip/firewall/nat/get $f in-interface]] != "bridge-lan") || ([:tostr [/ip/firewall/nat/get $f src-address]] != "192.168.88.0/24") || ([:tostr [/ip/firewall/nat/get $f dst-address]] != "198.18.0.0/15") || ([:tostr [/ip/firewall/nat/get $f protocol]] != "") || ([:tostr [/ip/firewall/nat/get $f dst-port]] != "") || ([:tostr [/ip/firewall/nat/get $f src-address-list]] != "")) do={
        /system/script/run mc-lab-down
        :error "MC_LAB_NOT_READY: unexpected dynamic jump generation"
    }
} on-error={ :error "MC_LAB_LEASE: invalid legacy selector generation" }
# Migration is deliberately not atomic. A failed import needs explicit repair.
# Disable the old monitor and establish its existing safe DOWN before changing rules.
/tool/netwatch/disable $w
/system/script/run mc-lab-down
/ip/firewall/nat/set $t src-address-list=mc-lab-up-lease
/ip/firewall/nat/set $u src-address-list=mc-lab-up-lease
/ip/firewall/nat/set $f src-address-list=!mc-lab-up-lease

/system/script/set $d policy=read,write,test dont-require-permissions=no source={
    # Removing the lease changes both packet predicates before any other work.
    :local lease [/ip/firewall/address-list/find where list="mc-lab-up-lease"]
    :if ([:len $lease] != 0) do={
        /ip/firewall/address-list/remove $lease
        :log warning "MC_LAB_LEASE_DIRECT: runtime lease removed; saved mappings stay enabled"
    }
}

/system/script/set $p policy=read,write,test dont-require-permissions=no source={
    :do {
        :local w [/tool/netwatch/find where comment="mikrocentauri:lab:netwatch:readiness"]
        :if (([:len $w] != 1) || ([:tostr [/tool/netwatch/get $w status]] != "up") || ([/tool/netwatch/get $w disabled] = true) || ([:tostr [/tool/netwatch/get $w host]] != "172.30.0.2") || ([:tostr [/tool/netwatch/get $w type]] != "http-get") || ([/tool/netwatch/get $w port] != 9099) || ([:tostr [/tool/netwatch/get $w http-codes]] != "200")) do={ :error "MC_LAB_LEASE: readiness probe not UP or changed" }
        :local r [/ip/route/find where comment="mikrocentauri:lab:route:fakeip"]
        :local t [/ip/firewall/nat/find where comment="mikrocentauri:lab:nat:dns-tcp"]
        :local u [/ip/firewall/nat/find where comment="mikrocentauri:lab:nat:dns-udp"]
        :local f [/ip/firewall/nat/find where comment="mikrocentauri:lab:nat:dynamic-jump"]
        :if (([:len $r] != 1) || ([:len $t] != 1) || ([:len $u] != 1) || ([:len $f] != 1)) do={
            /system/script/run mc-lab-down
            :error "MC_LAB_NOT_READY: missing or duplicate owned generation"
        }
        :if (([:tostr [/ip/route/get $r dst-address]] != "198.18.0.0/15") || ([:tostr [/ip/route/get $r gateway]] != "172.30.0.2") || ([:tostr [/ip/route/get $r routing-table]] != "main")) do={
            /system/script/run mc-lab-down
            :error "MC_LAB_NOT_READY: unexpected route generation"
        }
        :foreach n in=($t,$u) do={
            :if (([:tostr [/ip/firewall/nat/get $n chain]] != "dstnat") || ([:tostr [/ip/firewall/nat/get $n action]] != "dst-nat") || ([:tostr [/ip/firewall/nat/get $n in-interface]] != "bridge-lan") || ([:tostr [/ip/firewall/nat/get $n dst-address]] != "192.168.88.1") || ([:tostr [/ip/firewall/nat/get $n dst-port]] != "53") || ([:tostr [/ip/firewall/nat/get $n to-addresses]] != "172.30.0.2") || ([:tostr [/ip/firewall/nat/get $n to-ports]] != "5353") || ([:tostr [/ip/firewall/nat/get $n src-address-list]] != "mc-lab-up-lease")) do={
                /system/script/run mc-lab-down
                :error "MC_LAB_NOT_READY: unexpected DNS generation"
            }
        }
        :if (([:tostr [/ip/firewall/nat/get $t protocol]] != "tcp") || ([:tostr [/ip/firewall/nat/get $u protocol]] != "udp")) do={
            /system/script/run mc-lab-down
            :error "MC_LAB_NOT_READY: unexpected DNS protocols"
        }
        :if (([:tostr [/ip/firewall/nat/get $f chain]] != "dstnat") || ([:tostr [/ip/firewall/nat/get $f action]] != "jump") || ([:tostr [/ip/firewall/nat/get $f jump-target]] != "mc-dynamic-backup") || ([:tostr [/ip/firewall/nat/get $f in-interface]] != "bridge-lan") || ([:tostr [/ip/firewall/nat/get $f src-address]] != "192.168.88.0/24") || ([:tostr [/ip/firewall/nat/get $f dst-address]] != "198.18.0.0/15") || ([:tostr [/ip/firewall/nat/get $f protocol]] != "") || ([:tostr [/ip/firewall/nat/get $f dst-port]] != "") || ([:tostr [/ip/firewall/nat/get $f src-address-list]] != "!mc-lab-up-lease")) do={
            /system/script/run mc-lab-down
            :error "MC_LAB_NOT_READY: unexpected dynamic jump generation"
        }
        # Persisted selectors never toggle with readiness. If modified, revoke first.
        :if (([/ip/route/get $r disabled] = true) || ([/ip/firewall/nat/get $t disabled] = true) || ([/ip/firewall/nat/get $u disabled] = true) || ([/ip/firewall/nat/get $f disabled] = true)) do={ :error "MC_LAB_LEASE: static selector disabled" }
        :local lease [/ip/firewall/address-list/find where list="mc-lab-up-lease"]
        :if ([:len $lease] > 1) do={ :error "MC_LAB_LEASE: duplicate token" }
        :if ([:len $lease] = 1) do={
            :if (([:tostr [/ip/firewall/address-list/get $lease address]] != "192.168.88.0/24") || ([:tostr [/ip/firewall/address-list/get $lease comment]] != "mikrocentauri:lab:lease:up") || ([/ip/firewall/address-list/get $lease dynamic] != true) || ([/ip/firewall/address-list/get $lease disabled] = true) || ([/ip/firewall/address-list/get $lease timeout] <= 0s)) do={ :error "MC_LAB_LEASE: invalid or static token" }
            /ip/firewall/address-list/set $lease timeout=6s
        } else={
            # This is the ONLY UP mutation, last after every readiness/shape check.
            # A finite timeout makes the entry dynamic and absent after reboot.
            /ip/firewall/address-list/add list=mc-lab-up-lease address=192.168.88.0/24 timeout=6s comment="mikrocentauri:lab:lease:up"
        }
    } on-error={
        /system/script/run mc-lab-down
        :error "MC_LAB_LEASE: UP validation or renewal failed; lease revoked"
    }
}

/system/script/add name=mc-lab-lease-refresh policy=read,write,test dont-require-permissions=no source={
    :local w [/tool/netwatch/find where comment="mikrocentauri:lab:netwatch:readiness"]
    :if (([:len $w] = 1) && ([:tostr [/tool/netwatch/get $w status]] = "up") && ([/tool/netwatch/get $w disabled] = false)) do={
        /system/script/run mc-lab-up
    } else={
        /system/script/run mc-lab-down
    }
}
# No lease exists during installation. Thus static enabled selectors mean DIRECT.
/ip/route/enable $r
/ip/firewall/nat/enable $t
/ip/firewall/nat/enable $u
/ip/firewall/nat/enable $f
# Startup script is defense in depth; correctness must not depend on its timing.
/system/scheduler/set $b policy=read,write,test on-event="/system/script/run mc-lab-down"
/tool/netwatch/set $w interval=2s timeout=1s thr-http-time=1s startup-delay=10s start-delay=1s ignore-initial-up=no ignore-initial-down=no up-script="/system/script/run mc-lab-up" down-script="/system/script/run mc-lab-down" test-script="/system/script/run mc-lab-lease-refresh"
/tool/netwatch/enable $w
