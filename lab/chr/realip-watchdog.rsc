# Disposable CHR 7.24.5 only; real-IP alternative experiment, not installer.
:if ([:len [/system/script/find where name="mc-lab-real-down"]] != 0) do={ :error "real-IP watchdog already installed" }
/system/script/add name=mc-lab-real-down policy=read,write,test source={
 /ip/firewall/mangle/disable [find where comment="mikrocentauri:lab:mangle:realip"]
 /ip/route/disable [find where comment="mikrocentauri:lab:route:realip"]
 :log warning "MC_LAB_REAL_DIRECT: real-IP steering disabled"
}
/system/script/add name=mc-lab-real-up policy=read,write,test source={
 :local r [/ip/route/find where comment="mikrocentauri:lab:route:realip"]
 :local m [/ip/firewall/mangle/find where comment="mikrocentauri:lab:mangle:realip"]
 :if (([:len $r] != 1) || ([:len $m] != 1)) do={
  /system/script/run mc-lab-real-down
  :error "MC_LAB_REAL_NOT_READY: missing or duplicate objects"
 }
 :if (([/ip/route/get $r dst-address] != "0.0.0.0/0") || ([/ip/route/get $r gateway] != "172.30.0.2@main") || ([/ip/route/get $r routing-table] != "mc-lab-full")) do={
  /system/script/run mc-lab-real-down
  :error "MC_LAB_REAL_NOT_READY: unexpected route"
 }
 :if (([/ip/firewall/mangle/get $m chain] != "prerouting") || ([/ip/firewall/mangle/get $m in-interface] != "bridge-lan") || ([/ip/firewall/mangle/get $m dst-address-list] != "mc-lab-domains") || ([/ip/firewall/mangle/get $m action] != "mark-routing") || ([/ip/firewall/mangle/get $m new-routing-mark] != "mc-lab-full")) do={
  /system/script/run mc-lab-real-down
  :error "MC_LAB_REAL_NOT_READY: unexpected mangle"
 }
 /ip/route/enable $r
 /ip/firewall/mangle/enable $m
 :log info "MC_LAB_REAL_SELECTED: real-IP steering enabled"
}
/system/scheduler/add name=mc-lab-real-boot-direct start-time=startup interval=0s policy=read,write,test on-event="/system/script/run mc-lab-real-down"
/system/script/run mc-lab-real-down
/tool/netwatch/add comment="mikrocentauri:lab:netwatch:realip" host=172.30.0.2 type=http-get port=9099 http-codes=200 interval=2s timeout=1s thr-http-time=1s start-delay=1s startup-delay=10s ignore-initial-up=no ignore-initial-down=no up-script="/system/script/run mc-lab-real-up" down-script="/system/script/run mc-lab-real-down"
