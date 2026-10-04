# EMPTY DISPOSABLE CHR ONLY. Assembled from tested lab operations; fresh one-shot
# import has NOT been independently replayed. Does not format disks/import images.
:if ([:pick [/system/resource/get board-name] 0 3] != "CHR") do={ :error "CHR laboratory required" }
:if ([:len [/interface/find where name="ether3"]] != 1) do={ :error "third lab Ethernet missing" }
:if ([:len [/interface/bridge/find where name="bridge-lan"]] != 0) do={ :error "lab already provisioned" }
:if ([:len [/user/find where name="mc-lab"]] != 0) do={ :error "lab account exists" }
/interface/bridge/add name=bridge-lan
/interface/bridge/port/add bridge=bridge-lan interface=ether2
/ip/address/add address=192.168.88.1/24 interface=bridge-lan
/ip/address/add address=10.77.0.1/24 interface=ether3
/ip/address/add address=203.0.113.1/24 interface=ether3 comment="disposable-lab-public-fixture"
:if ([:len [/interface/bridge/find where name="mc-bridge"]] = 0) do={
 /interface/bridge/add name=mc-bridge
 /ip/address/add address=172.30.0.1/24 interface=mc-bridge
 /interface/veth/add name=mc-probe address=172.30.0.2/24 gateway=172.30.0.1
 /interface/bridge/port/add bridge=mc-bridge interface=mc-probe
}
/ip/dhcp-client/set [find where interface="ether1"] use-peer-dns=no
/ip/dns/set servers=10.77.0.20 allow-remote-requests=yes
/ip/firewall/nat/add chain=srcnat out-interface=ether3 action=masquerade comment="disposable-lab-wan"
/ip/route/add dst-address=198.18.0.0/15 gateway=172.30.0.2 disabled=yes comment="mikrocentauri:lab:route:fakeip"
/ip/firewall/nat/add chain=dstnat protocol=tcp in-interface=bridge-lan dst-address=192.168.88.1 dst-port=53 action=dst-nat to-addresses=172.30.0.2 to-ports=5353 disabled=yes comment="mikrocentauri:lab:nat:dns-tcp"
/ip/firewall/nat/add chain=dstnat protocol=udp in-interface=bridge-lan dst-address=192.168.88.1 dst-port=53 action=dst-nat to-addresses=172.30.0.2 to-ports=5353 disabled=yes comment="mikrocentauri:lab:nat:dns-udp"
/routing/table/add name=mc-lab-full fib=yes
/ip/route/add dst-address=0.0.0.0/0 gateway=172.30.0.2@main routing-table=mc-lab-full disabled=yes comment="mikrocentauri:lab:route:realip"
/ip/dns/static/add name=selected.test type=FWD address-list=mc-lab-domains match-subdomain=no disabled=yes comment="mikrocentauri:lab:dns:selected-real"
/ip/firewall/mangle/add chain=prerouting in-interface=bridge-lan dst-address-list=mc-lab-domains action=mark-routing new-routing-mark=mc-lab-full passthrough=no disabled=yes comment="mikrocentauri:lab:mangle:realip"
/user/group/add name=mc-lab-rest policy=read,write,api,rest-api,test
/user/add name=mc-lab group=mc-lab-rest password="DisposableLabOnly-2026"
/ip/service/set www disabled=no address=10.0.2.0/24
