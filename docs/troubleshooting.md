# Prototype troubleshooting

Use exact pinned sing-box 1.14.2; moving website examples can include future fields.
CLI errors hide sing-box stderr because it may include secrets. For trusted local
lab fixtures, run `sing-box check -c <private-candidate>` directly to inspect details.
Do not paste private endpoint output into diagnostics or Git.

CHR package absent after cold reset: transfer a matching official NPK again, verify
file size, and use **RouterOS `/system/reboot`** to trigger package installation.
Enable device-mode and confirm physically in the isolated lab. TUN node presence
alone does not mean `TUNSETIFF`/routing is permitted. Use the probe before dataplane.

FakeIP after a crash: cached addresses remain synthetic; disabling a route will not
make them public destinations. Read ADR-0002. Readiness, Netwatch and complete
failure recovery are not currently implemented.
