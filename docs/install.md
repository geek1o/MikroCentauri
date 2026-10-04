# Installation status

MikroCentauri is a research/prototype repository, not an installable application.
Run the local CLI/lab instructions in `development.md` and `lab.md`.

Official UX target: RouterOS >=7.22 custom `/app`, arm64/amd64. The manifest in
`packaging/routeros-app/app.yml` contains an intentional unpublished-image placeholder.
TUN/capabilities, app privilege mapping, secrets, persistence and watchdog need real
version-specific tests before installation commands can be supplied safely.
