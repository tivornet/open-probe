# Uninstall Tivor Open Probe V0.1

Open Probe V0.1 installs no daemon, LaunchAgent, privileged helper, background service, browser extension, or system network configuration.

1. Remove the `tivor` binary from the user-controlled directory where it was installed.
2. Optionally remove result files that you explicitly created with `--output-private` or `--export-public`.
3. Optionally remove a future user configuration/state directory only if its location is documented by the installed version. V0.1 creates none implicitly.

No route, DNS, proxy, TUN, or system preference cleanup is required.

