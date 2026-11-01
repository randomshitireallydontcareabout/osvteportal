OSV Browser RDP Setup

1. Docker and Docker Compose must already be available on the host.
2. Run browser_rdp_gateway\test.ps1.
3. Configure the existing HTTPS reverse proxy so /guacamole/ forwards to http://127.0.0.1:8080/guacamole/ with WebSocket support.
4. Open https://YOUR-WEB-APP/guacamole/ and change the initial Guacamole administrator password immediately.
5. Add permitted RDP targets in Guacamole. The host must reach each target on TCP 3389.
6. Assign Guacamole users only the connections they are authorized to use.

Do not expose port 8080 directly to the network. Keep browser access behind the existing HTTPS endpoint.
