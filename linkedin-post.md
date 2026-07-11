# LinkedIn Short Post

---

Your OT network has devices running protocols you've probably never heard of.

GE SRTP. ProConOS. Red Lion Crimson. MELSEC-Q. FF HSE. OPC UA.

These aren't niche — they run turbine controls, automotive assembly lines, power grid equipment, and semiconductor fabs. Yet most blue teams have **zero visibility** into them because:

❌ Official Nmap covers only ~30% of OT protocols
❌ Community scripts are often broken or incomplete
❌ You can't test against production PLCs without risk

I rebuilt 13 OT NSE scripts from the ground up to fix this. The improvements over community versions:

**GE SRTP** — Two-phase INIT/INIT_ACK handshake + PLC_SSTAT/LSTAT service probes. Extracts PLC model, firmware version (e.g. V9.50), CPU type (e.g. IC695CPE302), and running status. Community versions often hang after the first handshake.

**OPC UA** — Full HEL→ACK→OPN→MSG handshake with FindServers + GetEndpoints service calls. Extracts application name, application URI, product URI, gateway server URI, discovery profiles, and all available endpoints. Community versions use partial handshakes that miss half the fields.

**MELSEC-Q** — Proper MC protocol 3E-frame handshake with CPU type command (0x0101). Extracts PLC type (e.g. Q03UDVCPU), series name, and firmware version. The original community script returns inconsistent data on newer Q-series CPUs.

**FF HSE** — Complete SM_IDENTIFY + MA_IDENTIFY dual-query with LREQ session establishment. Extracts device name, vendor name, device tag, HSE version, software revision, stack version, and MAC address.

**ProConOS** — Multi-probe sequence (run-time version, PLC model, project name). Extracts runtime version (e.g. ProConOS V3.0.1040), PLC model (e.g. ADAM5510KW), project name, and source code protection status.

**Red Lion Crimson** — Dual-mode probe (legacy 16-byte zero probe + STX-framed command). Extracts model (e.g. G310C2), firmware (e.g. Crimson 3.2), part number, and vendor name.

Every script comes with a match.ip filter, proper error handling, timeout management, and has been tested against its own **honeypot-grade mock server** — so you can validate everything works before touching real gear.

📂 **github.com/carbon-evolution/ot-nmap-blue-team**

#OTSecurity #BlueTeam #Nmap #NSE #ICS #ICSsecurity #OT #IndustrialControlSystems #CyberSecurity
