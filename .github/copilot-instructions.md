# Copilot Instructions for sonic-dhcpmon

## Project Overview

sonic-dhcpmon is a DHCP monitoring daemon for SONiC switches. It monitors DHCP (Dynamic Host Configuration Protocol) packet flows to detect issues with DHCP relay functionality, ensuring that DHCP requests from connected hosts are properly relayed and responses are received.

## Architecture

```
sonic-dhcpmon/
├── src/                    # C++ source files
│   ├── dhcpmon.cpp/h       # Main DHCP monitor implementation
│   └── ...                 # Supporting source files
├── Makefile                # Build system
├── objects.mk              # Object file definitions
├── debian/                 # Debian packaging
├── .azure-pipelines/       # Azure DevOps CI configuration
└── azure-pipelines.yml     # CI pipeline definition
```

### Key Concepts
- **Packet monitoring**: Captures and analyzes DHCP packets on switch interfaces
- **Health checking**: Detects when DHCP relay stops forwarding packets
- **Syslog alerts**: Reports DHCP issues via syslog for alerting and diagnostics

## Language & Style

- **Primary language**: C++
- **Build system**: GNU Make
- **Indentation**: 4 spaces
- **Naming conventions**:
  - Functions: `camelCase` or `snake_case`
  - Macros/constants: `UPPER_CASE`
- **Memory management**: Careful manual memory management — avoid leaks in long-running daemon

## Build Instructions

```bash
# Build from source
make

# Build Debian package
dpkg-buildpackage -rfakeroot -b -us -uc
```

## Testing

- CI runs via Azure DevOps pipelines
- Test DHCP monitoring behavior against a SONiC VS environment
- Validate packet capture and alerting logic

## PR Guidelines

- **Signed-off-by**: Required on all commits
- **CLA**: Sign Linux Foundation EasyCLA
- **Testing**: Verify monitoring functionality in a SONiC environment
- **CI**: All Azure pipeline checks must pass

## Gotchas

- **Raw sockets**: Uses raw packet sockets — requires appropriate capabilities (CAP_NET_RAW)
- **Interface naming**: Must handle SONiC interface naming conventions
- **Resource usage**: Daemon runs continuously — minimize CPU and memory footprint
- **DHCP relay integration**: Changes must be compatible with sonic-dhcp-relay behavior
