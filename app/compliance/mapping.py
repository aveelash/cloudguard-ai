
COMPLIANCE_MAPPINGS = {
    "HTTPS-only traffic is disabled": {
        "frameworks": [
            {
                "name": "ISO 27001",
                "control": "A.8.24",
                "description": "Use of cryptography"
            },
            {
                "name": "SOC 2",
                "control": "CC6.7",
                "description": "Protection of information during transmission"
            }
        ]
    },

    "Weak minimum TLS version: 1.0": {
        "frameworks": [
            {
                "name": "ISO 27001",
                "control": "A.8.24",
                "description": "Use of cryptography"
            },
            {
                "name": "SOC 2",
                "control": "CC6.7",
                "description": "Protection of information during transmission"
            }
        ]
    },

    "Unencrypted FTP access is enabled": {
        "frameworks": [
            {
                "name": "ISO 27001",
                "control": "A.8.24",
                "description": "Use of cryptography"
            },
            {
                "name": "SOC 2",
                "control": "CC6.7",
                "description": "Protection of information during transmission"
            }
        ]
    },

    "Storage account allows access from all networks": {
        "frameworks": [
            {
                "name": "ISO 27001",
                "control": "A.8.20",
                "description": "Network security"
            },
            {
                "name": "SOC 2",
                "control": "CC6.6",
                "description": "Logical and physical access restrictions"
            }
        ]
    },

    "SSH port 22 is exposed to the internet": {
        "frameworks": [
            {
                "name": "ISO 27001",
                "control": "A.8.20",
                "description": "Network security"
            },
            {
                "name": "SOC 2",
                "control": "CC6.6",
                "description": "Logical access restrictions"
            }
        ]
    },

    "RDP port 3389 is exposed to the internet": {
        "frameworks": [
            {
                "name": "ISO 27001",
                "control": "A.8.20",
                "description": "Network security"
            },
            {
                "name": "SOC 2",
                "control": "CC6.6",
                "description": "Logical access restrictions"
            }
        ]
    },

    "All ports are exposed to the internet": {
        "frameworks": [
            {
                "name": "ISO 27001",
                "control": "A.8.20",
                "description": "Network security"
            },
            {
                "name": "SOC 2",
                "control": "CC6.6",
                "description": "Logical access restrictions"
            }
        ]
    },

    "Key Vault purge protection is disabled": {
        "frameworks": [
            {
                "name": "ISO 27001",
                "control": "A.8.10",
                "description": "Information deletion"
            },
            {
                "name": "SOC 2",
                "control": "CC6.5",
                "description": "Protection against unauthorized destruction"
            }
        ]
    },

    "Key Vault allows unrestricted public network access": {
        "frameworks": [
            {
                "name": "ISO 27001",
                "control": "A.8.20",
                "description": "Network security"
            },
            {
                "name": "SOC 2",
                "control": "CC6.6",
                "description": "Logical access restrictions"
            }
        ]
    },

    "Owner role assigned at subscription scope": {
        "frameworks": [
            {
                "name": "ISO 27001",
                "control": "A.5.15",
                "description": "Access control"
            },
            {
                "name": "SOC 2",
                "control": "CC6.1",
                "description": "Logical access security"
            }
        ]
    },

    "Contributor role assigned at subscription scope": {
        "frameworks": [
            {
                "name": "ISO 27001",
                "control": "A.5.15",
                "description": "Access control"
            },
            {
                "name": "SOC 2",
                "control": "CC6.1",
                "description": "Logical access security"
            }
        ]
    }
}


def map_finding_to_compliance(finding):
    issue = finding["issue"]

    mapping = COMPLIANCE_MAPPINGS.get(issue, {
        "frameworks": []
    })

    return {
        **finding,
        "compliance": mapping["frameworks"]
    }
