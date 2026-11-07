"""Versioned implementation coverage, separate from a particular host's result.

These descriptors do not probe a system, verify a runtime binary, authenticate,
fetch advisories, or claim that an implemented provider was run on any asset.
"""

import copy

VERSION = "scanner-capabilities-v1"
STAGES = (
    ("discovery", "Erkennung"),
    ("inventory", "Inventur"),
    ("configuration", "Konfiguration"),
    ("os_baseline", "OS-Baseline"),
    ("software_checks", "Software-Meldungen"),
    ("offered_updates", "Angebotene Updates"),
)


def _stage(status, provider, scope, prerequisites=(), limitations=()):
    return {
        "status": status,
        "provider": provider,
        "scope": scope,
        "prerequisites": list(prerequisites),
        "limitations": list(limitations),
    }


def _missing(scope):
    return _stage(
        "unavailable", None, scope, limitations=("Kein passender Anbieter implementiert.",)
    )


def _network_discovery():
    return _stage(
        "limited",
        "nmap-network",
        "IPv4/IPv6: begrenzte TCP-Ports und gemeldete Dienste in freigegebenen Netzen.",
        ("Konfigurierte Scanner-CIDRs", "Erreichbare freigegebene Zieladressen", "Nmap im Worker"),
        ("Keine UDP-Erkennung.", "Offene Ports oder Produktbanner bestätigen kein Betriebssystem."),
    )


def _network_configuration():
    return _stage(
        "limited",
        "network-audit",
        "Feste protokollbasierte Regeln für SSH, TLS, SMB und RDP.",
        ("Positive Diensterkennung", "Anwendbare Protokollregel", "Erfolgreiche Enumeration"),
        ("Kein vollständiger Geräte- oder Firmware-CVE-Abgleich.",),
    )


def _windows_inventory():
    return _stage(
        "limited",
        "hostinventory-winrm",
        "OS-Identität, maschinenweite Uninstall-Registry und Get-HotFix.",
        (
            "Freigegebenes Konto und Ziel",
            "WinRM/NTLM mit geprüftem HTTPS oder verschlüsselten HTTP-Nachrichten",
        ),
        ("Keine vollständige Softwareinventur; portable und benutzerbezogene Programme fehlen.",),
    )


def _windows_software():
    return _stage(
        "limited",
        "windows-registry-ranges-v1",
        "Exakte Produkt-/Herstellerzuordnung: ausgewählte Edge-Meldungen und 7-Zip CVE-2025-55188.",
        (
            "Aktuelle Registry-Inventur mit Hersteller- und Versionsdaten",
            "Aktueller Softwarekatalog",
        ),
        (
            "Andere Software und nicht ausgewertete Meldungen bleiben ungeprüft.",
            "Versionszuordnung bestätigt keine Ausnutzbarkeit.",
        ),
    )


def _offered_updates():
    return _stage(
        "limited",
        "windows-update-agent",
        (
            "Explizit gestartete Online-Suche nach angebotenen Updates der konfigurierten "
            "Windows-Update-/WSUS-Quelle."
        ),
        (
            "Expliziter Inventurmodus windows_updates",
            "Freigegebener WinRM-Zugang",
            "Funktionsfähiger Windows Update Agent und konfigurierte Quelle",
        ),
        (
            "Keine Installation und kein Download von Updates.",
            "Keine Angebote sind keine vollständige Entwarnung.",
            "WUA-Suchmetadaten können lokal aktualisiert werden.",
        ),
    )


def _platform(identifier, name, overrides):
    stages = {key: _missing("Für diese Plattform nicht implementiert.") for key, _ in STAGES}
    stages.update(overrides)
    return {"id": identifier, "name": name, "stages": stages}


def capabilities():
    """Return fresh objects; consumers cannot mutate the shared registry."""
    windows = {
        "discovery": _network_discovery(),
        "inventory": _windows_inventory(),
        "configuration": _network_configuration(),
        "software_checks": _windows_software(),
        "offered_updates": _offered_updates(),
    }
    platforms = [
        _platform(
            "domains",
            "Domains",
            {
                "discovery": _stage(
                    "limited",
                    "subfinder/dnsx/httpx",
                    "DNS-/Subdomain- und HTTP-Erkennung.",
                    ("Konfigurierte Webscanner",),
                    ("Keine authentifizierte Host-Inventur.",),
                ),
            },
        ),
        _platform(
            "urls",
            "URLs",
            {
                "discovery": _stage(
                    "limited",
                    "katana/urlprobe",
                    "Crawling und HTTP-Beobachtungen freigegebener URLs.",
                ),
                "configuration": _stage(
                    "limited",
                    "headerfindings/nucleiurl",
                    "Ausgewählte Headerregeln und Nuclei-Templates.",
                    ("Anwendbare Regeln und vorhandene Templates",),
                    ("Keine vollständige Host-Patchbewertung.",),
                ),
            },
        ),
        _platform(
            "network",
            "Netzwerk",
            {
                "discovery": _network_discovery(),
                "configuration": _network_configuration(),
            },
        ),
        _platform(
            "windows_server",
            "Windows Server",
            {
                **windows,
                "os_baseline": _stage(
                    "limited",
                    "windows-server-build-v1",
                    (
                        "Standardmäßige kumulative OS-Builds unterstützter Windows Server "
                        "2016/2019/2022/2025 AMD64-Editionen."
                    ),
                    ("Exakte aktuelle Windows-Identität", "Aktueller MSRC-Katalog"),
                    (
                        "Keine vollständige Komponenten- oder CVE-Anwendbarkeitsprüfung.",
                        "Hotpatch und abweichende Servicingmodelle sind nicht abgedeckt.",
                    ),
                ),
            },
        ),
        _platform(
            "windows_client",
            "Windows Clients",
            {
                **windows,
                "os_baseline": _missing(
                    "Kein generischer Windows-Client-Buildkatalog; angebotene Updates "
                    "werden separat über WUA ermittelt."
                ),
            },
        ),
        _platform(
            "linux",
            "Linux",
            {
                "discovery": _network_discovery(),
                "configuration": _network_configuration(),
                "inventory": _stage(
                    "limited",
                    "hostinventory-ssh",
                    "Linux-OS, Kernel und installierte dpkg-/RPM-Pakete.",
                    (
                        "Python 3 auf dem Ziel",
                        "Freigegebener SSH-Zugang und unabhängig bestätigter Hostschlüssel",
                    ),
                    (
                        "Keine distributionsspezifische Paket-CVE-/Patchbewertung.",
                        "Andere Paketformate und benutzerbezogene Software fehlen.",
                    ),
                ),
            },
        ),
        _platform(
            "vmware",
            "VMware",
            {
                "discovery": _network_discovery(),
                "configuration": _network_configuration(),
                "inventory": _missing("Noch kein authentifizierter ESXi-/vCenter-Inventuradapter."),
            },
        ),
        _platform(
            "other_devices",
            "Weitere Systeme",
            {
                "discovery": _network_discovery(),
                "configuration": _network_configuration(),
                "inventory": _missing(
                    "Noch keine plattformspezifischen Adapter für macOS, Appliances, "
                    "IoT/OT oder Containerinventare."
                ),
            },
        ),
    ]
    return copy.deepcopy(
        {
            "version": VERSION,
            "stage_labels": [{"id": key, "name": name} for key, name in STAGES],
            "platforms": platforms,
            "limitations": [
                (
                    "Diese Matrix beschreibt implementierte Möglichkeiten, "
                    "nicht den Prüfstatus eines bestimmten Hosts."
                ),
                (
                    "Erkennung, Inventur, Konfigurationsregeln, OS-Baselines und "
                    "angebotene Updates sind getrennte Prüfschritte."
                ),
                "Nicht unterstützte oder nicht ausgeführte Prüfungen bedeuten keine Entwarnung.",
            ],
        }
    )
