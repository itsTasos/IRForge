// Original IRForge benign test pack. License: MIT. Version: 1.0.
rule IRForge_Benign_Lab_Marker {
    meta:
        description = "Benign IRForge integration marker; not malware"
        license = "MIT"
        pack_version = "1.0"
    strings:
        $marker = "IRFORGE_BENIGN_LAB_MARKER_2026" ascii
    condition:
        $marker
}
