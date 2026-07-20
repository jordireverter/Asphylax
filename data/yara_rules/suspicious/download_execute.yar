rule Suspicious_Download_Execute
{
    meta:
        description = "Detecta patrons de descàrrega de contingut remot"
        severity = "medium"
        category = "download_execute"
        confidence = 65
        source = "asphylax"

    strings:
        $a = /curl\s+.*https?:\/\// nocase
        $b = /wget\s+.*https?:\/\// nocase
        $c = /invoke-webrequest\s+.*https?:\/\// nocase
        $d = /iwr\s+.*https?:\/\// nocase

    condition:
        any of them
}