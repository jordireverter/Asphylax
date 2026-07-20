rule Suspicious_PowerShell_EncodedCommand
{
    meta:
        description = "Detecta ús sospitós de PowerShell amb comandes codificades"
        severity = "high"
        category = "script_execution"
        confidence = 80
        source = "asphylax"

    strings:
        $a = /powershell(\.exe)?\s+.*(-enc|-encodedcommand)/ nocase

    condition:
        $a
}