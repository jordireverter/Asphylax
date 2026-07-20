rule Credential_Theft_Mimikatz_Indicators
{
    meta:
        description = "Detecta cadenes associades a Mimikatz"
        severity = "high"
        category = "credential_theft"
        confidence = 85
        source = "asphylax"

    strings:
        $a = "mimikatz" nocase
        $b = "sekurlsa" nocase
        $c = "kerberos::" nocase
        $d = "lsadump::" nocase

    condition:
        any of them
}