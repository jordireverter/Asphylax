rule Ransomware_Indicators_Basic
{
    meta:
        description = "Detecta indicadors textuals habituals en ransomware"
        severity = "high"
        category = "ransomware"
        confidence = 75
        source = "asphylax"

    strings:
        $a = "your files have been encrypted" nocase
        $b = "decrypt your files" nocase
        $c = "bitcoin" nocase
        $d = "ransom" nocase
        $e = ".locked" nocase
        $f = ".encrypted" nocase

    condition:
        2 of them
}