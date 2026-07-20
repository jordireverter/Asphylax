rule Asphylax_Test_Rule
{
    meta:
        description = "Regla de prova per validar el motor YARA"
        severity = "medium"
        category = "test"
        confidence = 60
        source = "asphylax"

    strings:
        $a = "asphylax malware test" nocase

    condition:
        $a
}