/*
   Reglas YARA mínimas de ejemplo.
   Pon aquí tus .yar/.yara reales.
*/

rule Suspicious_PowerShell_Encoded
{
    meta:
        author = "ciberbot"
        description = "Powershell base64-encoded payload heuristic"
    strings:
        $a = "powershell" nocase
        $b = "-EncodedCommand" nocase
        $c = "FromBase64String" nocase
    condition:
        2 of them
}

rule Eicar_Test_File
{
    meta:
        author = "ciberbot"
        description = "Standard EICAR antivirus test string"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
