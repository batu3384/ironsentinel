rule EICAR_Test_File
{
  meta:
    description = "Detects the standard EICAR antivirus test file"
    severity = "critical"
  strings:
    $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
  condition:
    $eicar
}

rule Suspicious_Obfuscated_Script
{
  meta:
    description = "Detects suspicious script fragments often seen in staged payloads"
    severity = "high"
  strings:
    $eval = /eval\s*\(\s*atob/i
    $powershell = /powershell(\.exe)?\s+-enc/i
    $curlpipe = /curl[^\n]{0,120}\|\s*(sh|bash|zsh)/i
  condition:
    any of them
}
