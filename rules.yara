rule Suspicious_Remote_Thread_Injection
{
    meta:
        description = "Detects suspicious binaries using Remote Thread Injection techniques"
        author = "Security Researcher"
        date = "2025-05-25"
        threat_level = "high"

    strings:
        $a1 = "CreateRemoteThread" ascii
        $a2 = "VirtualAllocEx" ascii
        $a3 = "WriteProcessMemory" ascii
        $a4 = "OpenProcess" ascii
        $c2 = "http://" ascii
        $exe = ".exe" ascii

    condition:
        uint16(0) == 0x5A4D and // MZ header for PE files
        3 of ($a*) and $c2
}
