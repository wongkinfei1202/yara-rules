rule test
{
    meta:
        description = "检测包含恶意代码特征字符串的病毒"
        version = "1.0"
        threat_level = "high"

    strings:
        $s1 = "malicious_function_call"    // 恶意函数名
        $s2 = "cmd.exe /c whoami"          // 常见命令注入
        $s3 = "powershell -enc"            // PowerShell 编码命令
        $s4 = { E8 ?? ?? ?? ?? 83 C4 04 C3 } // 可疑的 x86 shellcode 特征

    condition:
        any of ($s*)
}
