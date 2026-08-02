rule SUSP_Win_PowerShell_EncodedHiddenBypass_Aug26
{
    meta:
        description = "Detects PowerShell command lines combining an encoded-command flag with a hidden-window, no-profile, or execution-policy-bypass flag, a stacking pattern common in malicious loader/stager one-liners rather than routine admin scripting"
        author = "detection-workflow (portfolio project)"
        reference = "https://attack.mitre.org/techniques/T1059/001/, https://attack.mitre.org/techniques/T1027/010/"
        date = "2026-08-02"

    strings:
        // The invocation itself. Matches the bare interpreter name so it
        // fires regardless of full install path (System32 vs WOW64 vs a
        // renamed copy dropped elsewhere).
        $exe = "powershell" nocase

        // Category A: the encoded-command flag. PowerShell accepts any
        // unambiguous prefix of -EncodedCommand, and attackers routinely
        // mix case specifically to dodge case-sensitive matching -- nocase
        // is deliberate here, not speculative.
        $enc1 = "-enc " nocase
        $enc2 = "-encodedcommand " nocase

        // Category B: flags stacked alongside $enc in malicious one-liners
        // to suppress the visible window, skip profile-script loading, and
        // bypass execution policy. Individually these appear in benign
        // scripts too (see tests/yara/negative/) -- only combined with an
        // encoded-command flag do they become high-signal.
        $hide1 = "-windowstyle hidden" nocase
        $hide2 = "-w hidden" nocase
        $bypass1 = "-executionpolicy bypass" nocase
        $bypass2 = "-ep bypass" nocase
        $noprofile = "-noprofile" nocase

    condition:
        filesize < 1MB and
        $exe and
        any of ($enc*) and
        any of ($hide1, $hide2, $bypass1, $bypass2, $noprofile)
}
