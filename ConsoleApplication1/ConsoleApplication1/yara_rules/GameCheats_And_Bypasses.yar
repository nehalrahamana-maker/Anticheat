/*
    Anticheat YARA Rule Set - Game Cheats, Aimbots, Emulators & Bypasses
    Aggregated & Optimized for High-Performance Native Scanning
    Sources:
      - theITronin/File-Scanner-For-Windows (yara_rules)
      - InQuest/yara-rules (via InQuest/awesome-yara)
      - JcDesigns-the-developer/a-ton-of-yara-rules
*/

rule Game_Aimbot_Tracking_Collider : Cheat Combat
{
    meta:
        description = "Detects sniper tracking, collider aimbots, and scope calculation algorithms"
        author = "Anticheat Core Security"
        severity = "CRITICAL"
        reference = "https://github.com/JcDesigns-the-developer/a-ton-of-yara-rules-more-than-37000-lines"

    strings:
        $s1 = "sniper tracking" nocase ascii wide
        $s2 = "sniper scoper tracking" nocase ascii wide
        $s3 = "colloider aimbot" nocase ascii wide
        $s4 = "collider aimbot" nocase ascii wide
        $s5 = "sniper sope" nocase ascii wide
        $s6 = "colloider" nocase ascii wide
        $s7 = "scoper tracking" nocase ascii wide

    condition:
        any of them
}

rule Bypass_BSTKVMM_BlueStacks_Hypervisor : Emulator Bypass
{
    meta:
        description = "Detects BlueStacks bstkvmm hypervisor manipulation and VM memory bypass"
        author = "Anticheat Core Security"
        severity = "CRITICAL"

    strings:
        $b1 = "bstkvmm.dll" nocase ascii wide
        $b2 = "bstkvmm" nocase ascii wide
        $b3 = "bstk_vmm" nocase ascii wide
        $b4 = "\\\\.\\BstkDrv" ascii wide
        $b5 = "\\\\.\\BstkVM" ascii wide

    condition:
        any of them
}

rule Bypass_VIP_Authors_Signatures : VIP Bypass
{
    meta:
        description = "Identifies custom South-Asian and global VIP cheat authors: Galib, Rabbi, Ahamed, Daku, Mirza, GTC, Fin"
        author = "Anticheat Core Security"
        severity = "CRITICAL"

    strings:
        $v1 = "galib" nocase ascii wide
        $v2 = "galib_vip" nocase ascii wide
        $v3 = "galib_bypass" nocase ascii wide
        $v4 = "rabbi" nocase ascii wide
        $v5 = "rabbi_vip" nocase ascii wide
        $v6 = "ahamaed" nocase ascii wide
        $v7 = "ahamed" nocase ascii wide
        $v8 = "daku" nocase ascii wide
        $v9 = "daku_vip" nocase ascii wide
        $v10 = "mirza" nocase ascii wide
        $v11 = "mirza_vip" nocase ascii wide
        $v12 = "gtc" nocase ascii wide
        $v13 = "gtc_bypass" nocase ascii wide
        $v14 = "gtc_aimbot" nocase ascii wide
        $v15 = "fin_real" nocase ascii wide
        $v16 = "fin_bypass" nocase ascii wide

    condition:
        any of them
}

rule Bypass_Real_Bios_Hardware_Spoofer : Spoofer HWID
{
    meta:
        description = "Detects Real BIOS manipulation, SMBIOS spoofers, and motherboard serial modifications"
        author = "Anticheat Core Security"
        severity = "CRITICAL"

    strings:
        $bs1 = "real bios" nocase ascii wide
        $bs2 = "real_bios" nocase ascii wide
        $bs3 = "bios_spoofer" nocase ascii wide
        $bs4 = "bios_serial" nocase ascii wide
        $bs5 = "bios_bypass" nocase ascii wide
        $bs6 = "bios_flash" nocase ascii wide
        $bs7 = "AMIDEWIN" nocase ascii wide

    condition:
        any of them
}

rule Combat_Smooth_Brutal_Aimbot_Rage : Combat Aimbot
{
    meta:
        description = "Detects smooth aimbot, brutal rage aimbot, and aimbot hotkey dispatchers"
        author = "Anticheat Core Security"
        severity = "CRITICAL"

    strings:
        $r1 = "smooth aimbot brutal" nocase ascii wide
        $r2 = "smooth aimbot" nocase ascii wide
        $r3 = "brutal aimbot" nocase ascii wide
        $r4 = "brutal_rage" nocase ascii wide
        $r5 = "rage aimbot" nocase ascii wide
        $r6 = "real aimbot" nocase ascii wide
        $r7 = "ai aimbot" nocase ascii wide
        $r8 = "aimbot_hotkeys" nocase ascii wide

    condition:
        any of them
}

rule Hack_KDMapper_Vulnerable_Driver : Kernel Exploit
{
    meta:
        description = "Detects KDMapper Bring-Your-Own-Vulnerable-Driver kernel loaders"
        author = "Anticheat Core Security"
        severity = "CRITICAL"

    strings:
        $k1 = "kdmapper" nocase ascii wide
        $k2 = "iqvw64e.sys" nocase ascii wide
        $k3 = "\\Device\\Nal" nocase ascii wide
        $k4 = "kdu.exe" nocase ascii wide

    condition:
        any of them
}
