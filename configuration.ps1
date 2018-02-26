# this is a fairly naive implementation; could be more sophisticated about rule matching/collapsing
$fw = New-Object -ComObject HNetCfg.FWPolicy2

# try to find/enable the default rule first
$add_rule = $false
$matching_rules = $fw.Rules | ? { $_.Name -eq "Windows Remote Management (HTTP-In)" }
$rule = $null
If ($matching_rules) {
    If ($matching_rules -isnot [Array]) {
        $rule = $matching_rules
    }
    Else {
        # try to find one with the All or Public profile first
        $rule = $matching_rules | % { $_.Profiles -band 4 }[0]

        If (-not $rule -or $rule -is [Array]) {
            # oh well, just pick the first one
            $rule = $matching_rules[0]
        }
    }
}

If (-not $rule) {
    Write-Verbose "Creating a new HTTP firewall rule"
    $rule = New-Object -ComObject HNetCfg.FWRule
    $rule.Name = "Windows Remote Management (HTTP-In)"
    $rule.Description = "Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]"
    $add_rule = $true
}

$rule.Profiles = 0x7FFFFFFF
$rule.Protocol = 6
$rule.LocalPorts = 5985
$rule.RemotePorts = "*"
$rule.LocalAddresses = "*"
$rule.RemoteAddresses = "*"
$rule.Enabled = $true
$rule.Direction = 1
$rule.Action = 1
$rule.Grouping = "Windows Remote Management"

If ($add_rule) {
    $fw.Rules.Add($rule)
}

# Find and start the WinRM service.
If (!(Get-Service "WinRM"))
{
    Throw "Unable to find the WinRM service."
}
ElseIf ((Get-Service "WinRM").Status -ne "Running")
{
    Set-Service -Name "WinRM" -StartupType Automatic
    Start-Service -Name "WinRM" -ErrorAction Stop
}

Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop
netsh advfirewall firewall add rule profile=any name="Allow WinRM HTTPS" dir=in localport=5986 protocol=TCP action=allow
