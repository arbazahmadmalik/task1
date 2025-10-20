$outfile = "combined-nmap-report.csv"
"IP,Hostname,OpenPorts,RawPorts,Timestamp,Evidence" | Out-File -FilePath $outfile -Encoding UTF8

Get-ChildItem -Path . -Filter *.gnmap | ForEach-Object {
    $file = $_.FullName
    $basename = $_.Name
    $timestamp = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
    Get-Content -Path $file | ForEach-Object {
        $line = $_.Trim()
        if ($line -like "Host:*") {
            # Try pattern with hostname in parentheses
            $ip = $null; $hostname = "-"; $ports_field = $null
            if ($line -match '^Host:\s+(\S+)\s+\((.*?)\)\s+Ports:\s+(.+)$') {
                $ip = $matches[1]
                if ($matches[2]) { $hostname = $matches[2] } else { $hostname = "-" }
                $ports_field = $matches[3]
            }
            elseif ($line -match '^Host:\s+(\S+)\s+Ports:\s+(.+)$') {
                $ip = $matches[1]
                $ports_field = $matches[2]
            }
            if (-not $ports_field) { $ports_field = "-" }
            # Extract only port numbers marked /open/
            $openPorts = @()
            foreach ($p in ($ports_field -split ",")) {
                $p = $p.Trim()
                $m = [regex]::Match($p,'^(\d+)\/open\/')
                if ($m.Success) { $openPorts += $m.Groups[1].Value }
            }
            $openPortsCsv = if ($openPorts.Count -gt 0) { ($openPorts -join ",") } else { "-" }
            # Make fields CSV-safe by replacing commas with semicolons
            $safeHostname = ($hostname -replace ',',';')
            $safeRaw = ($ports_field -replace ',',';')
            $row = "{0},{1},{2},{3},{4},{5}" -f $ip, $safeHostname, $openPortsCsv, $safeRaw, $timestamp, $basename
            $row | Out-File -FilePath $outfile -Append -Encoding UTF8
        }
    }
}

  