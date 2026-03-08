# Export all .cs files to TXT
# Usage: .\Export-CsFiles.ps1 -OutputFile "output"
# Creates: output.txt

param(
    [string]$OutputFile = "cs_files_export",
    [string]$RootPath = ".",
    [switch]$IncludeLineNumbers,
    [switch]$VerboseOutput
)

# Ensure output name has no extension (we'll add .txt)
$baseName = $OutputFile -replace '\.txt$', ''
$txtFile = "$baseName.txt"

# Get all .cs files recursively, excluding common non-source directories
$excludeDirs = @('bin', 'obj', 'node_modules', '.git', '.vs', 'packages', 'TestResults', 'publish')
$csFiles = Get-ChildItem -Path $RootPath -Recurse -Filter "*.cs" -File | 
    Where-Object { 
        $fullPath = $_.FullName
        -not ($excludeDirs | Where-Object { $fullPath -like "*\$_\*" -or $fullPath -like "*/$_/*" })
    } |
    Sort-Object FullName

$totalFiles = $csFiles.Count
$totalLines = 0
Write-Host "Found $totalFiles .cs files to export..."

# Use StringBuilder for better performance with large codebases
$contentBuilder = [System.Text.StringBuilder]::new()

[void]$contentBuilder.AppendLine("C# Source Code Export")
[void]$contentBuilder.AppendLine("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$contentBuilder.AppendLine("Total Files: $totalFiles")
[void]$contentBuilder.AppendLine("Root Path: $(Resolve-Path $RootPath)")
[void]$contentBuilder.AppendLine("=" * 80)
[void]$contentBuilder.AppendLine()

$currentFile = 0
foreach ($file in $csFiles) {
    $currentFile++
    $relativePath = Resolve-Path -Relative -Path $file.FullName
    
    if ($VerboseOutput) {
        Write-Host "[$currentFile/$totalFiles] Processing: $relativePath"
    } else {
        Write-Progress -Activity "Exporting C# Files" -Status $relativePath -PercentComplete (($currentFile / $totalFiles) * 100)
    }
    
    [void]$contentBuilder.AppendLine("// " + "=" * 60)
    [void]$contentBuilder.AppendLine("// File: $relativePath")
    [void]$contentBuilder.AppendLine("// " + "=" * 60)
    [void]$contentBuilder.AppendLine()
    
    try {
        # Read raw bytes to detect encoding, then decode properly
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
        
        # Detect BOM
        $encoding = [System.Text.Encoding]::UTF8
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            $encoding = [System.Text.Encoding]::UTF8
            $bytes = $bytes[3..($bytes.Length-1)]  # Remove BOM
        } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
            $encoding = [System.Text.Encoding]::Unicode
            $bytes = $bytes[2..($bytes.Length-1)]
        } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
            $encoding = [System.Text.Encoding]::BigEndianUnicode
            $bytes = $bytes[2..($bytes.Length-1)]
        }
        
        # Convert to string, preserving ALL characters
        $fileContent = $encoding.GetString($bytes)
        
        # Normalize line endings to CRLF for consistency, but preserve empty lines
        $fileContent = $fileContent -replace "(?<!\r)\n", "`r`n"
        
        # Split into lines, preserving empty lines
        $lines = $fileContent -split "`r`n"
        
        $fileLineCount = 0
        if ($IncludeLineNumbers) {
            $lineNum = 1
            foreach ($line in $lines) {
                # Use fixed-width format that handles tab characters properly
                $displayLine = $line -replace "`t", "    "  # Convert tabs to 4 spaces
                [void]$contentBuilder.AppendLine("{0,5}: {1}" -f $lineNum, $displayLine)
                $lineNum++
                $fileLineCount++
            }
        } else {
            foreach ($line in $lines) {
                [void]$contentBuilder.AppendLine($line)
                $fileLineCount++
            }
        }
        
        $totalLines += $fileLineCount
        
        [void]$contentBuilder.AppendLine()
        [void]$contentBuilder.AppendLine()
        
        if ($VerboseOutput) {
            Write-Host "  -> $fileLineCount lines" -ForegroundColor Gray
        }
    }
    catch {
        [void]$contentBuilder.AppendLine("// ERROR reading file: $_")
        Write-Warning "Error reading $relativePath : $_"
    }
}

Write-Progress -Activity "Exporting C# Files" -Completed

$fullContent = $contentBuilder.ToString()

# Verify line counts
Write-Host "`nTotal lines exported: $totalLines" -ForegroundColor Cyan

# Export TXT using WriteAllText for exact byte-for-byte output
[System.IO.File]::WriteAllText($txtFile, $fullContent, [System.Text.Encoding]::UTF8)

$txtInfo = Get-Item $txtFile
Write-Host "`n✓ TXT created: $($txtInfo.FullName) ($($txtInfo.Length) bytes)" -ForegroundColor Green
Write-Host "Done! Exported $totalFiles files with $totalLines total lines." -ForegroundColor Cyan