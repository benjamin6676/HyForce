# Export all .cs files to TXT and PDF
# Usage: .\Export-CsFiles.ps1 -OutputFile "output"
# Creates: output.txt and output.pdf (if Word is available)

param(
    [string]$OutputFile = "cs_files_export",
    [string]$RootPath = ".",
    [switch]$IncludeLineNumbers,
    [switch]$OnlyTxt,
    [switch]$OnlyPdf
)

# Ensure output name has no extension (we'll add them)
$baseName = $OutputFile -replace '\.(txt|pdf)$', ''
$txtFile = "$baseName.txt"
$pdfFile = "$baseName.pdf"

# Get all .cs files recursively, excluding common non-source directories
$excludeDirs = @('bin', 'obj', 'node_modules', '.git', '.vs', 'packages', 'TestResults', 'publish')
$csFiles = Get-ChildItem -Path $RootPath -Recurse -Filter "*.cs" | 
    Where-Object { 
        $fullPath = $_.FullName
        -not ($excludeDirs | Where-Object { $fullPath -like "*\$_\*" -or $fullPath -like "*/$_/*" })
    } |
    Sort-Object FullName

$totalFiles = $csFiles.Count
Write-Host "Found $totalFiles .cs files to export..."

# Build content
$contentLines = @()
$contentLines += "C# Source Code Export"
$contentLines += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$contentLines += "Total Files: $totalFiles"
$contentLines += "Root Path: $(Resolve-Path $RootPath)"
$contentLines += "=" * 80
$contentLines += ""

$currentFile = 0
foreach ($file in $csFiles) {
    $currentFile++
    $relativePath = Resolve-Path -Relative -Path $file.FullName
    
    Write-Host "[$currentFile/$totalFiles] Processing: $relativePath"
    
    $contentLines += "// " + "=" * 60
    $contentLines += "// File: $relativePath"
    $contentLines += "// " + "=" * 60
    $contentLines += ""
    
    try {
        $fileContent = Get-Content -Path $file.FullName -Encoding UTF8
        
        if ($IncludeLineNumbers) {
            $lineNum = 1
            foreach ($line in $fileContent) {
                $contentLines += ("{0,4}: {1}" -f $lineNum, $line)
                $lineNum++
            }
        } else {
            $contentLines += $fileContent
        }
        
        $contentLines += ""
        $contentLines += ""
    }
    catch {
        $contentLines += "// ERROR reading file: $_"
    }
}

$fullContent = $contentLines -join "`r`n"

# Export TXT
if (-not $OnlyPdf) {
    $fullContent | Set-Content -Path $txtFile -Encoding UTF8 -NoNewline
    Write-Host "`n✓ TXT created: $(Resolve-Path $txtFile)" -ForegroundColor Green
}

# Export PDF (requires Microsoft Word)
if (-not $OnlyTxt) {
    try {
        $word = New-Object -ComObject Word.Application -ErrorAction Stop
        $word.Visible = $false
        
        $doc = $word.Documents.Add()
        
        # Add content
        $selection = $word.Selection
        $selection.Font.Name = "Consolas"
        $selection.Font.Size = 9
        $selection.TypeText($fullContent)
        
        # Save as PDF (17 = wdFormatPDF)
        $doc.SaveAs([ref]$pdfFile, [ref]17)
        $doc.Close([ref]$false)
        $word.Quit()
        
        # Cleanup COM objects
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($selection) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($doc) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
        
        Write-Host "✓ PDF created: $(Resolve-Path $pdfFile)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Could not create PDF (Microsoft Word required): $_"
        Write-Host "   You can manually 'Print to PDF' from the .txt file" -ForegroundColor Yellow
    }
}

Write-Host "`nDone! Exported $totalFiles files." -ForegroundColor Cyan