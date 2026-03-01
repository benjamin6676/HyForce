# ExportCode.ps1 - Export all .cs files to a single text file
# Run from PowerShell: .\ExportCode.ps1
# Or right-click → Run with PowerShell

param(
    [string]$OutputFile = "ProjectExport.txt",
    [string]$ProjectPath = $PSScriptRoot
)

# Change to project directory
Set-Location $ProjectPath

Write-Host "HyForce Project Exporter" -ForegroundColor Cyan
Write-Host "Project: $ProjectPath" -ForegroundColor Gray
Write-Host ""

# Remove old export if exists
if (Test-Path $OutputFile) {
    Remove-Item $OutputFile -Force
    Write-Host "Removed old export file" -ForegroundColor Yellow
}

# Get all .cs files (excluding build folders)
$files = Get-ChildItem -Path . -Recurse -Filter "*.cs" -File | 
    Where-Object { 
        $_.FullName -notmatch "\\(bin|obj|\.vs|packages|\.git|Exported logs)\\" -and
        $_.Name -ne $OutputFile
    } |
    Sort-Object FullName

Write-Host "Found $($files.Count) .cs files to export" -ForegroundColor Cyan

if ($files.Count -eq 0) {
    Write-Host "ERROR: No .cs files found!" -ForegroundColor Red
    Write-Host "Make sure you run this from the project root folder" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit
}

# Export each file
$exportedCount = 0
foreach ($file in $files) {
    try {
        $relativePath = $file.FullName.Substring((Get-Location).Path.Length + 1)
        
        # Write header
        Add-Content $OutputFile "===== FILE: $($file.FullName) ====="
        Add-Content $OutputFile ""
        
        # Write content
        $content = Get-Content $file.FullName -Raw -ErrorAction Stop
        Add-Content $OutputFile $content
        
        # Write footer spacing
        Add-Content $OutputFile ""
        Add-Content $OutputFile ""
        
        $exportedCount++
        Write-Host "  Exported: $relativePath" -ForegroundColor Green
    }
    catch {
        Write-Host "  ERROR: $($file.Name) - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Summary
Write-Host ""
Write-Host "Export Complete!" -ForegroundColor Green
Write-Host "Files exported: $exportedCount / $($files.Count)" -ForegroundColor White

if (Test-Path $OutputFile) {
    $fileInfo = Get-Item $OutputFile
    $sizeKB = [math]::Round($fileInfo.Length / 1KB, 2)
    Write-Host "Output: $($fileInfo.FullName)" -ForegroundColor Cyan
    Write-Host "Size: $sizeKB KB" -ForegroundColor Cyan
    
    # Copy to clipboard option
    Write-Host ""
    $copy = Read-Host "Copy to clipboard? (y/n)"
    if ($copy -eq 'y' -or $copy -eq 'Y') {
        try {
            $content = Get-Content $OutputFile -Raw
            Set-Clipboard $content
            Write-Host "Copied to clipboard!" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to copy: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host ""
Read-Host "Press Enter to exit"