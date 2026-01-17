<#
.SYNOPSIS
    Stable, low-glare PowerShell prompt for Windows Terminal with PSReadLine.

.DESCRIPTION
    EyeRelaxingPrompt.ps1 provides a minimal, eye-friendly PowerShell prompt
    optimized for long interactive sessions in Windows Terminal.

    The script deliberately prioritizes:
      - Visual stability over customization
      - Foreground-only coloring on a black background
      - Compatibility with PSReadLine, Git, Python, and ANSI tools
      - Correct prompt redraw behavior under continuation, history navigation,
        and Ctrl+C cancellation

    This script exists because many otherwise “simple” prompt customizations
    trigger redraw corruption, background inversion, or cursor misplacement in
    Windows Terminal when PSReadLine is enabled.

    All known unstable approaches are documented in the version history to
    prevent regressions and repeated experimentation.

.NON-GOALS
    This script intentionally does NOT attempt to:
      - Support non-black backgrounds
      - Override terminal color schemes
      - Provide rich glyphs, icons, or powerline segments
      - Suppress host-level Ctrl+C echo behavior
      - Work around terminal bugs with repeated ANSI resets

    If a feature compromises redraw stability, it is excluded.

.ENVIRONMENT
    - Windows Terminal
    - PowerShell 7.x
    - PSReadLine 2.3+
    - ANSI-emitting tools (Git, Python, etc.)

.VERSIONING POLICY
    Version numbers are only incremented when behavior materially changes.
    Minor experimental adjustments are recorded in the history without
    generating new minor versions.

.VERSION
    3.2
#>

<# ----------
** Version history (intentional and meaningful)
 3.2 - Incremental hardening (no version bumps)
   - PromptText synchronized exactly to prompt string
   - Continuation prompt padded to prompt width
   - Verified Ctrl+C redraw behavior as host-level
   Result: Eliminated prompt overwrite and cursor-shift artifacts.
 3.1 - Documentation and constraint formalization
   - Added detailed rationale and rejected-approach documentation
   - Codified “stability over novelty” design principle
   Result: Stable and maintainable.
 3.0 - First stable baseline
   - Black background
   - Soft gray foreground
   - Prompt returns plain string only
   - No background ANSI usage
   Result: Stable for daily use.
 2.x - PSReadLine interaction analysis
   Investigated PSReadLine color overrides, prediction features, history
   highlighting, and custom key handlers.
   Result: Learned that redraw stability depends on minimizing render layers
   and matching PSReadLine’s internal prompt width assumptions.
 1.x - Exploration phase (discarded approaches)
   Explored non-black backgrounds, RawUI enforcement, registry defaults,
   and ANSI background control.
   Result: All approaches caused redraw artifacts or background inversion
   under PSReadLine. Abandoned entirely.
#>


$global:EyeRelaxingPrompt_Version = '3.2'
Write-Host ("EyeRelaxingPrompt v{0} loaded (black background, native path prompt)." -f $global:EyeRelaxingPrompt_Version)

# --- PSReadLine + prompt hard fix (must be last) ---
Import-Module PSReadLine -ErrorAction SilentlyContinue

# Console foreground (soft gray, not pure white)
$host.UI.RawUI.ForegroundColor = 'Gray'
$host.UI.RawUI.BackgroundColor = 'Black'

<# ** Powershell 7.5.4 default color settings
    Availible colors in ASCII: Black, DarkBlue, DarkGreen, DarkCyan, DarkRed, DarkMagenta, DarkYellow, Gray, DarkGray, Blue, Green, Cyan, Red, Magenta, Yellow, White 
    CommandColor                           : "`e[93m", Yellow
    CommentColor                           : "`e[32m", DarkGreen
    ContinuationPromptColor                : "`e[37m", Gray
    DefaultTokenColor                      : "`e[37m", Gray
    EmphasisColor                          : "`e[96m", Cyan
    ErrorColor                             : "`e[91m", Red
    InlinePredictionColor                  : "`e[38;5;238m", DarkGray+Black (not very visible)
    KeywordColor                           : "`e[92m", Green
    ListPredictionColor                    : "`e[33m", DarkYellow
    ListPredictionSelectedColor            : "`e[48;5;238m"
    ListPredictionTooltipColor             : "`e[38;5;238m", DarkGray+Black (not very visible)
    MemberColor                            : "`e[37m", Gray
    NumberColor                            : "`e[97m", White
    OperatorColor                          : "`e[90m", (LessDarkGray)
    ParameterColor                         : "`e[90m", (LessDarkGray)
    SelectionColor                         : "`e[30;47m", (DarkGray+Gray aprox)
    StringColor                            : "`e[36m", DarkGreen
    TypeColor                              : "`e[37m", Gray
    VariableColor                          : "`e[92m", Green
#>

# PSReadLine colors (foreground-only, low contrast)
# Keep most default colors intact apart from prediction
Set-PSReadLineOption -Colors @{
    InlinePrediction   = "`e[90m"
    ListPredictionTooltip = "`e[90m"
}

# One-time PSReadLine init: make Ctrl+C cancel the edit buffer (do not emit ^C / do not propagate SIGINT)
if (Get-Module PSReadLine -ErrorAction SilentlyContinue) {
    if (-not $script:EyeRelaxingPrompt_PSReadLineInit) {
        Set-PSReadLineKeyHandler -Chord Ctrl+c -Function CancelLine
        $script:EyeRelaxingPrompt_PSReadLineInit = $true
    }
}

# Stable continuation prompt width (matches prompt length)
function global:prompt {
    $p = "PS $((Get-Location).Path)> "
    try {
        if (Get-Module PSReadLine -ErrorAction SilentlyContinue) {
            Set-PSReadLineOption -PromptText @($p, (' ' * $p.Length))
        }
    } catch {
    }
    $p
}
