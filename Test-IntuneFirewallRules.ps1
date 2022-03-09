<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

Test-IntuneFirewallRules.ps1

Utility for testing Intune Firewall Rules
Author: Mark Stanfill (markstan@microsoft.com)
Published:  1/21/2022
Last Updated: 3/4/2022
Version: 1.0

#>

####################################################

Param (
  [string]$PolicyName,
  [string]$PolicyID,
  [bool]$Debug = $false,
  # clean up test rules standalone option
  [switch]$DeleteTestFirewallRules,
  # process policies that are not assigned to a group in Intune
  [switch]$IncludeUnassignedPolicies,
  # bypass EULA check
  [switch]$AcceptEULA,
  # ingest JSON exported from EndpointSecurityPolicy_Export.ps1
  $RuleJSON

)

####################################################

#region Functions

####################################################

function Write-Log {
   
  <#
.SYNOPSIS
 Script-wide logging function
.DESCRIPTION
 Writes debug logging statements to script log file
.EXAMPLE
    Write-Log "Entering function"
    Write log entry with information level

.EXAMPLE
    Write-Log -Level Error -WriteStdOut "Error"
    Write error to log and also show in PowerShell output
 
.NOTES
NAME: Write-Log 

Set $global:LogName at the beginning of the script
#>

  [CmdletBinding()]
  param(
    [Parameter(ValueFromPipeline = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Message = "",

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('Information', 'Warning', 'Error', 'Verbose')]
    [string]$Level = 'Information',
      
    [Parameter()]
    [switch]$WriteStdOut,

    [Parameter()]
    # create log in format 
    [string]$LogName = $global:LogName
 
  )

  BEGIN {
    if ( ($null -eq $LogName) -or ($LogName -eq "")) { Write-Error "Please set variable `$global`:LogName." }
  }
  PROCESS {
    # only log verbose if flag is set
    if ( ($Level -eq "Verbose") -and ( -not ($debugMode) ) ) {
      # don't log events unless flag is set
    } else {
         
      [pscustomobject]@{
        Time    = (Get-Date -f u)   
        Line    = "`[$($MyInvocation.ScriptLineNumber)`]"          
        Level   = $Level
        Message = $Message
            
      } |  Export-Csv -Path $LogName -Append -Force -NoTypeInformation -Encoding Unicode

      if (  $WriteStdOut -or ( ($Level -eq "Verbose") -and $debugMode)) { Write-Output $Message }
    }
  }
  END {}
}

####################################################
 
function Test-IsEULAAccepted {
   
<#
.SYNOPSIS
 Show warning about firewall creation and how to remedy any artifacts left by the script 
.DESCRIPTION
 Informs admin of changes made to local device.  Prompts admin to acknowledged
.EXAMPLE
Test-IsEULAAccepted
 
.NOTES
NAME: Test-IsEULAAccepted

Bypass at script-level with Test-IntuneFirewallRules.ps1 -AcceptEULA
#>

  [string]$message =
@"  
Warning:  This script will create test firewall rules on the device it is ran on.  These rules are disabled and named with a `"____MSTestRule_DeleteMe____`" prefix.               
Rules will be automatically deleted when the script completes.
If there are any rules remaing (for instance, if the device reboots or the PowerShell window is closed while the script is running, run this command to delete remaining artifacts:
                                                                                                                                                                                  
Test-IntuneFirewallRules.ps1 -DeleteTestFirewallRules
"@

  [bool]$isEULAAccepted = $false

  if (  $AcceptEULA ) {
    $isEULAAccepted = $true
  }

  if ( $isEULAAccepted -eq $false) {
    Write-Host -Object $message -ForegroundColor "Black" -BackgroundColor Yellow
    Write-Host "`r`nType (Y)es to accept this warning and continue running this script:  " -NoNewline
    $accepted = Read-Host

    if ($accepted -in ("y", "yes", "yep") ) {
      $isEULAAccepted = $true
      "EULA accepted via command line: $accepted" | Write-Log
    } else {
      "EULA not accepted, exiting: $accepted" | Write-Log
    }

  } else {
    "EULA accepted via command line." | Write-Log
  }
  
  $isEULAAccepted
  
}

####################################################

function Get-SuggestedAction {
   
  <#
.SYNOPSIS
Parses rules for common regex patterns
.DESCRIPTION
Examines rule contents for common known issues - spaces in environmental variables, non-default variables, etc.
.EXAMPLE
Get-SuggestedAction
 
.NOTES
NAME: Get-SuggestedAction 
#>

  param (
    $ExceptionInfo,
    $DetectedPathIssues,
    $FilePath,
    $Port,
    $Protocol
  )

  [string]$Remediation = ""

  
  "Change $DetectedPathIssues to $fixedPath" | Write-Log  
  # String fix-up for reporting
  $ProblemDescription = $(($ExceptionInfo.Exception) | Out-String ) -replace "\r\n", ""

  switch -Wildcard  ( $ProblemDescription) {

    "The parameter is incorrect*" { 
        
      switch -Wildcard ($DetectedPathIssues) {
        "*space pattern*" { 
          $envVar = $FilePath -replace "(%.*%)(.*)", "`$1"
          $fixedString = $envVar -replace " ", ""
          $Remediation = "Remove spaces in the environmental variable in the rule's file path.`r`nChange $envVar to $fixedString in $FilePath."
        }
        "*Unterminated % *" {
          $UnterminatedEnvVar = $FilePath -replace "(%.*)(\\.*)", "`$1"
          $fixedString = $UnterminatedEnvVar + '%'
          $Remediation = "Add a '%' character to the environmental variable in the rule's file path.`r`nChange $UnterminatedEnvVar to $fixedString in $FilePath."
        }
        "Invalid system variable*" {
          $envVar = $FilePath -replace "(%.*%)(.*)", "`$1"
          $Remediation = "The environmental variable in file path $FilePath is not supported.  Only default environmental variables are supported.  Change $envVar to a fixed path."
        }
        "Leading spaces*" {
          $Remediation = "Remove all space characters before the first '%' character in file path `"$FilePath`"."
        }
           
      }
    }

    "The application contains invalid characters, or is an invalid length*" {

      $IllegalPathChars =  -join [System.IO.Path]::GetInvalidPathChars().Foreach{('\x{0:x2}' -f ([Byte][Char]$_))}    
      $IllegalFileChars = -join [System.IO.Path]::GetInvalidFileNameChars().Foreach{('\x{0:x2}' -f ([Byte][Char]$_))}    
      $IllegalPathRegex = "[$IllegalPathChars]"
      $IllegalFileRegex = "[$IllegalFileChars]"

      $null = $FilePath -match "^(?<Path>.*)\\(?<FileName>.*)$"
      $IllegalPathChars = [regex]::Matches($Matches['Path'],     $IllegalPathRegex, 'IgnoreCase').Value  
      $IllegalFileChars = [regex]::Matches($Matches['Filename'], $IllegalFileRegex, 'IgnoreCase').Value  

 
      $Remediation = "Verify that $Filepath is a legal Windows path."                                   
      if ($IllegalPathChars) { $Remediation += "  Illegal characters in path: `"$IllegalPathChars`"." }                                            
      if ($IllegalFileChars) { $Remediation += "  Illegal characters in file name: `"$IllegalFileChars`"." }
    }

    "The address range is invalid*" { $Remediation = "Fix address range in rule." }

    "The port is invalid*" {
  
        if ($null -eq $Protocol) {
          $Remediation = "'Any' protocol is specified with port(s) $Port.  Either change the protocol (typically to TCP or UDP) or remove the port number from the rule.  
                           If in doubt, delete the rule and recreate it manually."
        }
    }
    default { $Remediation = "Unable to detect fix.  Please try to create rule manually to troubleshoot." }

  }

  "REMEDIATION: $Remediation" | Write-Log
  $Remediation


}   

####################################################

# https://devblogs.microsoft.com/scripting/use-function-to-determine-elevation-of-powershell-console/
# Returns True if Admin, False if not
Function Test-IsAdmin {
   
<#
.SYNOPSIS
Determines if script is being ran in elevated (admin) context 
.DESCRIPTION
Required by script to create firewall rules
.EXAMPLE
Test-IsAdmin
 
.NOTES
NAME: Test-IsAdmin
#>

  # https://docs.microsoft.com/en-us/dotnet/api/system.security.principal.windowsbuiltinrole?view=net-6.0
  # BUILTIN\Administrators = 544
  Set-Variable ADMINISTRATORS -Option ReadOnly -Value 544
 
  ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent() `
      ).IsInRole($ADMINISTRATORS)
}

####################################################  

function Get-AuthToken {

  <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-AuthToken
    #>
    
  [cmdletbinding()]
    
  param
  (
    [Parameter(Mandatory = $true)]
    $User
  )
    
  $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    
  $tenant = $userUpn.Host
    
  Write-Host "Checking for AzureAD module..."
    
  $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    
  if ($null -eq $AadModule) {
    
    Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
    $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
  }
    
  if ($null -eq $AadModule) {
    Write-Host
    Write-Host "AzureAD Powershell module not installed..." -f Red
    Write-Host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
    Write-Host "Script can't continue..." -f Red
    Write-Host
    exit
  }
    
  # Getting path to ActiveDirectory Assemblies
  # If the module count is greater than 1 find the latest version
    
  if ($AadModule.count -gt 1) {
    
    $Latest_Version = ($AadModule | Select-Object version | Sort-Object)[-1]
    
    $aadModule = $AadModule | Where-Object { $_.version -eq $Latest_Version.version }
    
    # Checking if there are multiple versions of the same module found
    
    if ($AadModule.count -gt 1) {
    
      $aadModule = $AadModule | Select-Object -Unique
    
    }
    
    $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
  }
    
  else {
    
    $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
  }
    
  [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    
  [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
  $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    
  $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    
  $resourceAppIdURI = "https://graph.microsoft.com"
    
  $authority = "https://login.microsoftonline.com/$Tenant"
    
  try {
    
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    
    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    
    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
    
    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result
    
    if ($authResult.AccessToken) {
    
      # Creating header for Authorization token
    
      $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer " + $authResult.AccessToken
        'ExpiresOn'     = $authResult.ExpiresOn
      }
    
      return $authHeader
    
    }
    
    else {
    
      Write-Host
      Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
      Write-Host
      break
    
    }
    
  }
    
  catch {
    
    Write-Host $_.Exception.Message -f Red
    Write-Host $_.Exception.ItemName -f Red
    Write-Host
    break
    
  }
    
}
 

####################################################
 
function Get-LeafProperty {
   
  <#
.SYNOPSIS
Parses JSON objects
.DESCRIPTION
 Returns values given a KVP JSON object
.EXAMPLE
Get-LeafProperty 
 
.NOTES
NAME: Get- LeafProperty 
https://stackoverflow.com/questions/64187004/powershell-selecting-noteproperty-type-objects-from-object

#>

  param([Parameter(ValueFromPipeline)] [object] $InputObject, [string] $NamePath)
  process {   
    if ($null -eq $InputObject -or $InputObject -is [DbNull] -or $InputObject.GetType().IsPrimitive -or $InputObject.GetType() -in [string], [datetime], [datetimeoffset], [decimal], [bigint]) {
      # A null-like value or a primitive / quasi-primitive type -> output.
      # Note: Returning a 2-element ValueTuple would result in better performance, both time- and space-wise:
      #      [ValueTuple]::Create($NamePath, $InputObject)
      [pscustomobject] @{ NamePath = $NamePath; Value = $InputObject }
    } elseif ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [System.Collections.IDictionary]) {
      # A collection of sorts (other than a string or dictionary (hash table)), 
      # recurse on its elements.
      $i = 0
      foreach ($o in $InputObject) { Get-LeafProperty $o ($NamePath + '[' + $i++ + ']') }
    } else { 
      # A non-quasi-primitive scalar object or a dictionary:
      # enumerate its properties / entries.
      $props = if ($InputObject -is [System.Collections.IDictionary]) { $InputObject.GetEnumerator() } else { $InputObject.psobject.properties }
      $sep = '.' * ($NamePath -ne '')
      foreach ($p in $props) {
        Get-LeafProperty $p.Value ($NamePath + $sep + $p.Name)
      }
    }
  }
}

####################################################

function Write-BadRule {
   
  <#
.SYNOPSIS
 Records rules in error
.DESCRIPTION
 Given a firewall rule, creates a reporting string based on known patterns and exceptions reported by the Defender service
.EXAMPLE
Write-BadRule
 
.NOTES
NAME: Write-BadRule 
#>

  param(
    $FWRule,
    $ExceptionInfo = "",
    $DetectedPathIssues = " ",
    $PolicyName = "Unknown",
    $SuggestedFix
  )
 
  $ExceptionType = "Unknown"
  if ($ExceptionInfo) { $ExceptionType = $ExceptionInfo }
  $pathIssuesString = $DetectedPathIssues | Out-String
 
  $newReport = New-RuleCheckResult -FWRuleName $FWRule.DisplayName  -result "Failed" -Exception $ExceptionType -PatternsDetected  $pathIssuesString -PolicyName $PolicyName -SuggestedFix $SuggestedFix
  $global:detectedErrors += $newReport
}

####################################################

function New-RuleCheckResult {
   
  <#
.SYNOPSIS
 Helper function to return a formatted rule output object
.DESCRIPTION
 Returns a rule result object for reporting
.EXAMPLE
New-RuleCheckResult
 
.NOTES
NAME: New-RuleCheckResult
#>

  [CmdletBinding()]
  param(
    [string] [Parameter(Mandatory = $true)] $FWRuleName, 
    [string] $Exception,
    [string] [ValidateSet("Passed", "Warning", "Failed", "Information")] $result,
    [string] $PatternsDetected,
    [string] $PolicyName = "Unknown",
    $SuggestedFix
  )
  
  
  $RuleResult = [PSCustomObject] [Ordered] @{
    'Policy name'        = $PolicyName
    'Firewall Rule Name' = $FWRuleName
    'Exception'          = $Exception
    'Test Result'        = $result
    'Patterns Detected'  = $PatternsDetected
    'Suggested fix'      = $SuggestedFix
  }
  return $RuleResult
}
    
####################################################

function New-HTMLReport {
   
  <#
.SYNOPSIS
 Generates HTML report
.DESCRIPTION
 Creates HTML output based on rule results
.EXAMPLE
New-HTMLReport 
 
.NOTES
NAME: New-HTMLReport 
#>

  Param ($resultBlob) 
  
  $head = @'
<style>
body { background-color:#ffffff;
       font-family:Tahoma;
       font-size:12pt; }
table {
  border-spacing: 0;
  width: 100%;
  border: 1px solid #ddd;
  margin: auto;
}
th {
  background-color: #6495ED;
  cursor: pointer;
}
th, td {
  border: 1px solid #ddd;
  text-align: left;
  padding: 10px;
}
td.green { color: green; }
td.orange { color: orange; }
td.red { color: red; }
.active { 
  color: #efefef;
  font-style: italic;
}
.filterList {
  border: 1px solid #ddd;
  display: inline-block;
  margin: 4px 0px;
  padding: 8px;
}
.filterList h4 {
  margin: 0px 2px;
}
</style>
'@

  $preContent = @'
<h1>Firewall rules with errors</h1>
 
'@

  $script = @'
<script>
window.onload = function() {
  if (document.querySelectorAll('tr th').length != 0) {
    const headings = document.querySelectorAll('tr th');
    const col = Array.from(headings).find(hd => hd.innerHTML === "Test Result");
    const inx = Array.from(col.parentNode.children).indexOf(col);
    const cells = col.closest('table').querySelectorAll(`td:nth-child(${inx+1})`);
  }
else {
  var table = document.querySelector('table');
      var tableRow = table.insertRow(-1);
      tableRow.innerHTML = "<td bgcolor=#6495ed>No errors detected in firewall rules.</td>";
}
  

    Array.from(cells).map((td) => {
        switch (td.innerHTML) {
            case "Passed":
                td.classList.add("green")
                break
            case "Warning":
                td.classList.add("orange")
                break
            case "Failed":
                td.classList.add("red")
                break
        }
    })
    
    Array.from(headings).map((hd) => {
      hd.addEventListener('click', (e) => {
        sortTable(e.target.cellIndex)
        activeColumn(e)
      })
    })
     
}

function activeColumn(e) {
  const headings = document.querySelectorAll('tr th')
  const col = Array.from(headings).map(hd => hd.classList.remove('active'))
  e.target.classList.add('active')
}

function sortTable(n) {
  var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
  table = document.querySelector('table')
  switching = true;
  //Set the sorting direction to ascending:
  dir = "asc"; 
  /*Make a loop that will continue until
  no switching has been done:*/
  while (switching) {
    //start by saying: no switching is done:
    switching = false;
    rows = table.rows;
    /*Loop through all table rows (except the
    first, which contains table headers):*/
    for (i = 1; i < (rows.length - 1); i++) {
      //start by saying there should be no switching:
      shouldSwitch = false;
      /*Get the two elements you want to compare,
      one from current row and one from the next:*/
      x = rows[i].getElementsByTagName("TD")[n];
      y = rows[i + 1].getElementsByTagName("TD")[n];
      /*check if the two rows should switch place,
      based on the direction, asc or desc:*/
      if (dir == "asc") {
        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
          //if so, mark as a switch and break the loop:
          shouldSwitch= true;
          break;
        }
      } else if (dir == "desc") {
        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
          //if so, mark as a switch and break the loop:
          shouldSwitch = true;
          break;
        }
      }
    }
    if (shouldSwitch) {
      /*If a switch has been marked, make the switch
      and mark that a switch has been done:*/
      rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
      switching = true;
      //Each time a switch is done, increase this count by 1:
      switchcount ++;      
    } else {
      /*If no switching has been done AND the direction is "asc",
      set the direction to "desc" and run the while loop again.*/
      if (switchcount == 0 && dir == "asc") {
        dir = "desc";
        switching = true;
      }
    }
  }
}

function filterTable() {

  const checkboxes = document.querySelectorAll('input[name="filter"]:checked')
  const table = document.querySelector('table')
  const headings = table.querySelectorAll('tr th')
  const col = Array.from(headings).find(hd => hd.innerHTML === "Test Result")
  const inx = Array.from(col.parentNode.children).indexOf(col)
  const trs = table.querySelectorAll('tr')

  const filters = Array.from(checkboxes).map(chbx => chbx.value )

  if (filters.length === 0) {
    resetTableRows(trs)
  }
  else {
    Array.from(trs).map((tr) => {
      let td = tr.querySelectorAll('td')[inx]
      if (td) {
        if (filters.includes(td.innerHTML.toLowerCase())) {
          // display row
          tr.style.display = ""
        }
        else {
          // hide row
          tr.style.display = "none"
        }
      }
    })
  }

}

function resetTableRows(trs) {
  // reset rows for all to display
  Array.from(trs).map((tr) => {
    tr.style.display = ""
  })
}
</script>
'@
  $html = $resultBlob | ConvertTo-Html -Head $head -Body $script -PreContent $preContent
  $now = (Get-Date).ToString("ddMMyyyyhhmmss")
  $HTMLFileName = Join-Path $env:temp "FirewallRuleTests-$now.html"
  $html | Out-File -FilePath $HTMLFileName -Force
  $HTMLFileName

}
 
####################################################
 
function Test-FirewallRuleCreatesSuccessfully {
   
  <#
.SYNOPSIS
 Creates a disabled firewall rule given JSON definition of a FW rule
.DESCRIPTION
 Return a command line for the New-NetFirewallRule cmdlet based on JSON data
.EXAMPLE
Test-FirewallRuleCreatesSuccessfully
 
.NOTES
NAME: Test-FirewallRuleCreatesSuccessfully 
#>

  param( $FWRuleToCreate,
    $DetectedPathIssues,
    $PolicyName = "Unknown" )

  # support both object and JSON formats
  if ($FWRuleToCreate.GetType().Name -eq "String") {
    $FWRuleToCreate = $FWRuleToCreate | ConvertFrom-Json
  }

  # Get the list of populated properties to create the test rule from
  $PopulatedProperties = $FWRuleToCreate | Get-LeafProperty | Where-Object { ("" -ne $_.Value) -and ($null -ne $_.Value) }
  $ConstructedCommandLineArgs = @{}
  # for logging
  $tabs = "`t" * 3
  $stars = '*' * 80
  $pluses = '+' * 80
  # always create the rule disabled so that we don't inadvertantly block traffic
  $enabled = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::False
  $testString = "____MSTestRule_DeleteMe____"
  $errMsg = ""
    
  # hash of object properties to match against the corresponding Net-NetFirewallRule command line switches
  $PropertyToSwitchMapping = @{
    displayName             = "DisplayName"
    description             = "Description"
    trafficDirection        = "Direction"
    action                  = "Action" 
    packageFamilyName       = "Package"
    filePath                = "Program"
    serviceName             = "Service" 
    protocol                = "Protocol"
    localUserAuthorizations = "LocalUser"
      
  }
    
  foreach ($PopulatedProperty in $PopulatedProperties) {
    $CommandLineSwitch = $PopulatedProperty.NamePath
    "$CommandLineSwitch" | Out-String | Write-Log
    $argument = $PopulatedProperty.Value

    if ($argument -eq "notConfigured") {
      "Skipping notConfigured value $CommandLineSwitch" | Write-Log
    } 
    else {
      
      switch -Wildcard ($CommandLineSwitch) {
        'useAnyLocalAddressRange' { 
          $useAnyLocalAddressRange = $ConstructedCommandLineArgs[$CommandLineSwitch]
          "$useAnyLocalAddressRange " | Write-Log
      
           
          if ( ($null -eq $useAnyLocalAddressRange) -or ($useAnyLocalAddressRange -eq "") ) {
            "Skipping empty value for useAnyLocalAddressRange" | Write-Log -Level Verbose
          } else {
            $ConstructedCommandLineArgs['LocalAddress'] = "Any"
          }

        }   
        'useAnyRemoteAddressRange' {
          $useAnyRemoteAddressRange = $ConstructedCommandLineArgs[$CommandLineSwitch]
          "$useAnyRemoteAddressRange " | Write-Log
      
           
          if ( ($null -eq $useAnyRemoteAddressRange) -or ($useAnyRemoteAddressRange -eq "") ) {
            "Skipping empty value for useAnyRemoteAddressRange" | Write-Log -Level Verbose
          } else {
            $ConstructedCommandLineArgs['RemoteAddress'] = "Any"
          }

        }
        'DisplayName' {
          # create unique display names so we don't duplicate existing rules
         
          [string]$testName = $testString + $argument
          $ConstructedCommandLineArgs['DisplayName'] = $testname 
        }
        "actualRemoteAddressRanges*" {
           
          $ipRanges = $FWRuleToCreate.actualremoteaddressranges
          $ipAddressRanges = @()

          foreach ($ipRange in $ipRanges) {
            $ipAddressRanges += $ipRange
          } 
          $ConstructedCommandLineArgs['RemoteAddress'] = $ipAddressRanges
        }          
        'actualLocalAddressRanges*' {
            
          $ipRanges = $FWRuleToCreate.actualLocaladdressranges
          $ipAddressRanges = @()

          foreach ($ipRange in $ipRanges) {
            $ipAddressRanges += $ipRange
          } 

          foreach ($ipRange in $ipRanges) {
            $ConstructedCommandLineArgs['LocalAddress'] = $ipAddressRanges
          } 
        }
        'profileTypes*' {

          $ProfileTypes = $FWRuleToCreate.profileTypes
          $profileEnum = @()

          foreach ($ProfileType in $ProfileTypes) { 
            switch ($ProfileType) {
              "Domain" { $profileEnum += [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]::Domain }
              "Private" { $profileEnum += [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]::Private }
              "Public" { $profileEnum += [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]::Public }
              "NotApplicable" { $profileEnum += [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]::NotApplicable }
            } 
          } 
          $ConstructedCommandLineArgs['Profile'] = $ProfileEnum

        } 
        'action' {

          $Actions = $FWRuleToCreate.Action
          $ActionsEnum = ""

          foreach ($Action in $Actions) { 
            "Action:  $action" | Write-Log  
            switch ($Action) {
              "NotConfigured" { $ActionsEnum = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action]::NotConfigured }
              "Allowed" { $ActionsEnum = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action]::Allow }
              "Blocked" { $ActionsEnum = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action]::Block }
                
            } 
          } 
          $ConstructedCommandLineArgs['Action'] = $ActionsEnum

        } 
        'interfaceTypes*' {
          $interfaceTypes = $FWRuleToCreate.interfaceTypes
          $interfaceTypeEnum = @()

          foreach ($interfaceType in $interfaceTypes) { 
            "interfaceType:  $interfaceType" | Write-Log -WriteStdOut
                switch ($interfaceType) {
                    "Any" { $interfaceTypeEnum += [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.InterfaceType]::Any }
                    "Lan"  { $interfaceTypeEnum += [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.InterfaceType]::Wired }  
                    "wireless"  { $interfaceTypeEnum += [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.InterfaceType]::Wireless }  
                    "remoteAccess" { $interfaceTypeEnum += [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.InterfaceType]::RemoteAccess }  
                 }
                
          } 
            
          $ConstructedCommandLineArgs['interfaceType'] = $interfaceTypeEnum

        }
        '*PortRanges*' {
          # either localPortRanges or   remotePortRanges   
          # Name fixup from Get-LeafProperty data
          $localRemoteCommandLineSwitch = $CommandLineSwitch -replace "\[\d+\]$", ""
          "Port range rule $localRemoteCommandLineSwitch"  | Write-Log -WriteStdOut
          $PortRangesTypes = $FWRuleToCreate.$localRemoteCommandLineSwitch
          $PortRangesEnum = @()

          foreach ($PortRange in $PortRangesTypes) { 
            "PortRanges:  $PortRange" | Write-Log  
            $PortRangesEnum += $PortRange 
          }
         
            
          $PortCmdArg = $localRemoteCommandLineSwitch -replace "(.+)Ranges.*", "`$1"
          $ConstructedCommandLineArgs[$PortCmdArg] = $PortRangesEnum

        }
     
        Default {
          if ("" -eq $CommandLineSwitch){
            "Skipping null value for command line switch" | Write-Log
          }
          else {
              $hashValue = $PropertyToSwitchMapping[$CommandLineSwitch] 
              if ($hashValue){
                $ConstructedCommandLineArgs[$hashValue] = $argument
              }
              else {
                write-host "unknown mapping $CommandLineSwitch"
              }
              
          }
          
      
 
        }
      }
    }
  }

 
  # string interpolation for logging
  $nnfwrule = ($ConstructedCommandLineArgs | Format-List   | Out-String) -replace "(\r\n)+", " "  
  $nnfwrule = $nnfwrule -replace "Value\s+:\s+", "" 
  $nnfwrule = $nnfwrule -replace "Name  : ", "-" 
    
  "Running command (spaces will be quoted):`r`n`r`n$tabs New-NetFirewallRule $nnfwrule -Enabled $enabled`r`n"  | Write-Log
  try {
    $dispName = $ConstructedCommandLineArgs["displayName"] -replace $testString, ""
    $null = New-NetFirewallRule  @ConstructedCommandLineArgs -Enabled $enabled -ErrorAction "Stop"
    "`r`n$tabs$pluses`r`n$tabs Successfully created rule. Name: $dispName`r`n`r`n" | Write-Log
 
       
  } catch {
    [string]$Remediation = ""
    $errMsg = $error[0] 
    "`r`n$tabs$stars`r`n`r`n$tabs Exception creating rule. Name: $dispName`: $errMsg`r`n`r`n$tabs$stars`r`n" | Write-Log -WriteStdOut
    $Remediation = Get-SuggestedAction -ExceptionInfo  $errMsg -DetectedPathIssues $DetectedPathIssues -FilePath $ConstructedCommandLineArgs.program          `
            -Port  ( ($ConstructedCommandLineArgs.localPort) + ($ConstructedCommandLineArgs.RemotePort)) -Protocol $ConstructedCommandLineArgs.protocol
    Write-BadRule -FWRule $FWRuleToCreate -ExceptionInfo  $errMsg -DetectedPathIssues $DetectedPathIssues -PolicyName $PolicyName -SuggestedFix $Remediation
  } finally {
    # Catch condition where rule creates successfully but have detected a bad path
    if ( ($errMsg -eq "") -and ($DetectedPathIssues.count -gt 0) ) {
      [string]$Remediation = ""
      "Bad path regex found in $dispName" | Write-Log -Level Warning
      $DetectedPathIssues | Write-Log -Level Warning
      $Remediation = Get-SuggestedAction -ExceptionInfo  $errMsg -DetectedPathIssues $DetectedPathIssues -FilePath $ConstructedCommandLineArgs.program       `
               -Port  ( ($ConstructedCommandLineArgs.localPort) + ($ConstructedCommandLineArgs.RemotePort)) -Protocol $ConstructedCommandLineArgs.protocol
      Write-BadRule -FWRule $FWRuleToCreate -ExceptionInfo  $errMsg -DetectedPathIssues $DetectedPathIssues -PolicyName $PolicyName -SuggestedFix $Remediation
    }
  }
 
 
  
}

####################################################
				  

function Remove-TestFirewallRules {
   
  <#
.SYNOPSIS
 Cleans up test firewall rules created during rule creation
.DESCRIPTION
 Deletes firewall rules named "*____MSTestRule_DeleteMe____*" 
.EXAMPLE
Remove-TestFirewallRules 
 
.NOTES
NAME: Remove-TestFirewallRules 
#>

  $allLocalFWRules = Get-NetFirewallRule
  $testString = "____MSTestRule_DeleteMe____" 

  foreach ($localFWRule in $allLocalFWRules) {
     
    if ($localFWRule.displayName -match $testString) {
      try {
        "Deleting rule $($localFWRule.displayName)" | Write-Log -WriteStdOut
        Remove-NetFirewallRule -id $localFWRule.id  
        "Rule successfully deleted." | Write-Log -WriteStdOut
      } catch {
        "Unable to remove rule $($localFWRule.DispalayName).  Please delete manually" | Write-Log -WriteStdOut
        continue
      }
    }
  }



}

####################################################

Function Test-Rule {
   
  <#
.SYNOPSIS
 Tests firewall rules based on JSON to determine if the rule will succesfully create on managed devices
.DESCRIPTION
 Parses firewall rule, detects common issues, reports exceptions when creating disabled version of rule on local device
.EXAMPLE
Test-Rule
 
.NOTES
NAME: Test-Rule 
#>

  param(
    $ruleJSON,
    $PolicyName = "Unknown"
  ) 
  
  # support both parsed and unparsed versions of data
  if ($ruleJSON.GetType().Name -eq "String") {
    $parsedJSON = $ruleJSON  | ConvertFrom-Json
  }
  else {
    $parsedJSON = $ruleJSON  
  }
 
  $parsedJSON | Write-Log
  # Begin section rules
  $EnvVar_with_Space_Pattern = "%\w+\s+\w+.*%"
  # string starting with % followed by any number of chars except %, followed by a \
  $EnvVar_without_Closure = "^%([^%])*\\(.*)"
  $EnvVar_With_Leading_Spaces = "^\s+%.*"
  $defaultEnvVars = @("ALLUSERSPROFILE", "APPDATA", "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(x86)", "CommonProgramW6432", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", `
      "PATH", "PathExt", "PROGRAMDATA", "PROGRAMFILES", "ProgramW6432", "PROGRAMFILES(X86)", "SystemDrive", "SystemRoot", "TEMP", "TMP", "USERNAME", `
      "USERPROFILE", "WINDIR", "PUBLIC", "PSModulePath", "OneDrive", "DriverData" )
    
  $filepath = $parsedJSON.filePath
  $displayName = $parsedJSON.displayName
  $DetectedPathIssues = @()
  

 
  # first check regexs on file path - this is the most common issue
  "Evaluating rule $displayName" | Write-Log -WriteStdOut
  # validate that any env. vars are in the default list
  if ( $filepath -match "%(\w+)%.*" ) {
    if ($Matches[1] -in $defaultEnvVars) {
      "Correctly formatted system variable found $($Matches[0])in rule $displayName." | Write-Log
    } else {
      $msg = "Invalid system variable $($Matches[0]) in path $filepath found in rule $displayName"
      $msg | Write-Log -Level Error
      $DetectedPathIssues += $msg
    }
  }
  # check for patterns like "%program files%" or "%Program Files (x86)"
  elseif ($filepath -match $EnvVar_with_Space_Pattern ) {
    $msg = "Environmental variable with space pattern detected in $filepath in rule $displayName"            
    $msg | Write-Log -Level Error
    $DetectedPathIssues += $msg
  }
  # check for paths like %windir\ without a trailing '%'
  elseif ($filepath -match $EnvVar_without_Closure ) {
    $msg = "Unterminated % pattern detected in $filepath in rule $displayName" 
    $msg | Write-Log -Level Error
    $DetectedPathIssues += $msg
  } 
  # check for paths like %windir\ without a trailing '%'
  elseif ($filepath -match $EnvVar_With_Leading_Spaces ) {
    $msg = "Leading spaces detected in $filepath in rule $displayName" 
    $msg | Write-Log -Level Error
    $DetectedPathIssues += $msg
  } 

  Test-FirewallRuleCreatesSuccessfully -FWRuleToCreate $ruleJSON -DetectedPathIssues $DetectedPathIssues -PolicyName $PolicyName
    
 
}

#################################################### 
 
Function Test-JSON() {

  <#
  .SYNOPSIS
  This function is used to test if the JSON passed to a REST Post request is valid
  .DESCRIPTION
  The function tests if the JSON passed to the REST Post is valid
  .EXAMPLE
  Test-JSON -JSON $JSON
  Test if the JSON is valid before calling the Graph REST interface
  .NOTES
  NAME: Test-JSON
  #>
  
  param ($JSON)
  
  $validJson = $false
  
  try {
    $null = ConvertFrom-Json $JSON -ErrorAction Stop
    $validJson = $true  
  }

  catch {  
    $validJson = $false
    $_.Exception  
  }

  $validJson

}

####################################################

Function Get-EndpointSecurityPolicy(){

<#
.SYNOPSIS
This function is used to get all Endpoint Security policies using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets all Endpoint Security templates
.EXAMPLE
Get-EndpointSecurityPolicy
Gets all Endpoint Security Policies in Endpoint Manager
.NOTES
NAME: Get-EndpointSecurityPolicy
#>


$graphApiVersion = "Beta"
$ESP_resource = "deviceManagement/intents"

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
        (Invoke-RestMethod -Method Get -Uri $uri -Headers $authToken).value

    }
    
    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Get-EndpointSecurityTemplate(){

  <#
  .SYNOPSIS
  This function is used to get all Endpoint Security templates using the Graph API REST interface
  .DESCRIPTION
  The function connects to the Graph API Interface and gets all Endpoint Security templates
  .EXAMPLE
  Get-EndpointSecurityTemplate 
  Gets all Endpoint Security Templates in Endpoint Manager
  .NOTES
  NAME: Get-EndpointSecurityTemplate
  #>
  
  
  $graphApiVersion = "Beta"
  $ESP_resource = "deviceManagement/templates?`$filter=(isof(%27microsoft.graph.securityBaselineTemplate%27))"
  
      try {
  
          $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
          (Invoke-RestMethod -Method Get -Uri $uri -Headers $authToken).value
  
      }
      
      catch {
  
      $ex = $_.Exception
      $errorResponse = $ex.Response.GetResponseStream()
      $reader = New-Object System.IO.StreamReader($errorResponse)
      $reader.BaseStream.Position = 0
      $reader.DiscardBufferedData()
      $responseBody = $reader.ReadToEnd();
      Write-Host "Response content:`n$responseBody" -f Red
      Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
      write-host
      break
  
      }
  
  }

####################################################

Function Get-EndpointSecurityTemplateCategory(){

<#
.SYNOPSIS
This function is used to get all Endpoint Security categories from a specific template using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets all template categories
.EXAMPLE
Get-EndpointSecurityTemplateCategory -TemplateId $templateId
Gets an Endpoint Security Categories from a specific template in Endpoint Manager
.NOTES
NAME: Get-EndpointSecurityTemplateCategory
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $TemplateId
)

$graphApiVersion = "Beta"
$ESP_resource = "deviceManagement/templates/$TemplateId/categories"

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
        (Invoke-RestMethod -Method Get -Uri $uri -Headers $authToken).value

    }
    
    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Get-EndpointSecurityCategorySetting(){

<#
.SYNOPSIS
This function is used to get an Endpoint Security category setting from a specific policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a policy category setting
.EXAMPLE
Get-EndpointSecurityCategorySetting -PolicyId $policyId -categoryId $categoryId
Gets an Endpoint Security Categories from a specific template in Endpoint Manager
.NOTES
NAME: Get-EndpointSecurityCategory
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $PolicyId,
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $categoryId
)

$graphApiVersion = "Beta"
$ESP_resource = "deviceManagement/intents/$policyId/categories/$categoryId/settings?`$expand=Microsoft.Graph.DeviceManagementComplexSettingInstance/Value"

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
        (Invoke-RestMethod -Method Get -Uri $uri -Headers $authToken).value

    }
    
    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Export-JSONData(){

<#
.SYNOPSIS
This function is used to export JSON data returned from Graph
.DESCRIPTION
This function is used to export JSON data returned from Graph
.EXAMPLE
Export-JSONData -JSON $JSON
Export the JSON inputted on the function
.NOTES
NAME: Export-JSONData
#>

param (

$JSON,
$ExportPath

)

    try {

        if ( -not (Test-Path $ExportPath)){

            "Creating tempory folder $exportPath" | Write-Log
            mkdir $ExportPath -Force | Out-Null
        
        }

        if($JSON -eq "" -or $null -eq $JSON){

            write-host "No JSON specified, please specify valid JSON..." -f Red

        }

        elseif(!$ExportPath){

            write-host "No export path parameter set, please provide a path to export the file" -f Red

        }

        elseif(!(Test-Path $ExportPath)){

            write-host "$ExportPath doesn't exist, can't export JSON Data" -f Red

        }

        else {

        $JSON1 = ConvertTo-Json $JSON -Depth 5

        $JSON_Convert = $JSON1 | ConvertFrom-Json

        $displayName = $JSON_Convert.displayName

        # Updating display name to follow file naming conventions - https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx
        $DisplayName = $DisplayName -replace '\<|\>|:|"|/|\\|\||\?|\*', "_"

            # Added milliseconds to date format due to duplicate policy name
            $FileName_JSON = "$DisplayName" + "_" + $(get-date -f dd-MM-yyyy-H-mm-ss.fff) + ".json"

            "Export Path: $ExportPath" | Write-Log  

            $JSON1 | Set-Content -LiteralPath "$ExportPath\$FileName_JSON"
            "JSON created in $ExportPath\$FileName_JSON" | Write-Log  
            
        }

    }

    catch {

    $_.Exception

    }

}

#################################################### 

Function Export-Templates {

  <#
  .SYNOPSIS
  Exports rules from Graph API
  .DESCRIPTION
  This function is used to export JSON data returned from Graph.  Returns an list of generated files.
  .EXAMPLE
  Export-Templates 
  .NOTES
  NAME: Export-Templates 
  #>
  param($exportFolder)
    
  # Get all Endpoint Security Templates
  $Templates = Get-EndpointSecurityTemplate

  ####################################################

  # Get all Endpoint Security Policies configured
  $ESPolicies = Get-EndpointSecurityPolicy | Sort-Object displayName

  ####################################################

  # Looping through all policies configured
  foreach($policy in $ESPolicies){

      
      $PolicyName = $policy.displayName
      $PolicyDescription = $policy.description
      $policyId = $policy.id
      $TemplateId = $policy.templateId
      $roleScopeTagIds = $policy.roleScopeTagIds

      "Endpoint Security Policy: $PolicyName" |  Write-Log -WriteStdOut 
      $ES_Template = $Templates | Where-Object  { $_.id -eq $policy.templateId }

      $TemplateDisplayName = $ES_Template.displayName
      $TemplateId = $ES_Template.id
      $versionInfo = $ES_Template.versionInfo

      if($TemplateDisplayName -eq "Endpoint detection and response"){

        "Export of 'Endpoint detection and response' policy not included in sample script..."  |  Write-Log -WriteStdOut         
      }

      else {

          ####################################################

          # Creating object for JSON output
          $JSON = New-Object -TypeName PSObject

          Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'displayName' -Value "$PolicyName"
          Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'description' -Value "$PolicyDescription"
          Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'roleScopeTagIds' -Value $roleScopeTagIds
          Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'TemplateDisplayName' -Value "$TemplateDisplayName"
          Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'TemplateId' -Value "$TemplateId"
          Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'versionInfo' -Value "$versionInfo"

          ####################################################

          # Getting all categories in specified Endpoint Security Template
          $Categories = Get-EndpointSecurityTemplateCategory -TemplateId $TemplateId

          # Looping through all categories within the Template

          foreach($category in $Categories){

              $categoryId = $category.id

              $Settings += Get-EndpointSecurityCategorySetting -PolicyId $policyId -categoryId $categoryId
          
          }

          # Adding All settings to settingsDelta ready for JSON export
          Add-Member -InputObject $JSON -MemberType 'NoteProperty' -Name 'settingsDelta' -Value @($Settings)

          ####################################################

          Export-JSONData -JSON $JSON -ExportPath $exportFolder
 
          # Clearing up variables so previous data isn't exported in each policy
          Clear-Variable JSON
          Clear-Variable Settings

      }

    }   

}

#################################################### 

function Test-RulesFromJSONFiles {
  
  <#
  .SYNOPSIS
  Iterate through JSON files 
  .DESCRIPTION
  Evaluates JSON files and tests individual rules
  .EXAMPLE
  Test-RulesFromJSONFiles
  .NOTES
  NAME: Test-RulesFromJSONFiles
  #>
  foreach ($Rule in $RuleJSON){
    $line               | Write-Log -WriteStdOut
    "Processing $rule"  | Write-Log -WriteStdOut
    $line               | Write-Log -WriteStdOut
    " "                 | Write-Log -WriteStdOut
    # taking out -Raw for compat
    try {
      $JSONfromFile = (Get-Content -Path $Rule )  | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
      "Error reading $rule.  Skipping file" | Write-Log -WriteStdOut
      
    }
    
    # make sure JSON is valid before attempting to parse rules
    $isJSONValidated = $false
    if ($JSONfromFile) {
        $isJSONValidated = Test-JSON -JSON $JSONfromFile.settingsDelta.valueJson
      }

    if ( $isJSONValidated) {
      "JSON in $Rule is valid." | Write-Log  
      $Rules = $JSONfromFile.settingsDelta.valueJson  
      $firewallPolicyName = $JSONfromFile.displayName
      $templateID = $JSONfromFile.TemplateId

      # special case for security baseline templates.  These contain policies, but no rules
      # Example: MDM Security Baseline for Windows 10 and later for Decemeber 2020
      if ($templateID -ne "4356d05c-a4ab-4a07-9ece-739f7c792910") {
        "$rule is not Firewall Rules template.  Skipping" | Write-Log  -WriteStdOut
      }
      else {
        foreach ($Rule in $Rules) {
          # skip config settings, only process JSON rules in the format [{.*}]
          if ($Rule -match "\[\{.*\}\]") {
              $IndividualFWRuleJSONs = $Rule | ConvertFrom-Json
              foreach ($IndividualFWRuleJSON in $IndividualFWRuleJSONs) {
                Test-Rule -ruleJSON $IndividualFWRuleJSON -PolicyName $firewallPolicyName
            }
          }
        }
  

    }


    } 
  else {
      "Error in JSON, exiting" | Write-Log -WriteStdOut
    }
}
}

####################################################

function Test-IsUserAuthenticated {
<#
.SYNOPSIS
Test to see if user is authenticated to Graph API
.DESCRIPTION
Check if user is authenticated.  If not, prompt for credentials
.EXAMPLE
Test-IsUserAuthenticated
 
.NOTES
NAME: Test-IsUserAuthenticated
#> 


  # Checking if authToken exists before running authentication
  if ($global:authToken) {

  # Setting DateTime to Universal time to work in all timezones
  $DateTime = (Get-Date).ToUniversalTime()

  # If the authToken exists checking when it expires
  $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

  if ($TokenExpires -le 0) {

    Write-Host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
    Write-Host

    # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

    if (($null -eq $User) -or ($User -eq "")) {

      $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
      Write-Host

    }

    $global:authToken = Get-AuthToken -User $User

  }
    }

    # Authentication doesn't exist, calling Get-AuthToken function

                            else {
  if ( ($null -eq $User) -or ($User -eq "")) {

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host
  }

  # Getting the authorization token
  $global:authToken = Get-AuthToken -User $User

    }

}

####################################################

#endregion functions

####################################################

#region Main

####################################################
#
#  Main

$ErrorActionPreference = "Stop"
# set to true for verbose logging
$global:debugMode = $Debug
$line = "=" * 120

# validate that user is local admin running elevate for firewall rule creation
if (-not (Test-IsAdmin)){

      Return "Please run PowerShell elevated (run as administrator) and run the script again."
      Break
    
} 

####################################################
 
# Debug log for engineering
$global:LogName = Join-Path -Path $env:temp -ChildPath $("Test-IntuneFirewallRules_$((Get-Date -Format u) -replace "[\s:]","_").log")

# Error log with any imported rules that fail to create local rules
$global:ErrorLogName = Join-Path -Path $env:temp -ChildPath  $("Test-IntuneFirewallRules_Errors_$((Get-Date -Format u) -replace "[\s:]","_").log")

# reporting object
$global:detectedErrors = @() 

# Log settings for reference, also loads assembly
Get-NetFirewallSetting | Write-Log

Write-Log -WriteStdOut "`r`n$line`r`nStarting firewall policy evaluation `r`n$line`r`n"  -LogName $global:LogName  

# Special mode to clean up orphaned rules created by previous runs
if ($DeleteTestFirewallRules){
															 
    "Removing test firewall rules..." | Write-Log -WriteStdOut
    Remove-TestFirewallRules
    break

}

if (-not (Test-IsEULAAccepted) ){

    "EULA not accepted, exiting." | Write-Log -WriteStdOut
    break

}

####################################################
#
#   Ingest JSON generated by
#   https://github.com/microsoftgraph/powershell-intune-samples/blob/master/EndpointSecurity/EndpointSecurityPolicy_Export.ps1
#   from Intune PowerShell Samples Repo

#   If script is ran from the folder where EndpointSecurity/EndpointSecurityPolicy_Export.ps1 data has been exported,
#   prompt user to test all files in the folder


# If script is ran with no arguments, test to see if JSON files are present.  If not, give the user a choice to 
# automatically download and process JSON data from Graph
 
if (( $PSBoundParameters.Values.Count -eq 0 -and $args.count -eq 0 ) `
      -or                                                              `
      ($PSBoundParameters.Values.Count -eq 1 -and $args.count -eq 0 -and $AcceptEULA)

  ){
  $JSONFiles = @()
  $JSONFiles = Get-ChildItem $pwd\*.json

####################################################
#
# Scenario 1: Test data exported by EndpointSecurity/EndpointSecurityPolicy_Export.ps1
#
####################################################

    if ( $JSONFiles) {
														   
																				  
																																	  
																																  

        Write-Host "`r`n`r`n$line$stars" -ForegroundColor Green
        write-host "JSON files detected in current folder.`r`n" -ForegroundColor Green
        Write-Host "Type (Y)es to test firewall rules from JSON files in current folder, any other key to exit`r`n" -ForegroundColor Green
        Write-Host "Choose this option if firewall rules were exported using EndpointSecurityPolicy_Export.ps1" -ForegroundColor Green

        $response = Read-Host

        if ($response -match "^Y"){

            $RuleJSON = $JSONFiles
        
        }

    }

####################################################
#
# Scenario 2: Connect to Intune, export all firewall policies and test them automatically
#
####################################################
  
    else {
    
        Test-IsUserAuthenticated

        $exportFolderName = "FWJSON" +  (Get-Date).ToString("ddMMyyyyhhmmss")
        $exportpath = Join-Path $env:temp $exportFolderName

        Export-Templates -exportFolder $exportpath
        $RuleJSON = Get-ChildItem $exportpath\*.json

        }
  
    }
 

# Process rules if files exist

if ($RuleJSON){
						 
  
    Test-RulesFromJSONFiles
  
}

else {

    "No JSON files found in $pwd. Exiting." | Write-Log -WriteStdOut
    break

}


 
####################################################
#
# Create and display report
#
####################################################

												  
$global:detectedErrors |  Format-List | Out-File $global:ErrorLogName -Force -Append
$HTMLFileName = New-HTMLReport -resultBlob $global:detectedErrors

if (Test-Path $HTMLFileName){

    Start-Process $HTMLFileName

}
 
####################################################
#
# Remove test rules created by script
#
####################################################

Remove-TestFirewallRules


#endregion
