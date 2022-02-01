
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

Test-IntuneFirewallRules.ps1

Utility for testing Intune Firewall Rules
Author: Mark Stanfill (markstan@microsoft.com)
Published:  1/21/2022
Last Updateed: 2/1/2022

#>

####################################################

Param (
  [string]$PolicyName ,
  [string]$PolicyID,
  [bool]$Debug = $false,
  [switch]$DeleteTestFirewallRules,
  [switch]$IncludeUnassignedPolicies,
  [switch]$AcceptEULA


)

# Script-wide logging function
function Write-Log {
  [CmdletBinding()]
  param(
      [Parameter(ValueFromPipeline = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$Message = "",

      [Parameter()]
      [ValidateNotNullOrEmpty()]
      [ValidateSet('Information','Warning','Error','Verbose')]
      [string]$Level = 'Information',
      
      [Parameter()]
      [switch]$WriteStdOut,

      [Parameter()]
      # create log in format 
      [string]$logName =  $global:logName
 
  )

  

  BEGIN {
    if ( ($null -eq $logName) -or ($logName -eq "")) { Write-Error "Please set variable `$global$Logfile."}
  }
  PROCESS {
      # only log verbose if flag is set
      if ( ($Level -eq "Verbose") -and ( -not ($debugMode) ) ){
        # don't log events unless flag is set
      }
        else {
         
        [pscustomobject]@{
            Time = (Get-Date -f u)   
            Line = "`[$($MyInvocation.ScriptLineNumber)`]"          
            Level = $Level
            Message = $Message
            
        } |  Export-Csv -Path $logName -Append -Force -NoTypeInformation -Encoding Unicode

        if (  $WriteStdOut -or ( ($Level -eq "Verbose") -and $debugMode)) { Write-Output $Message}
    }
  }
  END{}
}


# Show warning about firewall creation and how to remedy any artifacts left by the script
function Test-IsEULAAccepted {
  [string]$message =
@"
  
  Warning:  This script will create test firewall rules on the device it is ran on.  These rules are disabled and named with a `"____MSTestRule_DeleteMe____`" prefix.
  
  Rules will be automatically deleted when the script completes.
  
  If there are any rules remaing (for instance, if the device reboots or the PowerShell window is closed while the script is running, run this command to delete remaining artifacts:
  
  Test-IntuneFirewallRules.ps1 -DeleteTestFirewallRules
"@

  [bool]$isEULAAccepted = $false

  if (  $AcceptEULA ){
    $isEULAAccepted = $true
  }

  if ( $isEULAAccepted -eq $false) {
    Write-Host -Object $message -ForegroundColor "Red"
    Write-Host "`r`nType (Y)es to accept this warning and continue running this script:  " -NoNewline
    $accepted = Read-Host

    if ($accepted -in ("y", "yes", "yep", "yeppers", "boyhowdy") ) {
      $isEULAAccepted = $true
      "EULA accepted via command line: $accepted" | Write-Log
    }
    else {
      "EULA not accepted, exiting: $accepted" | Write-Log
    }

  }
  else {
    "EULA accepted via command line." | Write-Log
  }
  
  $isEULAAccepted
  
}

function Get-SuggestedAction {
  param (
    $ExceptionInfo,
    $DetectedPathIssues,
    $FilePath
  )

  [string]$Remediation = ""

  
  "Change $DetectedPathIssues to $fixedPath" | Write-Log  
  # String fix-up for reporting
  $ProblemDescription = $(($ExceptionInfo.Exception) | Out-String ) -replace "\r\n", ""

  switch -Wildcard  ( $ProblemDescription){

    "The parameter is incorrect*"   { 
        
        

        switch -Wildcard ($DetectedPathIssues) {
          "*space pattern*" { 
              $envVar = $FilePath -replace "(%.*%)(.*)", "`$1"
              $fixedString = $envVar -replace " ", ""
              $Remediation = "Remove spaces in the environmental variable in the rule's file path.`r`nChange $envVar to $fixedString in $FilePath."
          }
          "*Unterminated % *"{
              $UnterminatedEnvVar = $FilePath -replace "(%.*)(\\.*)", "`$1"
              $fixedString = $UnterminatedEnvVar + '%'
              $Remediation = "Add a '%' character to the environmental variable in the rule's file path.`r`nChange $UnterminatedEnvVar to $fixedString in $FilePath."
          }
          "Invalid system variable*"{
              $envVar = $FilePath -replace "(%.*%)(.*)", "`$1"
              $Remediation = "The environmental variable in file path $FilePath is not supported.  Only default environmental variables are supported.  Change $envVar to a fixed path."
          }
          "Leading spaces*"{
              $Remediation = "Remove all space characters before the first '%' character in file path `"$FilePath`"."
          }
           
        }
      }
    "The address range is invalid*" { $Remediation = "Fix address range in rule."}
    default                         { $Remediation = "Unable to detect fix.  Please try to create rule manually to troubleshoot."}

  }

  "REMEDIATION: $Remediation" | Write-Log
  $Remediation


}   



  Function Test-IsAdmin
  {
      ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent() `
      ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  }
  
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
        [Parameter(Mandatory=$true)]
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
            write-host
            write-host "AzureAD Powershell module not installed..." -f Red
            write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
            write-host "Script can't continue..." -f Red
            write-host
            exit
        }
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
        if($AadModule.count -gt 1){
    
            $Latest_Version = ($AadModule | Select-Object version | Sort-Object)[-1]
    
            $aadModule = $AadModule | Where-Object { $_.version -eq $Latest_Version.version }
    
                # Checking if there are multiple versions of the same module found
    
                if($AadModule.count -gt 1){
    
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
    
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId,"prompt=admin_consent").Result
    
            if($authResult.AccessToken){
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'='application/json'
                'Authorization'="Bearer " + $authResult.AccessToken
                'ExpiresOn'=$authResult.ExpiresOn
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
    
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    
        }
    
    }




####################################################
# Returns values from JSON object 
#
#https://stackoverflow.com/questions/64187004/powershell-selecting-noteproperty-type-objects-from-object
function Get-LeafProperty {
    param([Parameter(ValueFromPipeline)] [object] $InputObject, [string] $NamePath)
    process {   
      if ($null -eq $InputObject -or $InputObject -is [DbNull] -or $InputObject.GetType().IsPrimitive -or $InputObject.GetType() -in [string], [datetime], [datetimeoffset], [decimal], [bigint]) {
        # A null-like value or a primitive / quasi-primitive type -> output.
        # Note: Returning a 2-element ValueTuple would result in better performance, both time- and space-wise:
        #      [ValueTuple]::Create($NamePath, $InputObject)
        [pscustomobject] @{ NamePath = $NamePath; Value = $InputObject }
      }
      elseif ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [System.Collections.IDictionary]) {
        # A collection of sorts (other than a string or dictionary (hash table)), 
        # recurse on its elements.
        $i = 0
        foreach ($o in $InputObject) { Get-LeafProperty $o ($NamePath + '[' + $i++ + ']') }
      }
      else { 
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

function Write-BadRule {
    param(
        $FWRule,
        $ExceptionInfo = "",
        $DetectedPathIssues = " ",
        $PolicyName = "Unknown",
        $SuggestedFix
    )
 
    $ExceptionType = "Unknown"
    if ($ExceptionInfo){ $ExceptionType = $ExceptionInfo}
    $pathIssuesString = $DetectedPathIssues | Out-String
 
    $newReport = New-RuleCheckResult -FWRuleName $FWRule.DisplayName  -result "Failed" -Exception $ExceptionType -PatternsDetected  $pathIssuesString -PolicyName $PolicyName -SuggestedFix $SuggestedFix
    $global:detectedErrors += $newReport
  }
 
  function New-RuleCheckResult
  {
      [CmdletBinding()]
      param(
          [string] [Parameter(Mandatory=$true)] $FWRuleName, 
          [string] $Exception,
          [string] [ValidateSet("Passed","Warning", "Failed", "Information")] $result,
          [string] $PatternsDetected,
          [string] $PolicyName = "Unknown",
          $SuggestedFix
      )
  
  
      $RuleResult = [PSCustomObject] [Ordered] @{
          'Policy name' = $PolicyName
          'Firewall Rule Name'= $FWRuleName
          'Exception'= $Exception
          'Test Result'= $result
          'Patterns Detected'= $PatternsDetected
          'Suggested fix' = $SuggestedFix
      }
      return $RuleResult
  }
    

function New-HTMLReport{
    Param ($resultBlob)

    
$xml = $resultBlob |ConvertTo-Xml -NoTypeInformation -As Document
$xml.InnerXML     |  Out-File WindowsHealthTests.xml -Force
 
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
    const headings = document.querySelectorAll('tr th')
    const col = Array.from(headings).find(hd => hd.innerHTML === "Test Result")
    const inx = Array.from(col.parentNode.children).indexOf(col)
    const cells = col.closest('table').querySelectorAll(`td:nth-child(${inx+1})`)

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
$html = $resultBlob | ConvertTo-Html -head $head -Body $script -PreContent $preContent
$HTMLFileName = Join-Path $env:temp "FirewallRuleTests.html"
$html | Out-File -FilePath $HTMLFileName -Force


}

Function Get-FirewallPolicies(){

<#
.SYNOPSIS
This function is used to get Firewall Policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and returns all Firewall Policies
.EXAMPLE
Get-ManagedDevices
Returns firewall policies created from the endpointSecurityFirewall template
.NOTES
NAME: Get-FirewallPolicies
#>
    [cmdletbinding()]

    $graphApiVersion = "Beta"

    if ($PolicyName) {
      $Resource = "deviceManagement/configurationPolicies?`$filter=name eq `'$PolicyName`'"
    }
    else {
      $Resource = "deviceManagement/configurationPolicies?`$filter=templateReference/TemplateFamily eq 'endpointSecurityFirewall'"
    }
    


    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
   
        $FirewallRulesResponse = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)
        $FirewallRules = $FirewallRulesResponse.value 
        $FirewallRulesNextLink = $FirewallRulesResponse."@odata.nextLink"

        while ($null -ne $FirewallRulesNextLink){ 
                $FirewallRulesResponse = (Invoke-RestMethod -Uri $FirewallRulesNextLink -Headers $authToken -Method Get)
                $FirewallRulesNextLink = $FirewallRulesResponse."@odata.nextLink"
                $FirewallRules += $FirewallRulesResponse.value 
            }

        return $FirewallRules  

    }

    catch {

        $ex = $_.Exception 
        Write-Log -Level Error -WriteStdOut  "Response content:`n$responseBody"  
        Write-Log -Level Error -WriteStdOut  "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Log -Level Error -WriteStdOut "$ex.scriptstacktrace"
        break

    }

}

####################################################

Function Get-ConfigManFirewallPolicies(){

<#
.SYNOPSIS
This function is used to get Managed Devices from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets Managed Devices
.EXAMPLE
Get-ManagedDevices
Returns Managed Devices configured in Intune
.NOTES
NAME: Get-ManagedDevices
#>

[cmdletbinding()]

$graphApiVersion = "Beta"
if ($PolicyName){
  $Resource = "deviceManagement/configurationPolicies?`$filter=(technologies eq 'configManager' and creationSource eq 'Firewall' and name eq `'$PolicyName`')"  
}
if ($PolicyID){
  $Resource = "deviceManagement/configurationPolicies?`$filter=(technologies eq 'configManager' and creationSource eq 'Firewall' and id eq `'$PolicyID`')"  
}
else {
  $Resource = "deviceManagement/configurationPolicies?`$filter=(technologies eq 'configManager' and creationSource eq 'Firewall')"
}

#https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$filter=(technologies%20eq%20%27configManager%27%20and%20creationSource%20eq%20%27Firewall%27) 


    try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

    $FirewallRulesResponse = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)


    $FirewallRules = $FirewallRulesResponse.value
     
    $FirewallRulesNextLink = $FirewallRulesResponse."@odata.nextLink"

        while ($null -ne $FirewallRulesNextLink){

            $FirewallRulesResponse = (Invoke-RestMethod -Uri $FirewallRulesNextLink -Headers $authToken -Method Get)
            $FirewallRulesNextLink = $FirewallRulesResponse."@odata.nextLink"
            $FirewallRules += $FirewallRulesResponse.value

        }

    return $FirewallRules  

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Output "Response content:`n$responseBody"  
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    
    break

    }

}



Function Get-FWPolicyIntents(){

<#
.SYNOPSIS
This function is used to get Firewall policies (intents) from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and returns intent information
.EXAMPLE
Get-FWPolicyIntents
Returns firewall policy intents
.NOTES
NAME: Get-FWPolicyIntents
#>
[cmdletbinding()]

$graphApiVersion = "Beta"

if ($PolicyName){
  "Policy name $PolicyName specified." | Write-Log  
  $Resource = "deviceManagement/intents?`$filter=displayName eq `'$PolicyName`'"
}
elseif ($PolicyID){
  "Policy ID $PolicyID specified." | Write-Log  
  $Resource = "deviceManagement/intents?`$filter=id eq `'$PolicyID`'"
}
else {
  
  $Resource = "deviceManagement/intents?`$filter=templateId%20eq%20%27c53e5a9f-2eec-4175-98a1-2b3d38084b91%27%20or%20templateId%20eq%20%274356d05c-a4ab-4a07-9ece-739f7c792910%27%20or%20templateId%20eq%20%275340aa10-47a8-4e67-893f-690984e4d5da%27"
}
 
    try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

    $FirewallRulesResponse = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)


    $FirewallRules = $FirewallRulesResponse.value
     
    $FirewallRulesNextLink = $FirewallRulesResponse."@odata.nextLink"

        while ($null -ne $FirewallRulesNextLink){

            $FirewallRulesResponse = (Invoke-RestMethod -Uri $FirewallRulesNextLink -Headers $authToken -Method Get)
            $FirewallRulesNextLink = $FirewallRulesResponse."@odata.nextLink"
            $FirewallRules += $FirewallRulesResponse.value

        }
    "Found $($FirewallRules.count) policies with intents" | Write-Log
    return $FirewallRules

    }

    catch { 
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Output "Response content:`n$responseBody"  
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        
        break

    }

}

 Function Get-FireWallRules(){

<#
.SYNOPSIS
This function is used to get Defender Firewall polcies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets Defender Firewall policies
.EXAMPLE
Get-ManagedDevices
Returns firewall rules as detected by intents, filtered on the Defender Firewall category (categories/fae9ad7a-772f-4cae-a60b-14a10fa827f7; this is the same across all tenants).
.NOTES
NAME: Get-FireWallRules
#>
[cmdletbinding()]
param( [string]$id)

$graphApiVersion = "Beta"
 
# TODO - do we have any general firewall rules with guid d9fb9722-5b6d-4f85-99e2-4a746a9c8b95?
$Resource = "deviceManagement/intents/$id/categories/fae9ad7a-772f-4cae-a60b-14a10fa827f7/settings?`$expand=Microsoft.Graph.DeviceManagementComplexSettingInstance/Value"
#ex: https://graph.microsoft.com/beta/deviceManagement/intents/dace94df-b380-46d1-85a8-a7eabc0f63d8/categories/fae9ad7a-772f-4cae-a60b-14a10fa827f7/settings?$expand=Microsoft.Graph.DeviceManagementComplexSettingInstance/Value


    try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

    $FirewallRulesResponse = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)


    $FirewallRules = $FirewallRulesResponse.value
     
    $FirewallRulesNextLink = $FirewallRulesResponse."@odata.nextLink"

        while ($null -ne $FirewallRulesNextLink){

            $FirewallRulesResponse = (Invoke-RestMethod -Uri $FirewallRulesNextLink -Headers $authToken -Method Get)
            $FirewallRulesNextLink = $FirewallRulesResponse."@odata.nextLink"
            $FirewallRules += $FirewallRulesResponse.value

        }

    if($debug){
        "Firewall rules blob:`r`n`r`n`r`n" | Write-Log -Level Verbose
        $FirewallRules | Out-String | Write-Log -Level Verbose
    }
    if($global:debugMode) {
        "Firewall Rules from  Get-FireWallRules:`r`n`r`n" | Write-Log -Level Verbose
        $FirewallRules | Write-Log -Level Verbose
    }
    return $FirewallRules

    }

    catch { 
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Log -Level Error -WriteStdOut  "Response content:`n$responseBody"  
        Write-Log -Level Error -WriteStdOut  "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Log -Level Error -WriteStdOut "$ex.scriptstacktrace"
        break 
    }

}
####################################################


# Return a command line for the New-NetFirewallRule cmdlet based on JSON data
function Test-FirewallRuleCreatesSuccessfully {
    param( $FWRuleToCreate,
           $DetectedPathIssues,
           $PolicyName = "Unknown" )


    # Get the list of populated properties to create the test rule from
    $PopulatedProperties = $FWRuleToCreate | Get-LeafProperty | Where-Object { ("" -ne $_.Value) -and ($null -ne $_.Value)}
    $ConstructedCommandLineArgs = @{}
    # for logging
    $tabs = "`t" * 3
    $stars = '*' * 80
    $pluses = '+' * 80
    # always create the rule disabled so that we don't inadvertantly block traffic
    # load assembly
    $null = Get-NetFirewallSetting
    $enabled =  [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::False
    $testString = "____MSTestRule_DeleteMe____"
    $errMsg = ""
    
    # hash of object properties to match against the corresponding Net-NetFirewallRule command line switches
    $PropertyToSwitchMapping = @{
      displayName                = "DisplayName"
      description                = "Description"
      trafficDirection           = "Direction"
      action                     = "Action" 
      packageFamilyName          = "Package"
      filePath                   = "Program"
      serviceName                = "Service" 
      protocol                   = "Protocol"
      localUserAuthorizations    = "LocalUser"
      
    }
    
    foreach ($PopulatedProperty in $PopulatedProperties){
      $CommandLineSwitch = $PopulatedProperty.NamePath
      "$CommandLineSwitch" | Out-String | Write-Log
      $argument = $PopulatedProperty.Value

      if ($argument -eq "notConfigured") {
        "Skipping notConfigured value $CommandLineSwitch" | Write-Log
      }
      else {
        
        switch -Wildcard ($CommandLineSwitch){
          'useAnyLocalAddressRange' { 
            $useAnyLocalAddressRange = $ConstructedCommandLineArgs[$CommandLineSwitch]
            "$useAnyLocalAddressRange " | Write-Log
      
           
            if ( ($null -eq $useAnyLocalAddressRange) -or ($useAnyLocalAddressRange -eq "") ){
                    "Skipping empty value for useAnyLocalAddressRange" | Write-Log -Level Verbose
                  }
            else {
                $ConstructedCommandLineArgs['LocalAddress'] = "Any"
            }

          }   
          'useAnyRemoteAddressRange' {
            $useAnyRemoteAddressRange = $ConstructedCommandLineArgs[$CommandLineSwitch]
            "$useAnyRemoteAddressRange " | Write-Log
      
           
            if ( ($null -eq $useAnyRemoteAddressRange) -or ($useAnyRemoteAddressRange -eq "") ){
                    "Skipping empty value for useAnyRemoteAddressRange" | Write-Log -Level Verbose
                  }
            else {
                $ConstructedCommandLineArgs['RemoteAddress'] = "Any"
            }

          }
          'DisplayName' {
            # create unique display names so we don't duplicate existing rules
         
            [string]$testName = $testString + $argument
            $ConstructedCommandLineArgs['DisplayName']=$testname 
          }
          "actualRemoteAddressRanges*"{
           
            $ipRanges = $FWRuleToCreate.actualremoteaddressranges
            $ipAddressRanges =@()

            foreach ($ipRange in $ipRanges){
              $ipAddressRanges += $ipRange
            } 
            $ConstructedCommandLineArgs['RemoteAddress'] =  $ipAddressRanges
          }          
          'actualLocalAddressRanges*'{
            
            $ipRanges = $FWRuleToCreate.actualLocaladdressranges
            $ipAddressRanges =@()

            foreach ($ipRange in $ipRanges){
              $ipAddressRanges += $ipRange
            } 

            foreach ($ipRange in $ipRanges){
              $ConstructedCommandLineArgs['LocalAddress']  =  $ipAddressRanges
            } 
          }
          'profileTypes*' {

            $ProfileTypes = $FWRuleToCreate.profileTypes
            $profileEnum = @()

            foreach ($ProfileType in $ProfileTypes){ 
              switch($ProfileType){
                "Domain"{ $profileEnum += [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]::Domain}
                "Private"{$profileEnum += [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]::Private}
                "Public"{$profileEnum += [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]::Public}
                "NotApplicable" {$profileEnum += [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]::NotApplicable}
              } 
            } 
            $ConstructedCommandLineArgs['Profile'] =  $ProfileEnum

          } 
          'action' {

            $Actions = $FWRuleToCreate.Action
            $ActionsEnum = ""

            foreach ($Action in $Actions){ 
              "Action:  $action" | Write-Log -WriteStdOut
              switch($Action){
                "NotConfigured"{ $ActionsEnum = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action]::NotConfigured}
                "Allowed"{$ActionsEnum = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action]::Allow}
                "Blocked"{$ActionsEnum = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Action]::Block}
                
              } 
            } 
            $ConstructedCommandLineArgs['Action'] =  $ActionsEnum

          } 
          'interfaceTypes*'{
            $interfaceTypes = $FWRuleToCreate.interfaceTypes
            $interfaceTypeEnum = @()

            foreach ($interfaceType in $interfaceTypes){ 
              "interfaceType:  $interfaceType" | Write-Log -WriteStdOut
              $interfaceTypeEnum += $interfaceType 
              } 
            
              $ConstructedCommandLineArgs['interfaceType'] =  $interfaceTypeEnum

          }
          '*PortRanges*' {
             # either localPortRanges or   remotePortRanges   
             # Name fixup from Get-LeafProperty data
            $localRemoteCommandLineSwitch =  $CommandLineSwitch   -replace "\[\d+\]$", ""
            "Port range rule $localRemoteCommandLineSwitch"  | Write-Log -WriteStdOut
            $PortRangesTypes =         $FWRuleToCreate.$localRemoteCommandLineSwitch
            $PortRangesEnum = @()

            foreach ($PortRange in $PortRangesTypes){ 
              "PortRanges:  $PortRange" | Write-Log -WriteStdOut
              $PortRangesEnum += $PortRange 
              } 
            
              $PortCmdArg = $localRemoteCommandLineSwitch -replace "(.+)Ranges.*", "`$1"
              $ConstructedCommandLineArgs[$PortCmdArg] =  $PortRangesEnum

          }
     
          Default {
 
                 $hashValue = $PropertyToSwitchMapping[$CommandLineSwitch] 
                 $ConstructedCommandLineArgs[$hashValue]=$argument
 
          }
        }
      }
    }

 
    # string interpolation for logging
    $nnfwrule = ($ConstructedCommandLineArgs |Format-List   | Out-String) -replace "(\r\n)+", " "  
    $nnfwrule = $nnfwrule -replace "Value\s+:\s+", "" 
    $nnfwrule = $nnfwrule -replace "Name  : ", "-" 
    
    "Running command (spaces will be quoted):`r`n`r`n$tabs New-NetFirewallRule $nnfwrule -Enabled $enabled`r`n"  | Write-Log
    try {
      $dispName = $ConstructedCommandLineArgs["displayName"] -replace $testString, ""
      $null = New-NetFirewallRule  @ConstructedCommandLineArgs -Enabled $enabled -ErrorAction "Stop"
      "`r`n$tabs$pluses`r`n$tabs Successfully created rule. Name: $dispName`r`n`r`n" | Write-Log
 
       
    }
    catch {
      [string]$Remediation = ""
      $errMsg = $error[0] 
      "`r`n$tabs$stars`r`n`r`n$tabs Exception creating rule. Name: $dispName`: $errMsg`r`n`r`n$tabs$stars`r`n" | Write-Log -WriteStdOut
      $Remediation = Get-SuggestedAction -ExceptionInfo  $errMsg -DetectedPathIssues $DetectedPathIssues -FilePath $ConstructedCommandLineArgs.program
      Write-BadRule -FWRule $FWRuleToCreate -ExceptionInfo  $errMsg -DetectedPathIssues $DetectedPathIssues -PolicyName $PolicyName -SuggestedFix $Remediation
    }
    finally {
        # Catch condition where rule creates successfully but have detected a bad path
        if ( ($errMsg -eq "") -and ($DetectedPathIssues.count -gt 0) ){
            [string]$Remediation = ""
            "Bad path regex found in $dispName" | Write-Log -Level Warning
            $DetectedPathIssues | Write-Log -Level Warning
            $Remediation = Get-SuggestedAction -ExceptionInfo  $errMsg -DetectedPathIssues $DetectedPathIssues -FilePath $ConstructedCommandLineArgs.program
            Write-BadRule -FWRule $FWRuleToCreate -ExceptionInfo  $errMsg -DetectedPathIssues $DetectedPathIssues -PolicyName $PolicyName -SuggestedFix $Remediation
        }
    }
 
 
  
}
 
# clean up on exit
function Remove-TestFirewallRules {
  $allLocalFWRules = Get-NetFirewallRule
  $testString = "____MSTestRule_DeleteMe____" 

  foreach ($localFWRule in $allLocalFWRules){
     
    if ($localFWRule.displayName -match $testString) {
      try {
        "Deleting rule $($localFWRule.displayName)" | Write-Log -WriteStdOut
        Remove-NetFirewallRule -id $localFWRule.id  
        "Rule successfully deleted." | Write-Log -WriteStdOut
        }
      catch {
        "Unable to remove rule $($localFWRule.DispalayName).  Please delete manually" | Write-Log -WriteStdOut
        continue
      }
    }
  }



}


Function  Test-Rule{
    param(
      $ruleJSON,
      $PolicyName = "Unknown"
      ) 
    
    $parsedJSON = $ruleJSON # | ConvertFrom-Json
    $parsedJSON | Write-Log
    # Begin section rules
    $EnvVar_with_Space_Pattern =  "%\w+\s+\w+.*%"
    # string starting with % followed by any number of chars except %, followed by a \
    $EnvVar_without_Closure =  "^%([^%])*\\(.*)"
    $EnvVar_With_Leading_Spaces = "^\s+%.*"
    $defaultEnvVars = @("ALLUSERSPROFILE", "APPDATA", "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(x86)", "CommonProgramW6432", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", `
                        "PATH", "PathExt", "PROGRAMDATA", "PROGRAMFILES", "ProgramW6432", "PROGRAMFILES(X86)", "SystemDrive", "SystemRoot", "TEMP", "TMP", "USERNAME", `
                        "USERPROFILE", "WINDIR", "PUBLIC", "PSModulePath", "OneDrive", "DriverData" )
    
    $filepath = $parsedJSON.filePath
    $displayName = $parsedJSON.displayName
    $DetectedPathIssues = @()
 
    # first check regexs on file path - this is the most common issue
    "Evaluating rule $displayName" | Write-Log
    # validate that any env. vars are in the default list
    if ( $filepath -match "%(\w+)%.*" ) {
        if ($Matches[1] -in $defaultEnvVars) {
            "Correctly formatted system variable found $($Matches[0])in rule $displayName." | Write-Log
        }
        else {
            $msg = "Invalid system variable $($Matches[0]) in path $filepath found in rule $displayName"
            $msg | Write-Log -Level Error
            $DetectedPathIssues += $msg
        }
    }
    # check for patterns like "%program files%" or "%Program Files (x86)"
    elseif ($filepath -match $EnvVar_with_Space_Pattern ){
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

#region Authentication
# validate that user is local admin running elevate for firewall rule creation
if (-not (Test-IsAdmin) ) {
  Return "Please run PowerShell elevated (run as administrator) and run the script again."
  Break
  } 


# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

            if (($null -eq $User) -or ($User -eq "")){

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {
    if( ($null -eq $User) -or ($User -eq "")){

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host
    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}

#endregion
 

####################################################
#
#  Main
#
$ErrorActionPreference = "Stop"
# set to true for verbose logging
$global:debugMode = $Debug
$line = "=" * 120
$FirewallPolicys = @() 
$global:logName = Join-Path -Path $env:temp -ChildPath  $("Test-IntuneFirewallRules_$((Get-Date -Format u) -replace "[\s:]","_").log")
$global:ErrorLogName = Join-Path -Path $env:temp -ChildPath  $("Test-IntuneFirewallRules_Errors_$((Get-Date -Format u) -replace "[\s:]","_").log")
$global:detectedErrors = @() 

Write-Log -WriteStdOut "`r`n$line`r`nStarting firewall policy evaluation `r`n$line`r`n"  -LogName $global:LogName  

# Special mode to clean up orphaned rules created by previous runs
if ($DeleteTestFirewallRules){
  "Removing test firewall rules..." | Write-Log -WriteStdOut
  Remove-TestFirewallRules
  break
}

if (-not (Test-IsEULAAccepted) ) {
  "EULA not accepted, exiting." | Write-Log -WriteStdOut
  break
}
 
$FirewallPolicys += Get-FirewallPolicies
$FirewallPolicys += Get-ConfigManFirewallPolicies
$FirewallPolicys += Get-FWPolicyIntents
 

if ($debugMode){ $FirewallPolicys | Write-Log -Level Verbose}
$FirewallPolicys =  $FirewallPolicys | Sort-Object -Property isAssigned, displayName  
 
if($FirewallPolicys){

    foreach($Firewallpolicy in $Firewallpolicys){
        $firewallPolicyName = $Firewallpolicy.displayName
        $isAssigned = $FirewallPolicy.isAssigned
        
        # Examine policy rules if 1) Default mode - policy is assigned
        #                         2) -IncludeUnassignedPolicies commmand line switch is specified
        #                         3) if -PolicyName command line switch (return policy whether enabled or not)
        if ( ($isAssigned -eq $true) -or ($IncludeUnassignedPolicies) -or ($PolicyName) -or ($PolicyID)) {
                    Write-Log -WriteStdOut "*** Assigned firewall policy $firewallPolicyName found..."  
                     

                    # don't process imported firewall global settings - these are firewall config, not settings
                    if ( $FirewallPolicy.definitionId -match "windows10EndpointProtectionConfiguration") {
                        Write-Log "Skipping policy $firewallPolicyName ($($parsedJSON.definitionId)) because it is a config policy(windows10EndpointProtectionConfiguration)."
                        }
                    else{
                        $Rules =  (Get-FireWallRules -id $Firewallpolicy.id).valueJson   
                        foreach ($Rule in $Rules) {
                            # skip config settings, only process JSON rules in the format [{.*}]
                            if ($Rule -match "\[\{.*\}\]") {
                                $ruleJSONs = $Rule | ConvertFrom-Json
                                foreach ($ruleJSON in $ruleJSONs){
                                    Test-Rule -ruleJSON $ruleJSON -PolicyName $firewallPolicyName
                                }
                            }
                            else {
                                if($debugMode){
                                    Write-Log -Level Verbose "Skipping rule with value $rule.  Most likely config setting, not firewall rule."
                                }
                            }
                             
                        }
                        "`r`n$line`r`nPolicy $firewallPolicyName evaluation complete.`r`n$line" | Write-Log -WriteStdOut
                    } 
            }
        else{
                Write-Log "Firewall policy $firewallPolicyName is not assigned.  Skipping" -WriteStdOut -Level Warning
            }
        
    }
}


else { 
    Write-Log "No firewall rules found..."  -WriteStdOut -Level Warning
}

New-HTMLReport -resultBlob $global:detectedErrors
$global:detectedErrors |  Format-List | Out-File $global:ErrorLogName -Force -Append
New-HTMLReport -resultBlob $global:detectedErrors

# Cleanup
Remove-TestFirewallRules
Start-Process $logName

if (test-path $env:temp\FirewallRuleTests.html) {
  Start-Process "$env:temp\FirewallRuleTests.html"
}


 