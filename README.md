# Test-IntuneFirewallRules

Test-IntuneFirewallRules is a utility to detect errors in Intune firewall rules definitions.  Common errors such as misspelled variable names, typographical errors, and unsupported configurations may lead to the rules not being imported during Intune device sync. This utility queries Intune Graph API to test creating each rule locally so that administrators can easily identify problematic rules.

## Prerequisites

Test-IntuneFirewallRules requirements:

* AzureAD or AzureADPreview module must be installed.  You will be prompted to install the module if it is not present.
* Internet connectivity
* Windows 10 or Windows 11 test device (does not need to be domain-joined or enrolled in Intune)
* The logged in account must be a member of the local administrators group.
* The script must be ran in an elevated PowerShell window so that test firewall rules can be created.

## Description

This utility will log on to your Intune tenant via Graph API and retrieve all firewall rules.  The rules are then tested locally and any errors are reported to a Test-IntuneFirewallRules_Errors.*log file and an FirewallRuleTests.html document.  The HTML document is displayed when the script completes.

## Precautions

It is highly recommended to run Test-IntuneFirewallRules on a virtual machine.  The device requires internet access to download the rule definitions, but otherwise has no special requirements.  The VM does not need to be enrolled in Intune.

The script currrently requires a Windows 11 device to run on.  Win10 version is coming soon.

**Warning:** Test-IntuneFirewallRules creates test rules to validate the information stored in Intune.  These rules are created in a **disabled** state, and the rule name is prepended with ____MSTestRule_DeleteMe____ to make it easy to distinguish.

At the completion of the script, Test-IntuneFirewallRules deletes any rules it creates and logs the result.  You can verify that there are no artifacts remaining in Windows Defender Firewall with Advanced Security MMC by examing the Inbound Rules and Outbound Rules sections. Click the **Name** column to sort alphabetically.  Any rules created by the tool are easy to identify and can safely be deleted.  Note the name and also that the *Enabled* check box is unselected to identify these rules (for example, if the device was rebooted in the middle of running the script):

![Disabled firewall rule with ___MSTestRule_DeleteMe____ name](https://github.com/markstan/Test-IntuneFirewallRules/blob/main/Resources/DisabledFirewallRule.png)

## Usage

Test-IntuneFirewallRules must be run as a local administrator.  Your Intune/AAD credentials must allow at least read access on Configuration Policies.

When the script finishes, it will show an HTML report automatically.![HTML report created by Test-IntuneFirewallRules.ps1](https://github.com/markstan/Test-IntuneFirewallRules/blob/main/Resources/results.png)

## Command Line Arguments

* -PolicyName
* -Debug
* -DeleteTestFirewallRules
* -IncludeUnassignedPolicies

## Examples

After the script runs, 3 files are created:

* Test-IntuneFirewallRules_*.log - debug log for this tool

* Test-IntuneFirewallRules_Errors_*.log -  Text version of error log.

* FirewallRuleTests.html

All files are located in %temp%.
![Files in %temp% created by Test-IntuneFirewallRules.ps1](https://github.com/markstan/Test-IntuneFirewallRules/blob/main/Resources/Filescreated.png)
