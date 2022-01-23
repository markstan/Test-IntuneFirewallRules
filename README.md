# Test-IntuneFirewallRules

 Utility to detect errors in Intune Firewall Rules XML

## Description

This utility will log on to your Intune tenant via Graph API and retrieve all firewall rules.  The rules are then tested locally and any errors are reported to a Test-IntuneFirewallRules_Errors.*log file and an FirewallRuleTests.html document.  The HTML document is displayed when the script completes.

## Usage

Test-IntuneFirewallRules must be run as a local administrator.  Your Intune/AAD credentials must allow at least read access on Configuration Policies.

When the script finishes, it will show an HTML report automatically.![HTML report created by Test-IntuneFirewallRules.ps1](https://github.com/markstan/Test-IntuneFirewallRules/blob/main/Resources/results.png)

## Example

After the script runs, 3 files are created:

* Test-IntuneFirewallRules_*.log - debug log for this tool

* Test-IntuneFirewallRules_Errors_*.log -  Text version of error log.

* FirewallRuleTests.html

All files are located in %temp%.
![Files in %temp% created by Test-IntuneFirewallRules.ps1](https://github.com/markstan/Test-IntuneFirewallRules/blob/main/Resources/Filescreated.png)
