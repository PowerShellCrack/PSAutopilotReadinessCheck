# Change log for AutoPilotReadiness.ps1

## 2.2.7 - August 5, 2023

- Fixed User ESP app assignment check
- Changed last output to show if autopilot is ready
- Added Write-Action function to reduce repetitive code. 

## 2.2.6 - August 4, 2023

- Reduced repetitive logic into function; saving some lines of code
- Enhanced ESP App detection and output
- Fixed licenses output to display correctly for verbose

## 2.2.5 - August 3, 2023

- Change order or process; moved license check in prereq
- Added Device restriction limit count; nee dto check user total enrollment still
- Converted some repeating code to functions. 

## 2.2.1 - August 2, 2023

- Resolved code best practices: changed alias cmdlets to cmdlet
- Updated error output; changed from write-error to write-host
- Added Azure Advanced settings parameter; azure ad join setting check
- Refined permission scopes. Removed unused permissions
- Updated readme with permissions table and parameters.
- Fixed verbose output and value output; no line wrapping

## 2.1.0 - August 1, 2023

- Fixed license check for users; it checked it all the time. 
- Fixed graph call for MDM; always checking .com
- Fixed group check during user and mdm; remove security filter
- Fixed graph scopes. Missing Policy.Read.All. 

## 2.0.0 - July 23, 2023

- Added Intune license check; validates Intune license against service plans
- Added User group check against licenses; ensure user is assigned a Intune license
- Added MDM policy check; ensures MDM is enabled

## 1.5.0 - July 20, 2023

- Changed all graph calls to use API. Allows for proper scoping to work
- Added UserPrincipalName check; define user to check for Autopilot readiness

## 1.0.0 - June 28, 2023

- initial build
