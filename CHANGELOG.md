# Change log for AutoPilotReadiness.ps1

## 2.2.0 - August 2, 2023

- Resolved code best practices: changed alias cmdlets to cmdlet
- Updated error output; changed from write-error to write-host
- Added Azure Advanced settings parameter; azure ad join setting check
- Refined permission scopes. Removed unused permissions
- Updated readme with permissions table and parameters.

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
