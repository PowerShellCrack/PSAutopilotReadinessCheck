# Change log for AutoPilotReadiness.ps1

## 2.0.0 - July 23, 2023

- Added Intune license check; validates Intune license against service plans
- Added User group check against licenses; ensure user is assigned a Intune license
- Added MDM policy check; ensures MDM is enabled

## 1.5.0 - July 20, 2023

- Changed all graph calls to use API. Allows for proper scoping to work
- Added UserPricinpalName check; define user to check for Autopilot readiness

## 1.0.0 - June 28, 2023

- initial build
