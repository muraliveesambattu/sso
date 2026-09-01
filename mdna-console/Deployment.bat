@ECHO OFF
IF %1.==. GOTO Error
:CHOICE
set /P c=Is "%1" right Firebase Project-ID for deployment[Y/N]?
if /I "%c%" EQU "Y" goto :CONTINUE
if /I "%c%" EQU "N" goto :Error
:CONTINUE

:: ── Per-environment configuration ────────────────────────────────────────────
:: Region and Cloud Run service names differ per deployment target. Adding a new
:: target means adding one block here; nothing else in this file changes.
if /I "%1"=="dnacloud-demo2-t" (
    set "REGION=us-central1"
    set "SSO_SERVICE=sso-container"
    set "GATEWAY_FUNCTION=ssoGateway"
) else if /I "%1"=="gms-dnacloud-eu-p" (
    set "REGION=europe-west1"
    set "SSO_SERVICE=sso-container"
    set "GATEWAY_FUNCTION=ssoGateway"
) else (
    ECHO Unknown project-ID "%1" - no environment configuration defined in Deployment.bat.
    GOTO Error
)
ECHO Target: %1 ^| region: %REGION% ^| SSO service: %SSO_SERVICE%

ECHO "*********************************** Installing Firebase CLI ***********************************"
SET mypath=%cd%
ECHO %mypath%
cd %mypath%
call npm install -g firebase-tools@13.27.0
ECHO "*********************************** Firebase CLI installed successfully ***********************************"
call firebase logout
call firebase login
call firebase use %1
cd %mypath%\functions
call npm i firebase-functions@6.1.1

IF NOT EXIST node_modules (
ECHO "Installing node modules for cloud functions"
call npm install
)

cd %mypath%

:: ── Generate firebase.json from template ─────────────────────────────────────
:: firebase.json is a build artifact (gitignored); firebase.json.template is the
:: tracked source. Region and service name come from the block above, so the
:: Hosting rewrites and the Cloud Run deployment cannot drift apart.
ECHO "*********************************** Generating firebase.json ***********************************"
IF NOT EXIST firebase.json.template (
    ECHO firebase.json.template not found - see mdna-console/README.md for how to create it.
    GOTO Error
)
powershell -NoProfile -Command "(Get-Content firebase.json.template -Raw) -replace '\$\{REGION\}','%REGION%' -replace '\$\{SSO_SERVICE\}','%SSO_SERVICE%' -replace '\$\{GATEWAY_FUNCTION\}','%GATEWAY_FUNCTION%' | Set-Content firebase.json -NoNewline"
if errorlevel 1 GOTO Error

powershell -NoProfile -Command "try { Get-Content firebase.json -Raw | ConvertFrom-Json > $null } catch { exit 1 }"
if errorlevel 1 (
    ECHO Generated firebase.json is not valid JSON - aborting before deploy.
    GOTO Error
)
ECHO firebase.json generated for %1 ^(%REGION%^)

ECHO "*********************************** Deploying the KR console ***********************************"
call npm install
call npm run build
call firebase deploy

ECHO "Web console deployment complete!!"
pause
exit /b 0

:Error
ECHO Deployment aborted.
pause
exit /b 1
