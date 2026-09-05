@ECHO OFF
IF %1.==. GOTO Error
:CHOICE
set /P c=Is "%1" right Firebase Project-ID for deployment[Y/N]?
if /I "%c%" EQU "Y" goto :CONTINUE
if /I "%c%" EQU "N" goto :Error
:CONTINUE

:: -- SSO feature flag ---------------------------------------------------------
:: SSO rewrites are included only when the flag is passed:
::     Deployment.bat <project-id> sso_enabled
:: Without it the console deploys with SPA routing only and no /auth/** routes.
:: An unrecognised second argument aborts, so a typo cannot silently drop
:: the SSO routes from the deployment.
set "SSO_ENABLED=false"
if "%2"=="" goto :FLAGDONE
if /I "%2"=="sso_enabled" goto :FLAGON
if /I "%2"=="--sso" goto :FLAGON
ECHO Unknown option "%2" - expected sso_enabled
GOTO Error
:FLAGON
set "SSO_ENABLED=true"
:FLAGDONE

:: -- Per-environment configuration --------------------------------------------
:: Service names and the expected region per deployment target. Adding a new
:: target means adding one block here; nothing else in this file changes.
if /I "%1"=="dnacloud-demo2-t" (
    set "DEFAULT_REGION=us-central1"
    set "SSO_SERVICE=sso-container"
    set "GATEWAY_FUNCTION=ssoGateway"
) else if /I "%1"=="gms-dnacloud-eu-p" (
    set "DEFAULT_REGION=europe-west1"
    set "SSO_SERVICE=sso-container"
    set "GATEWAY_FUNCTION=ssoGateway"
) else (
    ECHO Unknown project-ID "%1" - no environment configuration defined in Deployment.bat.
    GOTO Error
)

:: -- Region selection ---------------------------------------------------------
:: The region goes into the Hosting rewrites, so it must be the region the
:: Cloud Run service actually runs in. The default below is the one recorded
:: for this project; choosing the other is possible but only correct if the
:: service has been deployed there.
:REGIONCHOICE
ECHO.
ECHO Select the Cloud Run region for %1:
ECHO   1^) us-central1
ECHO   2^) europe-west1
ECHO   Enter = keep default ^(%DEFAULT_REGION%^)
set "r="
set /P r=Region [1/2/Enter]?
if "%r%"=="" set "REGION=%DEFAULT_REGION%" & goto :REGIONDONE
if "%r%"=="1" set "REGION=us-central1" & goto :REGIONDONE
if "%r%"=="2" set "REGION=europe-west1" & goto :REGIONDONE
ECHO Invalid choice "%r%" - enter 1, 2, or press Enter.
goto :REGIONCHOICE
:REGIONDONE

:: Flat, not a parenthesised block: %k% inside a block would be expanded when
:: the block is parsed, before set /P runs, so the answer would always be empty.
if /I "%REGION%"=="%DEFAULT_REGION%" goto :REGIONOK
ECHO.
ECHO WARNING: %1 is recorded as %DEFAULT_REGION% but you selected %REGION%.
ECHO The Hosting rewrites will point at %SSO_SERVICE% in %REGION%. If the
ECHO service is not deployed there, every /auth/** route will 404.
set "k="
set /P k=Continue anyway [Y/N]?
if /I not "%k%"=="Y" GOTO Error
:REGIONOK

ECHO Target: %1 ^| region: %REGION% ^| SSO service: %SSO_SERVICE% ^| SSO rewrites: %SSO_ENABLED%

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

:: -- Generate firebase.json from template -------------------------------------
:: firebase.json is a build artifact (gitignored); firebase.json.template is the
:: tracked source. Region and service name come from the block above, so the
:: Hosting rewrites and the Cloud Run deployment cannot drift apart.
ECHO "*********************************** Generating firebase.json ***********************************"
IF NOT EXIST firebase.json.template (
    ECHO firebase.json.template not found - generate it from firebase.json first.
    GOTO Error
)
if /I "%SSO_ENABLED%"=="true" (
    IF NOT EXIST rewrites.sso.template (
        ECHO rewrites.sso.template not found - required when --sso is passed.
        GOTO Error
    )
)
powershell -NoProfile -Command "$c=(Get-Content firebase.json.template -Raw); if ('%SSO_ENABLED%' -eq 'true') { $sso=(Get-Content rewrites.sso.template -Raw) } else { $sso='' }; $c=$c.Replace('__SSO_REWRITES__',$sso); $c=$c.Replace('${REGION}','%REGION%'); $c=$c.Replace('${SSO_SERVICE}','%SSO_SERVICE%'); $c=$c.Replace('${GATEWAY_FUNCTION}','%GATEWAY_FUNCTION%'); Set-Content firebase.json -Value $c -NoNewline"
if errorlevel 1 GOTO Error

powershell -NoProfile -Command "try { Get-Content firebase.json -Raw | ConvertFrom-Json > $null } catch { exit 1 }"
if errorlevel 1 (
    ECHO Generated firebase.json is not valid JSON - aborting before deploy.
    GOTO Error
)
ECHO firebase.json generated for %1 ^(%REGION%^) ^| SSO rewrites: %SSO_ENABLED%

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
