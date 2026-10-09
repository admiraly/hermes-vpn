; NSIS hooks for the Hermes installer (referenced from
; hermes-ui/src-tauri/tauri.installer.conf.json). The installer runs
; per-machine (administrator), so it can register the daemon as a Windows
; service - that is what creates the virtual network adapter - and open
; the firewall for it.
;
; An upgrade runs the old uninstaller first, so the service is stopped and
; removed before files are replaced, then registered again afterwards.

!macro NSIS_HOOK_PREINSTALL
  ; A previous version may still be installed and running (e.g. a manual
  ; install over an old one): free its files before they are overwritten.
  IfFileExists "$INSTDIR\hermes-daemon.exe" 0 +3
    nsExec::Exec '"$INSTDIR\hermes-daemon.exe" service uninstall'
    Pop $0
!macroend

!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToLog '"$INSTDIR\hermes-daemon.exe" service install'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONEXCLAMATION "Hermes was installed, but its background service could not be started (code $0).$\r$\n$\r$\nRun this from an administrator prompt to retry:$\r$\n$\"$INSTDIR\hermes-daemon.exe$\" service install"
  ${EndIf}
  ; Without this, inbound peer-to-peer packets are dropped on most machines.
  nsExec::Exec 'netsh advfirewall firewall add rule name="Hermes daemon" dir=in action=allow program="$INSTDIR\hermes-daemon.exe" enable=yes profile=any'
  Pop $0
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToLog '"$INSTDIR\hermes-daemon.exe" service uninstall'
  Pop $0
  nsExec::Exec 'netsh advfirewall firewall delete rule name="Hermes daemon"'
  Pop $0
!macroend
