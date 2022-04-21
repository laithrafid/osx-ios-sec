 sudo /usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled
  452   sudo /usr/bin/profiles -P -o stdout | /usr/bin/grep AutomaticCheckEnabled
  453  sudo /usr/bin/profiles -P -o stdout | /usr/bin/grep AutomaticCheckEnabled
  454   sudo /usr/bin/defaults read /Library/Preferences/com.apple.commerce AutoUpdate
  455  sudo /usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates
  456  sudo /usr/bin/profiles -P -o stdout | /usr/bin/grep AutomaticallyInstallMacOSUpdates
  457   sudo -u laithrafid defaults -currentHost read com.apple.controlcenter.plist Bluetooth
  458  sudo /usr/sbin/systemsetup -getusingnetworktime
  459  sudo /usr/bin/profiles -P -o stdout | /usr/bin/grep forceAutomaticDateAndTime
  460  sudo /usr/sbin/systemsetup -setnetworktimeserver time.apple.com setNetworkTimeServer: time.apple.com
  461   sudo /usr/sbin/systemsetup -listtimezones
  462  sudo /usr/sbin/systemsetup -settimezone America/Montreal
  463  sudo systemsetup -getnetworktimeserver
  464  sudo sntp time.apple.com | grep +/-
  465   sudo /usr/bin/defaults -currentHost read com.apple.screensaver idleTime
  466   sudo /usr/bin/profiles -P -o stdout | /usr/bin/grep idleTime
  467   sudo /usr/sbin/systemsetup -setremoteappleevents off
  468  sudo defaults read /Library/Preferences/SystemConfiguration/com.apple.nat | grep -i Enabled
  469  sudo /usr/bin/profiles -P -o stdout | /usr/bin/grep forceInternetSharingOff
  470  sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.nat
  471  sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict Enabled -int 0
  472   sudo launchctl print-disabled system | grep -c '"com.apple.screensharing" => true'
  473  sudo launchctl disable system/com.apple.screensharing
  474   sudo launchctl print-disabled system | grep -c '"com.apple.screensharing" => true'
  475  sudo launchctl disable system/com.apple.screensharing
  476  sudo launchctl disable system/com.apple.screensharing
  477  sudo cupsctl --no-share-printers
  478  sudo systemsetup -setremotelogin off
  479  sudo launchctl print-disabled system | grep -c '"com.apple.ODSAgent" => true'
  480  sudo launchctl disable system/com.apple.ODSAgent
  481  sudo -u laithrafid /usr/bin/defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled
  482  sudo -u laithrafid /usr/bin/defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled
  483  sudo -u firstuser /usr/bin/defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled
  484  sudo -u laithrafid /usr/bin/defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled
  485  v sudo launchctl print-disabled system | grep -c '"com.apple.smbd" => true'
  486   sudo launchctl print-disabled system | grep -c '"com.apple.smbd" => true'
  487  sudo launchctl disable system/com.apple.smbd
  488   sudo launchctl print-disabled system | grep -c '"com.apple.smbd" => true'
  489  sudo ps -ef | grep -e ARDAgent
  490  sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources /kickstart -deactivate -stop
  491  sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop
  492  sudo /usr/bin/defaults read /Library/Preferences/com.apple.AssetCache.plist Activated
  493  sudo /usr/bin/profiles -P -o stdout | /usr/bin/grep allowContentCaching
  494  sudo /usr/bin/AssetCacheManagerUtil deactivate
  495  sudo -u laithrafid /usr/bin/defaults read com.apple.NetworkBrowser DisableAirDrop
  496  sudo -u laithrafid /usr/bin/defaults read com.apple.NetworkBrowser DisableAirDrop
  497   sudo /usr/bin/profiles -P -o stdout | /usr/bin/grep DisableAirDrop
  498  sudo -u laithrafid defaults read com.apple.amp.mediasharingd home-sharing- enabled
  499  sudo -u laithrafid defaults read com.apple.amp.mediasharingd home-sharing-enabled
  500  sudo diskutil ap list
  501  sudo diskutil cs list
  502   sudo /usr/sbin/spctl --status
  503   sudo /usr/sbin/spctl --master-enable
  504  sudo /usr/bin/defaults read /Library/Preferences/com.apple.alf globalstate
  505   sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps
  506  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps
  507  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps
  508   sudo /usr/sbin/system_profiler SPFirewallDataType | /usr/bin/grep "Stealth Mode: Yes" | /usr/bin/awk -F ": " '{print $2}' | /usr/bin/xargs
  509  sudo launchctl list | grep -c com.apple.locationd
  510  sudo /usr/bin/defaults read /var/db/locationd/clients.plist
  511  sudo /usr/bin/defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit
  512  sudo -u laithrafid defaults -currentHost read /Users/<username>/Library/Preferences/com.apple.AdLib.plist allowApplePersonalizedAdvertising
  513  sudo -u laithrafid defaults -currentHost read /Users/laithrafid/Library/Preferences/com.apple.AdLib.plist allowApplePersonalizedAdvertising
  514   sudo -u laithrafid defaults -currentHost read /Users/laithrafid/Library/Preferences/com.apple.AdLib.plist allowApplePersonalizedAdvertising
  515  sudo -u laithrafid defaults -currentHost write /Users/laithrafid/Library/Preferences/com.apple.Adlib.plist allowApplePersonalizedAdvertising -bool false
  516  sudo -u laithrafid defaults -currentHost write /Users/laithrafid/Library/Preferences/com.apple.Adlib.plist allowApplePersonalizedAdvertising -bool false
  517   sudo -u laithrafid defaults -currentHost read /Users/laithrafid/Library/Preferences/com.apple.AdLib.plist allowApplePersonalizedAdvertising
  518  sudo /usr/bin/profiles -P -o stdout | /usr/bin/grep allowCamera
  519  sudo -u laithrafid defaults read /Users/laithrafid/Library/Preferences/MobileMeAccounts
  520  sudo /usr/bin/defaults read /Library/Preferences/com.apple.TimeMachine.plist AutoBackup
  521  sudo /usr/bin/defaults read /Library/Preferences/com.apple.TimeMachine.plist AutoBackup
  522  sudo /usr/bin/defaults read /Library/Preferences/com.apple.TimeMachine.plist AutoBackup
  523  sudo /usr/bin/defaults read /Library/Preferences/com.apple.TimeMachine.plist AutoBackup
  524  sudo /usr/bin/defaults write /Library/Preferences/com.apple.TimeMachine.plist AutoBackup -bool true
  525  sudo pmset -g | grep -e womp
  526   sudo pmset -a womp 0
  527  sudo pmset -g | grep -e womp
  528  man pmset
  529  sudo pmset -g everything | grep -c 'powernap 1'
  530   sudo pmset -a powernap 0
  531  sudo -u laithrafid /usr/bin/defaults read -app Terminal SecureKeyboardEntry
  532  sudo -u laithrafid /usr/bin/defaults write -app Terminal SecureKeyboardEntry -bool true
  533  sudo /usr/libexec/firmwarecheckers/eficheck/eficheck --integrity-check
  534  sudo launchctl list | grep com.apple.driver.eficheck
  535  sudo -u laithrafid /usr/bin/defaults read com.apple.assistant.support.plist 'Assistant Enabled'
  536  sudo -u laithrafid /usr/bin/defaults read com.apple.Siri.plist
  537   sudo -u <username> /usr/bin/defaults write com.apple.assistant.support.plist 'Assistant Enabled' -bool false
  538   sudo -u laithrafid /usr/bin/defaults write com.apple.assistant.support.plist 'Assistant Enabled' -bool false
  539  sudo /usr/bin/defaults read com.apple.sidecar.display AllowAllDevices
  540  sudo /usr/bin/defaults read com.apple.sidecar.display AllowAllDevices
  541  sudo /usr/bin/profiles -P -o stdout | /usr/bin/grep "AllowAllDevices"
  542  sudo /usr/bin/profiles -P -o stdout | /usr/bin/grep "AllowAllDevices"
  543  sudo /usr/bin/defaults write com.apple.sidecar.display AllowAllDevices <true/false>
  544  sudo /usr/bin/defaults write com.apple.sidecar.display AllowAllDevices false
  545  sudo /usr/bin/defaults write com.apple.sidecar.display hasShownPref false
  546  sudo launchctl list | grep -i auditd
  547  sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
  548   sudo grep -e "^flags:" /etc/security/audit_control
  549  /var/log/install.log
  550  sudo cat /var/log/install.log
  551  sudo cat /var/log/install.log | lolcat
  552  ls sudo grep -i ttl /etc/asl/com.apple.install
  553   sudo grep -i ttl /etc/asl/com.apple.install
  554   sudo grep -i ttl /etc/asl/com.apple.install
  555  sudo grep -i all_max= /etc/asl/com.apple.install
  556  sudo vim /etc/asl/com.apple.install
  557  sudo grep -i all_max= /etc/asl/com.apple.install
  558  sudo vim /etc/asl/com.apple.install
  559  sudo grep -e "^expire-after" /etc/security/audit_control
  560   sudo ls -le /etc/security/audit_control
  561  sudo ls -le /var/audit/
  562  sudo cat /var/audit/20220417062651.not_terminated
  563  sudo edit /var/audit/20220417062651.not_terminated
  564  sudo code /var/audit/20220417062651.not_terminated
  565  sudo code /var/audit/20220417062651.not_terminated
  566  sudo vim /var/audit/20220417062651.not_terminated
  567  sudo ls -le /var/audit/
  568  sudo /usr/sbin/system_profiler SPFirewallDataType | /usr/bin/grep Logging
  569   sudo /usr/bin/defaults read /Library/Preferences/com.apple.alf.plist loggingoption
  570  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on
  571  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingopt detail
  572  udo system_profiler
  573  sudo system_profiler
  574  sudo /usr/bin/defaults read /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements
  575  sudo /usr/bin/profiles -P -o stdout | /usr/bin/grep "NoMulticastAdvertisements"
  576  sudo /usr/bin/defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true
  577  sudo -u laithrafid  defaults -currentHost read com.apple.controlcenter.plist WiFi
  578  sudo -u laithrafid  defaults -currentHost read com.apple.controlcenter.plist WiFi
  579  sudo -u laithradid defaults -currentHost read com.apple.controlcenter.plist WiFi
  580  sudo -u laithrafid defaults -currentHost read com.apple.controlcenter.plist WiFi
  581  sudo -u laithrafid defaults -currentHost write com.apple.controlcenter.plist WiFi -int 18
  582  sudo launchctl print-disabled system | /usr/bin/grep -c '"org.apache.httpd" => true'
  583   sudo launchctl disable system/org.apache.httpd
  584  sudo launchctl print-disabled system | /usr/bin/grep -c '"org.apache.httpd" => true'
  585  sudo launchctl print-disabled system | grep -c '"com.apple.nfsd" => true'
  586  sudo cat /etc/exports
  587  sudo launchctl disable system/com.apple.nfsd
  588  sudo rm /etc/exports
  589   sudo networksetup -listallhardwareports | grep -A 1 'Hardware Port: Wi-Fi'
  590  sudo networksetup -getairportpower en0
  591  sudo networksetup -getairportpower Wi-Fi
  592  sudo networksetup -getairportpower en0
  593  sudo /bin/ls -l /Users/
  594  sudo /usr/bin/csrutil status
  595  sudo /usr/sbin/nvram -p | /usr/bin/grep -c "amfi_get_out_of_my_way=1"
  596  sudo /usr/bin/defaults read /Library/Preferences/com.apple.security.libraryvalidation.plist DisableLibraryValidation
  597  sudo /usr/bin/defaults write /Library/Preferences/com.apple.security.libraryvalidation.plist DisableLibraryValidation -bool false
  598  sudo /usr/bin/csrutil enable authenticated-root
  599  sudo /usr/bin/csrutil authenticated-root status
  600  sudo /usr/bin/find /Applications -iname "*.app" -type d -perm -2 -ls
  601  sudo /usr/bin/find /Applications -iname "*.app" -type d -perm -2 -ls
  602   sudo /usr/sbin/find /System/Volumes/Data/System -type d -perm -2 -ls
  603  sudo /usr/sbin/find /System/Volumes/Data/System -type d -perm -2 -ls
  604  sudo /usr/bin/find /System/Volumes/Data/System -type d -perm -2 -ls
  605  sudo /usr/sbin/find /System/Volumes/Data/Library -type d -perm -2 -ls | /usr/bin/grep -v Caches | grep -v Audio
  606  sudo /usr/bin/find /System/Volumes/Data/Library -type d -perm -2 -ls | /usr/bin/grep -v Caches | grep -v Audio
  607  sudo /bin/chmod -R o-w /System/Volumes/Data/Library/Caches/com.apple.aned
  608  sudo /bin/chmod -R o-w /System/Volumes/Data/Library/Caches/com.apple.aned
  609  sudo /usr/bin/pwpolicy -getaccountpolicies | /usr/bin/grep -A 1 'policyAttributeMaximumFailedAuthentications' | /usr/bin/tail -1 | /usr/bin/cut -d'>' -f2 | /usr/bin/cut -d '<' -f1
  610  sudo /usr/bin/grep -E -s '!tty_tickets' /etc/sudoers /etc/sudoers.d/*
  611  sudo -u <username> security unlock-keychain
  612  sudo -u laithrafid security unlock-keychain
  613  sudo -u laithrafid security unlock-keychain /Users/laithrafid/Library/Keychains/login.keychain
  614  sudo -u laithrafid security show-keychain-info /Users/laithrafid/Library/Keychains/login.keychain
  615  sudo -u laithrafid security set-keychain-settings -l /Users/laithrafid/Library/Keychains/login.keychain
  616  sudo -u laithrafid security show-keychain-info /Users/laithrafid/Library/Keychains/login.keychain
  617   sudo /usr/bin/dscl . -read /Users/root AuthenticationAuthority
  618  sudo /usr/sbin/dsenableroot -d
  619  sudo /usr/sbin/dsenableroot -d
  620  sudo /usr/sbin/dsenableroot -d
  621  sudo /usr/sbin/dsenableroot -d
  622  sudo /usr/sbin/dsenableroot -d
  623  sudo /usr/sbin/dsenableroot -d
  624  sudo /usr/sbin/dsenableroot -d
  625  sudo su root
  626  ls
  627  sudo /bin/cat /Library/Security/PolicyBanner.*
  628  sudo /usr/bin/defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText "please take a photo with camera and don't delete it or will alarm Center for internet security"
  629  sudo /bin/cat /Library/Security/PolicyBanner.*
  630  sudo /bin/cat /Library/Security/PolicyBanner.txt
  631   sudo /usr/bin/dscl . -list /Users hint
  632  sudo /usr/bin/defaults read /Library/Preferences/.GlobalPreferences.plist MultipleSessionEnabled
  633  sudo /usr/bin/defaults read /Library/Preferences/.GlobalPreferences.plist MultipleSessionEnabled
  634  sudo -u laithrafid /usr/bin/defaults read /Users/laithrafid/Library/Containers/com.apple.Safari/Data/Library/Preference s/com.apple.Safari AutoOpenSafeDownloads
  635  sudo -u laithrafid /usr/bin/defaults read /Users/laithrafid/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari AutoOpenSafeDownloads
  636  sudo -u laithrafid /usr/bin/defaults read /Users/laithrafid/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari/Data/Library/Preferences/com.apple.Safari AutoOpenSafeDownloads
