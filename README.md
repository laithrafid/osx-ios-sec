##  Apple Datacollection proxying on macos 
Blocked all output streams by lulu and flagged multiple times 

to generate logs 
```
log show --style syslog --predicate 'senderImagePath contains[cd] networkserviceproxy' --info --debug > networkserviceproxy.log
```

other services that been flagged 
*  /usr/libexec/networkserviceproxy
* /System/Library/PrivateFrameworks/AOSUI.framework/Versions/A/XPCServices/AccountProfileRemoteViewService.xpc

