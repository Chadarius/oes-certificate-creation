# oes-certificate-creation
Fork of certificate-creation-3.1 script originally created by jmeldrum@novell.com. Updates newly minted certificates for Microfocus/Novell OES servers

[The original script] (https://www.novell.com/communities/coolsolutions/cool_tools/certificate-recreation-script-oes1-and-oes2 "Certificate Re-creation Script for OES1, OES2 and OES 11") is tagged as release 3.1. Any versions after this release are updates with my own, or other contributors', code.

## Change Log
### Version 3.2
Issue - rcowcimomd was attempting to run even though it was running on OES 11.1 and 11.2.
Resolution - Updated so it can check for version 11 or higher instead of just version 11. 