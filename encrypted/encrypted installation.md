----------------------------------------------------------------------------------------------------
Installation: Encrypted Version
----------------------------------------------------------------------------------------------------
If you're going to use the encrypted version of the Paschwords, in order to protect the module from
tampering or being reverse engineered, add the PS1 script as a function to your profile:

'`nfunction startpaschwords {$powershell = Split-Path $profile; & " $powershell\modules\paschwords\
paschwords.ps1"}'| Add-Content -Path $PROFILE

Ensure that you've copied the following 2 files into the Paschwords directory and made a backup of
Pascwhords.psm1 somewhere that Standard users cannot gain access to it:

EncryptPaschwordsModule.ps1
Paschwords.ps1

Then run: "EncryptPaschwordsModule.ps1 paschwords.psm1"

This will prompt you for a password to encrypt the module. Do not lose this. It will need to be
entered everytime Paschwords is launched, decrypting the module and executing it exclusively in
memory. The script will now ask if you want to delete the Paschwords.psm1 file. Agree. This will
ensure that the only copy of the Paschwords module that exists, other than your backup, will be the
newly created and entirely unique "paschwords.enc" file that will be initiated by the
startpaschwords command you created with the profile function above. You now have a fully encrypted,
secure, HMAC, RBAC, enterprise grade password manager at your disposal.
----------------------------------------------------------------------------------------------------