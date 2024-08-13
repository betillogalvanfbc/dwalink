# dwalink
Check for deeplink,weblink,applinks

# How to install
go install -v github.com/betillogalvanfbc/dwalink@latest

# How to use 
dwalink -apk /path/to/.apk
dwalink -h 

# Brute Force EXAMPLES

adb shell am start -n app.beetlebug/.ctf.DeeplinkAccountActivity -d 'https://beetlebug.com/account'

adb shell am start -a android.intent.action.VIEW -d 'insecureshop://com.insecureshop/web?url=http://example.com'

# REFERENCES
https://z4ki.medium.com/android-deep-links-exploitation-4abade4d45b4

https://blog.oversecured.com/Android-security-checklist-webview/

https://nirajkharel.com.np/posts/android-pentesting-deeplinks/
