Volatility Framework: browser memory scraping
==============================================

This plugin search for user/password patterns in the memory of browsers

Supported browsers:
Google Chrome
Mozila Firefox
Internet Explorer


Supported memory images:
- Windows 7


Python	dependencies:	
Pycrypto & Distorm3 & lxml & Psutils

Install them by executing the command line (with admin rights)
pip install pycrypto && pip install distorm3 && pip install lxml
C:\Python27\python.exe -m pip install psutil



Arguments for the plugin:
--browser chrome / firefox / ie
--website facebook / twitter / linkedin / instagram / pinterest / gmail / youtube / hotmail / outlook azure / amazon / owa
--v for verbose mode



Example case - Windows 7 x86
------------------------------

On a entire memero dump search for credentials in internet explorer browser process memory

```console
python vol.py -f dumpPath --profile Win7SP0x86 search --browser ie

...
```


Contact
-------

To send questions, comments or remarks, just drop an e-mail at
[adriyian@gmail.com](mailto:adriyian@gmail.com)


