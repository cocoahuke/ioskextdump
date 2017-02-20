# ioskextdump
Dump Kext information from iOS kernel cache. Applicable to the kernel of dump from kernel. The disassembly framework used is [Capstone](http://www.capstone-engine.org/)

[![Contact](https://img.shields.io/badge/contact-@cocoahuke-fbb52b.svg?style=flat)](https://twitter.com/cocoahuke) [![build](https://travis-ci.org/cocoahuke/ioskextdump.svg?branch=master)](https://travis-ci.org/cocoahuke/ioskextdump) [![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/cocoahuke/ioskextdump/blob/master/LICENSE) [![paypal](https://img.shields.io/badge/Donate-PayPal-039ce0.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=EQDXSYW8Z23UY)

<br>

Analyze kernel extension information from iOS kernel cache with arm instructions and extract information, information including the basic IOKit classes construction parameters, inheritance relationship of the IOKit class and subclass methods override.

I finished this dirty project a year ago. Have been tested at iOS8& (32bit iOS9) kernel cache, Does not support iOS10, iOS10 Kext format has some changing, For example, sections of kernel cache is changed `__DATA -> __DATA_CONST`. I haven't studied the kernel of iOS10 yet because I spend time to learn something else

The project will begin from `__DATA.__ mod_init_func` as start point. Get all basic IOKit class construction functions first, and then export Kexts from `__PRELINK_TEXT.__text` one by one. According to basic IOKit classes’s VM address get a different inheritance relationship of IOKit classes of Kexts so this program could analyze different table and compare to its superclass, The result obtained is determine which functions this IOKit class override.
So it needs to execute twice to get the inheritance order of all classes, first time was record information

And also will determine structure of `IOExternalMethodDispatch` if its a Userclient class, but many classes implements their own externalMethod, didn’t use any `IOExternalMethodDispatch`, `IOExternalMethod` or `IOExternalTrap`
 So still need lots of manual analysis to find interface of Kext

# How to use

**Download**
```bash
git clone https://github.com/cocoahuke/ioskextdump.git && cd ioskextdump
```
**Compile and install** to /usr/local/bin/

```bash
make
make install
```
**Usage**
```
Usage: ioskextdump [-e] [-p <access directory path>] <kernelcache>
```
`-e` Specify the export mode  
`-p` Specifiy a folder path that contains the data file or export data file to there  
<br>  
**Example to use**
I left a sample iOS8.3 kernelcache in the test directory, try to run this command  
```
ioskextdump -e -p test test/iPhone6p_8.3_kernel.arm
```
You will see all Inheritance relationship is empty and `allClass_relation.plist saved success` should be at end of program print  
```
Inheritance relationship:
```
<br>

Then try same command removes `-e`
```
ioskextdump -p test test/iPhone6p_8.3_kernel.arm
```
ioskextdump will print contain lists of inheritance and override functions:
```
******** 3:com.apple.iokit.IOAcceleratorFamily2 *******
(0xffffff801ce66998)->OSMetaClass:OSMetaClass call 4 args list
x0:0xffffff801ce93588
x1:IOAccelCLContext2
x2:0xffffff801ce935d8
x3:0xfc8
vtable start from addr 0xffffff801ce8bb70
Inheritance relationship: IOAccelContext2->IOAccelSubmitter2->IOUserClient->IOService->IORegistryEntry->OSObject

overwrite: IOUserClient_IOUserClient loc:0xffffff801ce8bb70 imp:0xffffff801ce66818
overwrite: IOUserClient_~IOUserClient loc:0xffffff801ce8bb78 imp:0xffffff801ce6681c
overwrite: IOUserClient_getMetaClass loc:0xffffff801ce8bba8 imp:0xffffff801ce66834
overwrite: IOUserClient_free loc:0xffffff801ce8bbd8 imp:0xffffff801ce68618
...
```
