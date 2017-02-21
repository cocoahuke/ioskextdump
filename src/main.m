//
//  main.m
//  parseDisasmKexts_64
//
//  Created by huke on 3/26/16.
//  Copyright (c) 2016 com.cocoahuke. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "capstone/capstone.h"
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

NSString *EXPORT_CLASSINFO_FILES_PATH = NULL;
//导出多个整理后的信息文件(需要自己创建目录) 或者作为当作导入的路径

//#define FuzzIOKit_data_path @"/Users/huke/Desktop/fuzz_data/" //导出给Fuzz使用的文件夹位置

//#define FuzzIOKit_phase1_export 0 //第一个数据文件输出,内含KEXT名称和类(FuzzIOKit_data1.plist)

char *__DATA = "__DATA";
//iOS10为__DATA_CONST

BOOL exportMode = 0;

NSMutableDictionary *export_allClass_relation; //所有类之间的继承关系
//Save the all classes address to showinheritance relationship

//NSMutableDictionary *export_cracking_inheritFunc; //所有类的继承关系
//Track the inheritance of a single class



NSMutableDictionary *FuzzIOKit_phase1;

uint64_t x0;
uint64_t x1;
uint64_t x2;
uint64_t x3;
uint64_t x4;
uint64_t x5;
uint64_t x6;
uint64_t x7;
uint64_t x8;
uint64_t x9;
uint64_t x10;
uint64_t x11;
uint64_t x12;
uint64_t x13;
uint64_t x14;
uint64_t x15;
uint64_t x16;
uint64_t x17;
uint64_t x18;
uint64_t x19;
uint64_t x20;
uint64_t x21;
uint64_t x22;
uint64_t x23;
uint64_t x24;
uint64_t x25;
uint64_t x26;
uint64_t x27;
uint64_t x28;

uint64_t x29;
uint64_t x30;

uint64_t xzr = 0;

//下面是读取的类信息,来自KEXT_info_export读取出来的
NSDictionary *cracking_inheritFunc; //指定的IO对象继承函数地址
NSDictionary *allClass_relation; //所有类之间的继承关系

//下面是打包的类信息,用于写入文件
NSMutableArray *class_array; //所有类
NSMutableArray *class_newUserClientWithOSDic; //收集信息:重写这个函数的类
NSMutableArray *class_newUserClient; //收集信息:重写这个函数的类
NSMutableDictionary *class_userCleint_methods; //收集信息:客户端类用于externalMethod的函数表

//下面的变量在基础IO类中收集的信息,在这个程序中为全局变量
uint64_t VM_OSMetaClassOSMetaClass; //OSMetaClass::OSMetaClass

uint64_t VM_IOService; //IOService
uint64_t VM_IOUserClient; //IOUserClient


/*ida找IOServicenewUserClientWithOSDic函数技巧,下方的函数是stringFromReturn,卡头就会引用一个字符串"success"*/

uint64_t *IOService_newUserClientWithOSDic; //IOService + 0x458
uint64_t *IOService_newUserClient; //IOService + 0x460

uint64_t *IOUserClient_externalMethod; //IOUserClient + 0x538
uint64_t *IOUserClient_clientMemoryForType; //IOUserClient + 0x588
uint64_t *IOUserClient_getExternalMethodForIndex; //IOUserClient + 0x598
uint64_t *IOUserClient_getTargetAndMethodForIndex; //IOUserClient + 0x5A8
uint64_t *IOUserClient_getExternalTrapForIndex; //IOUserClient + 0x5B8
uint64_t *IOUserClient_getTargetAndTrapForIndex; //IOUserClient + 0x5C0

//除了基础类函数继承,分析其他的类继承函数,从dic(allClass_relation)读取
NSDictionary *IOHIDEventService_copyEvent; //IOHIDEventService + 0x640

struct vtable_func{
    char *func_name;
    uint32_t func_offset;
    uint64_t func_vm;
};

int IOService_vtable_limit = 166;//IOService函数表结束的位置或者IOUserClient_externalMethod-1的位置

static struct userclient_funcList{
    struct vtable_func p0x0;
    struct vtable_func p0x8;
    struct vtable_func p0x10;
    struct vtable_func p0x18;
    struct vtable_func p0x20;
    struct vtable_func p0x28;
    struct vtable_func p0x30;
    struct vtable_func p0x38;
    struct vtable_func p0x40;
    struct vtable_func p0x48;
    struct vtable_func p0x50;
    struct vtable_func p0x58;
    struct vtable_func p0x60;
    struct vtable_func p0x68;
    struct vtable_func p0x70;
    struct vtable_func p0x78;
    struct vtable_func p0x80;
    struct vtable_func p0x88;
    struct vtable_func p0x90;
    struct vtable_func p0x98;
    struct vtable_func p0xa0;
    struct vtable_func p0xa8;
    struct vtable_func p0xb0;
    struct vtable_func p0xb8;
    struct vtable_func p0xc0;
    struct vtable_func p0xc8;
    struct vtable_func p0xd0;
    struct vtable_func p0xd8;
    struct vtable_func p0xe0;
    struct vtable_func p0xe8;
    struct vtable_func p0xf0;
    struct vtable_func p0xf8;
    struct vtable_func p0x100;
    struct vtable_func p0x108;
    struct vtable_func p0x110;
    struct vtable_func p0x118;
    struct vtable_func p0x120;
    struct vtable_func p0x128;
    struct vtable_func p0x130;
    struct vtable_func p0x138;
    struct vtable_func p0x140;
    struct vtable_func p0x148;
    struct vtable_func p0x150;
    struct vtable_func p0x158;
    struct vtable_func p0x160;
    struct vtable_func p0x168;
    struct vtable_func p0x170;
    struct vtable_func p0x178;
    struct vtable_func p0x180;
    struct vtable_func p0x188;
    struct vtable_func p0x190;
    struct vtable_func p0x198;
    struct vtable_func p0x1a0;
    struct vtable_func p0x1a8;
    struct vtable_func p0x1b0;
    struct vtable_func p0x1b8;
    struct vtable_func p0x1c0;
    struct vtable_func p0x1c8;
    struct vtable_func p0x1d0;
    struct vtable_func p0x1d8;
    struct vtable_func p0x1e0;
    struct vtable_func p0x1e8;
    struct vtable_func p0x1f0;
    struct vtable_func p0x1f8;
    struct vtable_func p0x200;
    struct vtable_func p0x208;
    struct vtable_func p0x210;
    struct vtable_func p0x218;
    struct vtable_func p0x220;
    struct vtable_func p0x228;
    struct vtable_func p0x230;
    struct vtable_func p0x238;
    struct vtable_func p0x240;
    struct vtable_func p0x248;
    struct vtable_func p0x250;
    struct vtable_func p0x258;
    struct vtable_func p0x260;
    struct vtable_func p0x268;
    struct vtable_func p0x270;
    struct vtable_func p0x278;
    struct vtable_func p0x280;
    struct vtable_func p0x288;
    struct vtable_func p0x290;
    struct vtable_func p0x298;
    struct vtable_func p0x2a0;
    struct vtable_func p0x2a8;
    struct vtable_func p0x2b0;
    struct vtable_func p0x2b8;
    struct vtable_func p0x2c0;
    struct vtable_func p0x2c8;
    struct vtable_func p0x2d0;
    struct vtable_func p0x2d8;
    struct vtable_func p0x2e0;
    struct vtable_func p0x2e8;
    struct vtable_func p0x2f0;
    struct vtable_func p0x2f8;
    struct vtable_func p0x300;
    struct vtable_func p0x308;
    struct vtable_func p0x310;
    struct vtable_func p0x318;
    struct vtable_func p0x320;
    struct vtable_func p0x328;
    struct vtable_func p0x330;
    struct vtable_func p0x338;
    struct vtable_func p0x340;
    struct vtable_func p0x348;
    struct vtable_func p0x350;
    struct vtable_func p0x358;
    struct vtable_func p0x360;
    struct vtable_func p0x368;
    struct vtable_func p0x370;
    struct vtable_func p0x378;
    struct vtable_func p0x380;
    struct vtable_func p0x388;
    struct vtable_func p0x390;
    struct vtable_func p0x398;
    struct vtable_func p0x3a0;
    struct vtable_func p0x3a8;
    struct vtable_func p0x3b0;
    struct vtable_func p0x3b8;
    struct vtable_func p0x3c0;
    struct vtable_func p0x3c8;
    struct vtable_func p0x3d0;
    struct vtable_func p0x3d8;
    struct vtable_func p0x3e0;
    struct vtable_func p0x3e8;
    struct vtable_func p0x3f0;
    struct vtable_func p0x3f8;
    struct vtable_func p0x400;
    struct vtable_func p0x408;
    struct vtable_func p0x410;
    struct vtable_func p0x418;
    struct vtable_func p0x420;
    struct vtable_func p0x428;
    struct vtable_func p0x430;
    struct vtable_func p0x438;
    struct vtable_func p0x440;
    struct vtable_func p0x448;
    struct vtable_func p0x450;
    struct vtable_func p0x458;
    struct vtable_func p0x460;
    struct vtable_func p0x468;
    struct vtable_func p0x470;
    struct vtable_func p0x478;
    struct vtable_func p0x480;
    struct vtable_func p0x488;
    struct vtable_func p0x490;
    struct vtable_func p0x498;
    struct vtable_func p0x4a0;
    struct vtable_func p0x4a8;
    struct vtable_func p0x4b0;
    struct vtable_func p0x4b8;
    struct vtable_func p0x4c0;
    struct vtable_func p0x4c8;
    struct vtable_func p0x4d0;
    struct vtable_func p0x4d8;
    struct vtable_func p0x4e0;
    struct vtable_func p0x4e8;
    struct vtable_func p0x4f0;
    struct vtable_func p0x4f8;
    struct vtable_func p0x500;
    struct vtable_func p0x508;
    struct vtable_func p0x510;
    struct vtable_func p0x518;
    struct vtable_func p0x520;
    struct vtable_func p0x528;
    struct vtable_func p0x530;
    struct vtable_func p0x538;
    struct vtable_func p0x540;
    struct vtable_func p0x548;
    struct vtable_func p0x550;
    struct vtable_func p0x558;
    struct vtable_func p0x560;
    struct vtable_func p0x568;
    struct vtable_func p0x570;
    struct vtable_func p0x578;
    struct vtable_func p0x580;
    struct vtable_func p0x588;
    struct vtable_func p0x590;
    struct vtable_func p0x598;
    struct vtable_func p0x5a0;
    struct vtable_func p0x5a8;
    struct vtable_func p0x5b0;
    struct vtable_func p0x5b8;
    struct vtable_func p0x5c0;
}userclient_funcList = {
    .p0x0 = {"IOUserClient_IOUserClient",0x0,0x0},
    .p0x8 = {"IOUserClient_~IOUserClient",0x8,0x0},
    .p0x10 = {"OSObject_release",0x10,0x0},
    .p0x18 = {"OSObject_getRetainCount",0x18,0x0},
    .p0x20 = {"OSObject_retain",0x20,0x0},
    .p0x28 = {"OSObject_release",0x28,0x0},
    .p0x30 = {"OSObject_serialize",0x30,0x0},
    .p0x38 = {"IOUserClient_getMetaClass",0x38,0x0},
    .p0x40 = {"OSMetaClassBase_isEqualTo",0x40,0x0},
    .p0x48 = {"OSObject_taggedRetain",0x48,0x0},
    .p0x50 = {"OSObject_taggedRelease",0x50,0x0},
    .p0x58 = {"OSObject_taggedRelease",0x58,0x0},
    .p0x60 = {"IOUserClient_init",0x60,0x0}, //anyClass init
    .p0x68 = {"IOUserClient_free",0x68,0x0}, //anyClass free
    .p0x70 = {"IORegistryEntry_copyProperty",0x70,0x0},
    .p0x78 = {"IORegistryEntry_copyPropertyWithOSString",0x78,0x0},
    .p0x80 = {"IORegistryEntry_copyPropertyWithOSSymbol",0x80,0x0},
    .p0x88 = {"IORegistryEntry_copyParentEntry",0x88,0x0},
    .p0x90 = {"IORegistryEntry_copyChildEntry",0x90,0x0},
    .p0x98 = {"IORegistryEntry_runPropertyAction",0x98,0x0},
    .p0xa0 = {"IOUserClient_init",0xa0,0x0},
    .p0xa8 = {"IORegistryEntry_setPropertyTable",0xa8,0x0},
    .p0xb0 = {"IORegistryEntry_setPropertyWithOSSymbol",0xb0,0x0},
    .p0xb8 = {"IORegistryEntry_setPropertyWithOSString",0xb8,0x0},
    .p0xc0 = {"IORegistryEntry_setProperty5",0xc0,0x0},
    .p0xc8 = {"IORegistryEntry_setProperty4",0xc8,0x0},
    .p0xd0 = {"IORegistryEntry_setProperty3",0xd0,0x0},
    .p0xd8 = {"IORegistryEntry_setProperty2",0xd8,0x0},
    .p0xe0 = {"IORegistryEntry_setProperty1",0xe0,0x0},
    .p0xe8 = {"IORegistryEntry_removeProperty",0xe8,0x0},
    .p0xf0 = {"IORegistryEntry_removeProperty",0xf0,0x0},
    .p0xf8 = {"IORegistryEntry_removeProperty",0xf8,0x0},
    .p0x100 = {"IORegistryEntry_getPropertyOnlyOSSymbol",0x100,0x0},
    .p0x108 = {"IORegistryEntry_getPropertyOnlyOSString",0x108,0x0},
    .p0x110 = {"IORegistryEntry_getPropertyOnlyChar",0x110,0x0},
    .p0x118 = {"IORegistryEntry_getPropertyWithOSSymbol",0x118,0x0},
    .p0x120 = {"IORegistryEntry_getPropertyWithOSString",0x120,0x0},
    .p0x128 = {"IORegistryEntry_getProperty",0x128,0x0},
    .p0x130 = {"IORegistryEntry_copyPropertyWithOSSymbol",0x130,0x0},
    .p0x138 = {"IORegistryEntry_copyPropertyWithOSString",0x138,0x0},
    .p0x140 = {"IORegistryEntry_copyProperty",0x140,0x0},
    .p0x148 = {"IORegistryEntry_dictionaryWithProperties",0x148,0x0},
    .p0x150 = {"IOService_serializeProperties",0x150,0x0}, //IOService re-write
    .p0x158 = {"IORegistryEntry_setProperties",0x158,0x0},
    .p0x160 = {"IORegistryEntry_getParentIterator",0x160,0x0},
    .p0x168 = {"IORegistryEntry_applyToParents",0x168,0x0},
    .p0x170 = {"IORegistryEntry_getParentEntry",0x170,0x0},
    .p0x178 = {"IORegistryEntry_getChildIterator",0x178,0x0},
    .p0x180 = {"IORegistryEntry_applyToChildren",0x180,0x0},
    .p0x188 = {"IORegistryEntry_getChildEntry",0x188,0x0},
    .p0x190 = {"IORegistryEntry_isChild",0x190,0x0},
    .p0x198 = {"IORegistryEntry_isParent",0x198,0x0},
    .p0x1a0 = {"IORegistryEntry_inPlane",0x1a0,0x0},
    .p0x1a8 = {"IORegistryEntry_getDepth",0x1a8,0x0},
    .p0x1b0 = {"IORegistryEntry_attachToParent",0x1b0,0x0},
    .p0x1b8 = {"IORegistryEntry_detachFromParent",0x1b8,0x0},
    .p0x1c0 = {"IORegistryEntry_attachToChild",0x1c0,0x0},
    .p0x1c8 = {"IORegistryEntry_detachFromChild",0x1c8,0x0},
    .p0x1d0 = {"IORegistryEntry_detachAbove",0x1d0,0x0},
    .p0x1d8 = {"IORegistryEntry_detachAll",0x1d8,0x0},
    .p0x1e0 = {"IORegistryEntry_getName",0x1e0,0x0},
    .p0x1e8 = {"IORegistryEntry_copyName",0x1e8,0x0},
    .p0x1f0 = {"IORegistryEntry_compareNames",0x1f0,0x0},
    .p0x1f8 = {"IORegistryEntry_compareName",0x1f8,0x0},
    .p0x200 = {"IORegistryEntry_setNameWithOSSymbol",0x200,0x0},
    .p0x208 = {"IORegistryEntry_setName",0x208,0x0},
    .p0x210 = {"IORegistryEntry_getLocation",0x210,0x0},
    .p0x218 = {"IORegistryEntry_copyLocation",0x218,0x0},
    .p0x220 = {"IORegistryEntry_setLocationWithOSSymbol",0x220,0x0},
    .p0x228 = {"IORegistryEntry_setLocation",0x228,0x0},
    .p0x230 = {"IORegistryEntry_getPath",0x230,0x0},
    .p0x238 = {"IORegistryEntry_getPathComponent",0x238,0x0},
    .p0x240 = {"IORegistryEntry_childFromPath",0x240,0x0},
    .p0x248 = {"IOService_init",0x248,0x0},
    .p0x250 = {"IOService_requestTerminate",0x250,0x0},
    .p0x258 = {"IOService_willTerminate",0x258,0x0},
    .p0x260 = {"IOService_didTerminate",0x260,0x0},
    .p0x268 = {"IOService_nextIdleTimeout",0x268,0x0},
    .p0x270 = {"IOService_systemWillShutdown",0x270,0x0},
    .p0x278 = {"IOService_copyClientWithCategory",0x278,0x0},
    .p0x280 = {"IOService_configureReport",0x280,0x0},
    .p0x288 = {"IOService_updateReport",0x288,0x0},
    .p0x290 = {"IOService_getState",0x290,0x0},
    .p0x298 = {"IOService_registerService",0x298,0x0},
    .p0x2a0 = {"IOService_probe",0x2a0,0x0},
    .p0x2a8 = {"IOService_start",0x2a8,0x0},
    .p0x2b0 = {"IOService_stop",0x2b0,0x0},
    .p0x2b8 = {"IOService_open",0x2b8,0x0},
    .p0x2c0 = {"IOService_close",0x2c0,0x0},
    .p0x2c8 = {"IOService_isOpen",0x2c8,0x0},
    .p0x2d0 = {"IOService_handleOpen",0x2d0,0x0},
    .p0x2d8 = {"IOService_handleClose",0x2d8,0x0},
    .p0x2e0 = {"IOService_handleIsOpen",0x2e0,0x0},
    .p0x2e8 = {"IOService_terminate",0x2e8,0x0},
    .p0x2f0 = {"IOService_finalize",0x2f0,0x0},
    .p0x2f8 = {"IOService_lockForArbitration",0x2f8,0x0},
    .p0x300 = {"IOService_unlockForArbitration",0x300,0x0},
    .p0x308 = {"IOService_terminateClient",0x308,0x0},
    .p0x310 = {"IOService_getBusyState",0x310,0x0},
    .p0x318 = {"IOService_adjustBusy",0x318,0x0},
    .p0x320 = {"IOService_matchPropertyTableWithInt",0x320,0x0},
    .p0x328 = {"IOService_matchPropertyTable",0x328,0x0},
    .p0x330 = {"IOService_matchLocation",0x330,0x0},
    .p0x338 = {"IOService_addNeededResource",0x338,0x0},
    .p0x340 = {"IOService_compareProperty",0x340,0x0},
    .p0x348 = {"IOService_comparePropertyWithOSString",0x348,0x0},
    .p0x350 = {"IOService_compareProperties",0x350,0x0},
    .p0x358 = {"IOService_attach",0x358,0x0},
    .p0x360 = {"IOService_detach",0x360,0x0},
    .p0x368 = {"IOService_getProvider",0x368,0x0},
    .p0x370 = {"IOService_getWorkLoop",0x370,0x0},
    .p0x378 = {"IOService_getProviderIterator",0x378,0x0},
    .p0x380 = {"IOService_getOpenProviderIterator",0x380,0x0},
    .p0x388 = {"IOService_getClient",0x388,0x0},
    .p0x390 = {"IOService_getClientIterator",0x390,0x0},
    .p0x398 = {"IOService_getOpenClientIterator",0x398,0x0},
    .p0x3a0 = {"IOService_callPlatformFunctionWithOSSymbol",0x3a0,0x0},
    .p0x3a8 = {"IOService_callPlatformFunction",0x3a8,0x0},
    .p0x3b0 = {"IOService_getResources",0x3b0,0x0},
    .p0x3b8 = {"IOService_getDeviceMemoryCount",0x3b8,0x0},
    .p0x3c0 = {"IOService_getDeviceMemoryWithIndex",0x3c0,0x0},
    .p0x3c8 = {"IOService_mapDeviceMemoryWithIndex",0x3c8,0x0},
    .p0x3d0 = {"IOService_getDeviceMemory",0x3d0,0x0},
    .p0x3d8 = {"IOService_setDeviceMemory",0x3d8,0x0},
    .p0x3e0 = {"IOService_registerInterrupt",0x3e0,0x0},
    .p0x3e8 = {"IOService_unregisterInterrupt",0x3e8,0x0},
    .p0x3f0 = {"IOService_getInterruptType",0x3f0,0x0},
    .p0x3f8 = {"IOService_enableInterrupt",0x3f8,0x0},
    .p0x400 = {"IOService_disableInterrupt",0x400,0x0},
    .p0x408 = {"IOService_causeInterrupt",0x408,0x0},
    .p0x410 = {"IOService_requestProbe",0x410,0x0},
    .p0x418 = {"IOService_message",0x418,0x0},
    .p0x420 = {"IOService_messageClient",0x420,0x0},
    .p0x428 = {"IOService_messageClients",0x428,0x0},
    .p0x430 = {"IOService_registerInterest",0x430,0x0},
    .p0x438 = {"IOService_applyToProviders",0x438,0x0},
    .p0x440 = {"IOService_applyToClients",0x440,0x0},
    .p0x448 = {"IOService_applyToInterested",0x448,0x0},
    .p0x450 = {"IOService_acknowledgeNotification",0x450,0x0},
    .p0x458 = {"IOService_newUserClientWithOSDic",0x458,0x0},
    .p0x460 = {"IOService_newUserClient",0x460,0x0},
    .p0x468 = {"IOService_stringFromReturn",0x468,0x0},
    .p0x470 = {"IOService_errnoFromReturn",0x470,0x0},
    .p0x478 = {"IOService_PMinit",0x478,0x0},
    .p0x480 = {"IOService_PMstop",0x480,0x0},
    .p0x488 = {"IOService_joinPMtree",0x488,0x0},
    .p0x490 = {"IOService_registerPowerDriver",0x490,0x0},
    .p0x498 = {"IOService_requestPowerDomainState",0x498,0x0},
    .p0x4a0 = {"IOService_activityTickle",0x4a0,0x0},
    .p0x4a8 = {"IOService_setAggressiveness",0x4a8,0x0},
    .p0x4b0 = {"IOService_getAggressiveness",0x4b0,0x0},
    .p0x4b8 = {"IOService_addPowerChild",0x4b8,0x0},
    .p0x4c0 = {"IOService_removePowerChild",0x4c0,0x0},
    .p0x4c8 = {"IOService_setIdleTimerPeriod",0x4c8,0x0},
    .p0x4d0 = {"IOService_setPowerState",0x4d0,0x0},
    .p0x4d8 = {"IOService_maxCapabilityForDomainState",0x4d8,0x0},
    .p0x4e0 = {"IOService_initialPowerStateForDomainState",0x4e0,0x0},
    .p0x4e8 = {"IOService_powerStateForDomainState",0x4e8,0x0},
    .p0x4f0 = {"IOService_powerStateWillChangeTo",0x4f0,0x0},
    .p0x4f8 = {"IOService_powerStateDidChangeTo",0x4f8,0x0},
    .p0x500 = {"IOService_askChangeDown",0x500,0x0},
    .p0x508 = {"IOService_tellChangeDown",0x508,0x0},
    .p0x510 = {"IOService_tellNoChangeDown",0x510,0x0},
    .p0x518 = {"IOService_tellChangeUp",0x518,0x0},
    .p0x520 = {"IOService_allowPowerChange",0x520,0x0},
    .p0x528 = {"IOService_cancelPowerChange",0x528,0x0},
    .p0x530 = {"IOService_powerChangeDone",0x530,0x0},
    .p0x538 = {"IOUserClient_externalMethod",0x538,0x0}, //IOUserClient
    .p0x540 = {"IOUserClient_registerNotificationPort",0x540,0x0},
    .p0x548 = {"IOUserClient_initWithTaskWithOSDic",0x548,0x0},
    .p0x550 = {"IOUserClient_initWithTask",0x550,0x0},
    .p0x558 = {"IOUserClient_clientClose",0x558,0x0},
    .p0x560 = {"IOUserClient_clientDied",0x560,0x0},
    .p0x568 = {"IOUserClient_getService",0x568,0x0},
    .p0x570 = {"IOUserClient_registerNotificationPort",0x570,0x0},
    .p0x578 = {"IOUserClient_getNotificationSemaphore",0x578,0x0},
    .p0x580 = {"IOUserClient_connectClient",0x580,0x0},
    .p0x588 = {"IOUserClient_clientMemoryForType",0x588,0x0},
    .p0x590 = {"IOUserClient_exportObjectToClient",0x590,0x0},
    .p0x598 = {"IOUserClient_getExternalMethodForIndex",0x598,0x0},
    .p0x5a0 = {"IOUserClient_getExternalAsyncMethodForIndex",0x5a0,0x0},
    .p0x5a8 = {"IOUserClient_getTargetAndMethodForIndex",0x5a8,0x0},
    .p0x5b0 = {"IOUserClient_getAsyncTargetAndMethodForIndex",0x5b0,0x0},
    .p0x5b8 = {"IOUserClient_getExternalTrapForIndex",0x5b8,0x0},
    .p0x5c0 = {"IOUserClient_getTargetAndTrapForIndex",0x5c0,0x0},
};

#define IOService_newUserClientWithOSDic_offset 0x458 //IOService + 0x458
#define IOService_newUserClient_offset 0x460 //IOService + 0x460

struct func_nameAnDoffset{
    int a:5;
};

// - - - 分割线

int isUserClient; //判断当前分析的IO类是否为UserClient类.
int isInKEXTnow; //区分当前在分析内核还是内核扩展

//machoH、文件相关函数
uint64_t machoGetVMAddr(uint8_t firstPage[4096],char *segname,char *sectname);
uint64_t machoGetFileAddr(uint8_t firstPage[4096],char *segname,char *sectname);
uint64_t machoGetSize(uint8_t firstPage[4096],char *segname,char *sectname);
uint64_t FilegetSize(char *file_path);

//传入每个KEXT的二进制,返回该KEXT的CFBundleID
char *KextGetBundleID(void *bin);

//获取macho文件的入口,搜集基类信息
void setup_OSMetaClassFunc(char *kr_path);

//分析内核中的ModInit函数,获取各种基本类信息,对后面分析KEXT有帮助
void AnalysisModInitOfKernel(char *kr_path);

//分析每个内核扩展中的ModInit函数,主要的分析汇编代码的函数
void AnalysisModInitOfKEXT(void *bin);

//找出内核二进制中所有有效的内核扩展,并且调用函数开始分析(为解析KEXT的始函数)
void FindKEXTsThenAnalysis(char *kr_path);

//检查是否为有效的内核扩展,有效的话返回1,无效的话返回0
int checkValidKEXTMachOH(void *bin);

//辨认和解析KEXTs中的跳转块(如果不是R12跳转块,返回-1),返回R12跳转地址(ADD R12,PC ~ BX R12)
uint64_t GetR12JumpFromAnalysis(void* bin,uint64_t tar_VMAddr,uint64_t tar_fileoff);

int32_t getMEMOPoffset(csh handle,const cs_insn *insn); //得到str/ldr指令的内存偏移数
int getMEMOPregister(csh handle,const cs_insn *insn); //得到str/ldr指令的偏移寄存器

int getFirstReg(csh handle,const cs_insn *insn); //得到第一个寄存器 *64位新
int getSecondReg(csh handle,const cs_insn *insn); //得到第二个寄存器

uint64_t* getActualVarFromRegName(uint64_t address,int RegName); //根据寄存器名字得到对应的变量

uint64_t getSingleIMM(csh handle,const cs_insn *insn); //得到单条指令的立即数

void* getMemFromAddrOfVM(void* bin,uint64_t CurFunc_FilebaseAddr,uint64_t CurFunc_VMbaseAddr,uint64_t cur_VMAddr);//转换汇编的虚拟内存地址,返回在内存中的实际内容

uint64_t getfileoffFromAddrOfVM(uint64_t CurFunc_FilebaseAddr,uint64_t CurFunc_VMbaseAddr,uint64_t cur_VMAddr);//转换虚拟内存地址,返回文件中偏移地址

uint64_t getPCinThumboffset(uint64_t base,int offset); //计算返回根据thumb指令pc(+2/4)+offset的地址

void ParseConstFunc(char **cn,uint64_t class_self,uint64_t class_super,void *bin,uint64_t VMaddr,uint64_t fileoff);//分析该IO类的函数表等处在_const sec的内容

void find_openType(char *class_name,void *bin,uint64_t newUserClient_vm,uint64_t newUserClient_fileoff);//查找重写了newUserClient的对象中,得到可能的OpenType值

//检查指针指向位置是否在已分配的虚拟内存内,正确返回1
int check_PointerAddrInVM(uint64_t tar_addr);

void AnalysisAllocFunc();//分析Alloc函数,得到vtable

//收集程序的信息的输出宏,按需要使用,以下1为输出,反之为0
#pragma mark define:输出内核对象的信息
#define printInfoOfKernel 1 //如果关掉这个,那么下面的选项对内核对象都不会输出

#pragma mark define:输出对内核对象所收集的地址信息
#define printFuncFinderOfKernel 1 //会输出一些函数地址,用于后面判断内核扩展对象的继承,不受上面所影响

#pragma mark define:输出UserClient类的methods信息
#define printMethodsInfo 1 //输出UserClient类的methods信息

#pragma mark define:在每次分析IO类时输出其归属内核扩展BundleID和序号
#define printKEXTBundleとOR 1 //也可以用于清楚地看清有多少个内核扩展

#pragma mark define:输出IO类注册时BL指令的VM地址
#define printVMAddrOfBL 1 //地址可以用于ida中分析

#pragma mark define:输出IO类注册时进行BL调用时的寄存器
#define printCallMC_r0 1 //输出r0寄存器 该类自己
#define printCallMC_r1 1 //输出r1寄存器 该类名字
#define printCallMC_r2 1 //输出r2寄存器 该类父类
#define printCallMC_r3 1 //输出r3寄存器 该类大小

#pragma mark define:输出每个IO类的vtable起始位置
#define printAddrOfVtable 1 //以IO类自己的地址为开头.后面为IO类函数表

#pragma mark define:输出每个客户端(UserClient)类的methods起始位置
#define printAddrOfMethod 0 //eg.class_name methods table in vm_addr

#pragma mark define:输出每个IO类的MetaClass基础函数位置
#define printMCFunc 0 //比如release,alloc等基础函数位置,alloc为最后一个

#pragma mark define:为继承自IOUserClient的类作标记输出
#define printUserClientTag 0//会从继承类和名字中检查 eg.class_name is from IOUserClient

#pragma mark define:在开始分析IO对象时,输出对象的modInit数量
#define printModInitQt 1//eg.total 1 modInit in kext_bundleID

#pragma mark define:输出str/ldr警告信息
#define printWarnFromStrLdr 0 //输出会包含vm地址,注意不包含内核中的IO类,那些代码已经注释掉了,仅仅会输出内核扩展中的错误,饿;其实大部分时候可以无视这些错误信息

#pragma mark define:输出"没有设置相应的寄存器"警告信息
#define printWarnFromRegDidtSet 0//基本这个信息都是由SP寄存器引起的,当前不考虑栈,所以不影响结果

void initForArrAndDic(); //为收集信息的array或者dictionary初始化

void usage(){
    printf("Usage: ioskextdump [-e] [-p <access directory path>] <kernelcache>\n");
}

int check_file_exist(char *path){
    if(!access(path,F_OK)){
        if(!access(path,R_OK)){
            return 0;
        }
           return -1;
    }
    return -1;
}

int main(int argc, const char * argv[]) {
    
    if(argc==1){
        printf("wrong args\n");usage();exit(1);
    }
    
    for(int i=0;i<argc;i++){
        if(!strcmp(argv[i],"-h")){
            usage();exit(1);
        }
        if(!strcmp(argv[i],"-e")){
            exportMode = YES;
        }
        if(!strcmp(argv[i],"-p")){
            EXPORT_CLASSINFO_FILES_PATH = (i=i+1)>=argc?nil:[[[NSString stringWithUTF8String:argv[i]] stringByDeletingPathExtension]stringByAppendingString:@"/"];
        }
    }
    
    initForArrAndDic();
 
    char *ker_path = argv[argc-1];
    if(check_file_exist(ker_path)){
        printf("(%s) kernel cache file is not exist\n",ker_path);exit(1);
    }
    
    if(exportMode)
        export_allClass_relation = [[NSMutableDictionary alloc]init];
    
    setup_OSMetaClassFunc(ker_path);
    AnalysisModInitOfKernel(ker_path);
    FindKEXTsThenAnalysis(ker_path);
    printf("- - - END - - -\n");
    //收集信息结束后,将信息写入文件
    NSLog(@"Total number of IOkit Classes:%lu",(unsigned long)[class_array count]);
    
    /*if(FuzzIOKit_phase1_export){
        [FuzzIOKit_phase1 writeToFile:[FuzzIOKit_data_path stringByAppendingString:@"FuzzIOKit_phase1.plist"] atomically:YES];
    }*/
    
    if(exportMode){
        if([export_allClass_relation writeToFile:[EXPORT_CLASSINFO_FILES_PATH stringByAppendingString:@"class_relation.plist"] atomically:YES])
            printf("\nallClass_relation.plist saved success\n\n");
        else
            printf("\nallClass_relation.plist writen failed\n\n");
    }
    
    
    //[class_array writeToFile:@"/Desktop/allclass.plist" atomically:YES];
    
    //收集信息
    //[class_newUserClientWithOSDic writeToFile:[EXPORT_CLASSINFO_FILES_PATH stringByAppendingString:@"class_newUserClientWithOSDic.plist"] atomically:YES];
    //[class_newUserClient writeToFile:[EXPORT_CLASSINFO_FILES_PATH stringByAppendingString:@"class_newUserClient.plist"] atomically:YES];
    //[class_userCleint_methods writeToFile:[EXPORT_CLASSINFO_FILES_PATH stringByAppendingString:@"class_userCleint_methods.plist"] atomically:YES];
    //exit(1);
}

//为收集信息的array或者dictionary初始化
#pragma mark imp:为收集信息的array或者dictionary初始化
void initForArrAndDic(){
    FuzzIOKit_phase1 = [[NSMutableDictionary alloc]init];
    NSMutableDictionary *KEXT_INPUT_Mdic = [[NSMutableDictionary alloc]init];
    NSMutableDictionary *KEXT_CLASS_OPENTYPE_Mdic = [[NSMutableDictionary alloc]init];
    [FuzzIOKit_phase1 setObject:KEXT_INPUT_Mdic forKey:@"KEXT_INPUT"];
    [FuzzIOKit_phase1 setObject:KEXT_CLASS_OPENTYPE_Mdic forKey:@"KEXT_CLASS_OPENTYPE"];
    
    //- - - 上面是FuzzIOKit的初始化
    allClass_relation = [NSDictionary dictionaryWithContentsOfFile:[EXPORT_CLASSINFO_FILES_PATH stringByAppendingString:@"class_relation.plist"]];
    //cracking_inheritFunc = [NSDictionary dictionaryWithContentsOfFile:[EXPORT_CLASSINFO_FILES_PATH stringByAppendingString:@"cracking_inheritFunc.plist"]];
    class_array = [[NSMutableArray alloc]init];
    class_newUserClientWithOSDic = [[NSMutableArray alloc]init];
    class_newUserClient = [[NSMutableArray alloc]init];
    class_userCleint_methods = [[NSMutableDictionary alloc]init];
    
    //对指定的IO对象继承的函数变量初始化 供参考
    /*IOHIDEventService_copyEvent = [cracking_inheritFunc objectForKey:@"IOHIDEventService_copyEvent"];
     if(!IOHIDEventService_copyEvent){
     printf("IOHIDEventService_copyEvent is not exist\n");
     exit(1);
     }*/
}


uint64_t machoGetVMAddr(uint8_t firstPage[4096],char *segname,char *sectname){
    if(!segname){
        printf("machoH missing segname,it must need segname\n");
        exit(1);
    }
    
    struct fat_header* fileStartAsFat = (struct fat_header*)firstPage;
    if(fileStartAsFat->magic==FAT_CIGAM||fileStartAsFat->magic==FAT_MAGIC){
        printf("machoH is fat\n");
        exit(1);
    }
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    
    int is32 = 1;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)firstPage+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        //如果没有sectname,代表该seg的VM起始地址
                        return seg->vmaddr;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->addr;
                        }
                        sec = (struct section_64*)((char*)sec + sizeof(struct section_64));
                    }
                    
                }
                
            }
            case LC_SEGMENT:
            {
                struct segment_command *seg = (struct segment_command*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        //如果没有sectname,代表该seg的VM起始地址
                        return seg->vmaddr;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section *sec = (struct section*)((char*)seg + sizeof(struct segment_command));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->addr;
                        }
                        sec = (struct section*)((char*)sec + sizeof(struct section));
                    }
                    
                }
                
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return -1;
}

uint64_t machoGetFileAddr(uint8_t firstPage[4096],char *segname,char *sectname){
    if(!segname){
        printf("machoH missing segname,it must need segname\n");
        exit(1);
    }
    
    struct fat_header* fileStartAsFat = (struct fat_header*)firstPage;
    if(fileStartAsFat->magic==FAT_CIGAM||fileStartAsFat->magic==FAT_MAGIC){
        printf("machoH is fat\n");
        exit(1);
    }
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    
    int is32 = 1;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)firstPage+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->fileoff;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->offset;
                        }
                        sec = (struct section_64*)((char*)sec + sizeof(struct section_64));
                    }
                    
                }
                
            }
            case LC_SEGMENT:
            {
                struct segment_command *seg = (struct segment_command*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->fileoff;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section *sec = (struct section*)((char*)seg + sizeof(struct segment_command));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->offset;
                        }
                        sec = (struct section*)((char*)sec + sizeof(struct section));
                    }
                    
                }
                
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return -1;
}

uint64_t machoGetSize(uint8_t firstPage[4096],char *segname,char *sectname){
    if(!segname){
        printf("machoH missing segname,it must need segname\n");
        exit(1);
    }
    
    struct fat_header* fileStartAsFat = (struct fat_header*)firstPage;
    if(fileStartAsFat->magic==FAT_CIGAM||fileStartAsFat->magic==FAT_MAGIC){
        printf("machoH is fat\n");
        exit(1);
    }
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    
    int is32 = 1;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)firstPage+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->filesize;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->size;
                        }
                        sec = (struct section_64*)((char*)sec + sizeof(struct section_64));
                    }
                    
                }
                
            }
            case LC_SEGMENT:
            {
                struct segment_command *seg = (struct segment_command*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->filesize;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section *sec = (struct section*)((char*)seg + sizeof(struct segment_command));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->size;
                        }
                        sec = (struct section*)((char*)sec + sizeof(struct section));
                    }
                    
                }
                
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return -1;
}

uint64_t FilegetSize(char *file_path){
    struct stat buf;
    
    if ( stat(file_path,&buf) < 0 )
    {
        perror(file_path);
        exit(1);
    }
    return buf.st_size;
}

//传入每个KEXT的二进制,返回该KEXT的CFBundleID
#pragma mark imp:传入每个KEXT的二进制,返回该KEXT的CFBundleID
char *KextGetBundleID(void *bin){
    uint64_t dataSecStart = machoGetFileAddr(bin,"__DATA","__data");
    uint64_t dataSecSize = machoGetSize(bin,"__DATA","__data");
    
    //printf("\n__DATA is 0x%llx-0x%llx\n",dataSecStart,dataSecStart+dataSecSize);
    
    char mh_Magic[] = {'c','o','m','.'};
    char* per_mh = memmem(bin+dataSecStart,dataSecSize,mh_Magic,0x4);
    if(per_mh){
        return per_mh;
    }
    return "******WRONG_KEXT_NAME******";
}

//imp:获取macho文件的入口,搜集基类信息
#pragma mark imp:获取macho文件的入口,搜集基类信息
//0x90ac3e40
void setup_OSMetaClassFunc(char *kr_path){
    
    uint8_t firstPage[4096];
    FILE *fp = fopen(kr_path,"ro");
    if(fread(firstPage,1,4096,fp)!=4096){
        printf("read error\n");
        exit(1);
    }
    fclose(fp);
    uint64_t BaseVMAddr = machoGetVMAddr(firstPage,"__TEXT",NULL);
    uint64_t VMAddrOf__DataModInit = machoGetVMAddr(firstPage,__DATA,"__mod_init_func");
    uint64_t fileoffOf__DataModInit = machoGetFileAddr(firstPage,__DATA,"__mod_init_func");
    uint64_t sizeOf__DataModInit = machoGetSize(firstPage,__DATA,"__mod_init_func");
    
    
    FILE *fp_bin = fopen(kr_path,"r");
    void *bin = malloc(fileoffOf__DataModInit+sizeOf__DataModInit); //__mod_init_func的fileoff+size
    if(fread(bin,1,fileoffOf__DataModInit+sizeOf__DataModInit,fp_bin)!=fileoffOf__DataModInit+sizeOf__DataModInit)
        exit(1);
    uint64_t aFuncInit = 0;
    uint64_t VMOSMetaClass = 0;
    memcpy(&aFuncInit,(bin+fileoffOf__DataModInit) + 0x8,8); //__DATA段__mod_init_func的第二行(+4)
    
    if(aFuncInit<=0||aFuncInit>VMAddrOf__DataModInit||aFuncInit<BaseVMAddr){
        printf("setup_OSMetaClassFunc memcpy 获得地址错误\n");
        exit(1);
    }
    
    fclose(fp_bin);
    
    csh handle;
    cs_insn *insn;
    size_t count;
    
    printf("begin to disasm a FuncInit...\n");
    if(cs_open(CS_ARCH_ARM64,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN,&handle)!=CS_ERR_OK)
        exit(1);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    int64_t curFunc_FilebaseAddr = aFuncInit-BaseVMAddr;
    int64_t curFunc_VMbaseAddr = aFuncInit;
    count = cs_disasm(handle,bin+curFunc_FilebaseAddr,0xFFF,curFunc_VMbaseAddr,0,&insn);
    
    size_t j;
    
    for(j=0;j<count;j++){
        if(count > 0){
            //printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j].address,insn[j].mnemonic,insn[j].op_str);
            
            if(strstr(insn[j].mnemonic,"bl")){
                printf("try to analysis the info...\n\n");
                int acount = cs_op_count(handle,&insn[j],ARM_OP_IMM);
                if (acount){
                    uint64_t bl_addr = getSingleIMM(handle,&insn[j]);
                    if(bl_addr&&VMOSMetaClass!=0)
                        printf("setup_OSMetaClassFunc aFuncInit 存在多个bl_addr\n");
                    if(bl_addr)
                        VMOSMetaClass = bl_addr;
                }
            }
            
            if(strstr(insn[j].mnemonic,"ret")){
                //循环到第一个ret处停止
                break;
            }
        }
    }
    cs_free(insn,count);
    VM_OSMetaClassOSMetaClass = VMOSMetaClass;
    free(bin);
    cs_close(&handle);
    printf("OSMetaClass::OSMetaClass -> 0x%llx\n\n",VMOSMetaClass);
}

//分析内核中的ModInit函数,获取各种基本类信息,对后面分析KEXT有帮助
#pragma mark imp:分析内核中的ModInit函数,获取各种基本类信息,对后面分析KEXT有帮助
void AnalysisModInitOfKernel(char *kr_path){
    
    int KR_DEBUG_ENABLE = 0; //1为激活DEBUG,输出每个基础类的信息
    
    if(printInfoOfKernel){
        KR_DEBUG_ENABLE = 1;
    }
    
    csh handle;
    cs_insn *insn = NULL;
    size_t count = 0;
    
    uint64_t kr_size = FilegetSize(kr_path);
    if(kr_size==0){
        printf("FilegetSize Error\n");
        exit(1);
    }
    
    void *kr_bin = malloc(kr_size);
    FILE *fp = fopen(kr_path,"ro");
    if(fread(kr_bin,1,kr_size,fp)!=kr_size){
        printf("read error\n");
        exit(1);
    }
    fclose(fp);
    
    if(cs_open(CS_ARCH_ARM64,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN,&handle)!=CS_ERR_OK)
        exit(1);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    uint64_t modInitVM = machoGetVMAddr(kr_bin,__DATA,"__mod_init_func");
    uint64_t modInitFileoff = machoGetFileAddr(kr_bin,__DATA,"__mod_init_func");
    uint64_t modInitSize = machoGetSize(kr_bin,__DATA,"__mod_init_func");
    
    printf("total %llu Kernel base Object modInit\n",modInitSize/8);
    printf("starting try to collect basic IOKit class info...\n\n");
    
    //这里少一个,因为第一个mod_Init不算在内,从第二个mod_Init开始才是OSMetaClass
    for(int ab=1;ab<modInitSize/8;ab++){
        uint64_t *eachModInitEntry = getMemFromAddrOfVM(kr_bin,modInitFileoff,modInitVM,modInitVM+ab*8);
        uint64_t eachModInitFileoff = getfileoffFromAddrOfVM(modInitFileoff,modInitVM,*eachModInitEntry);
        
        int64_t curFunc_FilebaseAddr = eachModInitFileoff;
        int64_t curFunc_VMbaseAddr = (*eachModInitEntry);
        if(KR_DEBUG_ENABLE&&printKEXTBundleとOR)
            printf("\nKEXT_DEBUG:********%d*******\n",ab);
        count = cs_disasm(handle,kr_bin+curFunc_FilebaseAddr,0xfff,curFunc_VMbaseAddr,0,&insn);
        if(count > 0){
            
            size_t j;
            
            x0 = 0;
            x1 = 0;
            x2 = 0;
            x3 = 0;
            x4 = 0;
            x5 = 0;
            x6 = 0;
            x7 = 0;
            x8 = 0;
            x9 = 0;
            x10 = 0;
            x11 = 0;
            x12 = 0;
            x13 = 0;
            x14 = 0;
            x15 = 0;
            x16 = 0;
            x17 = 0;
            x18 = 0;
            x19 = 0;
            x20 = 0;
            x21 = 0;
            x22 = 0;
            x23 = 0;
            x24 = 0;
            x25 = 0;
            x26 = 0;
            x27 = 0;
            x28 = 0;
            
            char *cn = "";
            uint64_t class_self = 0;
            uint64_t class_super = 0;
            for(j=0;j<count;j++){
#pragma mark KER_DEBUG:KEXT输出汇编
                //printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j].address,insn[j].mnemonic,insn[j].op_str);
                
#pragma mark KER_DEBUG:ADRP OP
                if(strstr(insn[j].mnemonic,"adr")){
                    int acount = cs_op_count(handle,&insn[j],ARM64_OP_IMM);
                    if(acount>0){
                        //adrp指令将一个地址读进寄存器
                        //eg. adrp x19,#0xffffff801c137000
                        //只需要从有无立即数判断就好了,因为adrp没有多寄存器的形式
                        uint64_t *xx = NULL;
                        uint64_t imm = getSingleIMM(handle,&insn[j]);
                        
                        int i;
                        int s_reg = 0;
                        int acount = cs_op_count(handle,&insn[j],ARM64_OP_REG);
                        if (acount) {
                            if(acount>2){
                                printf("0x%llx adrp的立即数指令寄存器大于2个\n",insn[j].address);
                                exit(1);
                            }
                            for (i = 1; i < acount + 1;i++) {
                                int index = cs_op_index(handle,&insn[j],ARM64_OP_REG,i);
                                if(i==1){
                                    s_reg = insn[j].detail->arm64.operands[index].reg;
                                }
                            }
                        }
                        if(s_reg==0){
                            printf("0x%llx adrp的立即数指令没有获取到第一个寄存器\n",insn[j].address);
                            exit(1);
                        }
                        
                        xx = getActualVarFromRegName(insn[j].address,s_reg);
                        if(xx){
                            *xx = imm;
                        }
                    }
                }
                
#pragma mark KER_DEBUG:MOV OP
                if(strstr(insn[j].mnemonic,"mov")){
                    //movz 一样
                    int acount = cs_op_count(handle,&insn[j],ARM64_OP_REG);
                    if(acount==2){
                        //两个寄存器之间的MOV操作
                        int s_reg = getSecondReg(handle,&insn[j]);
                        if(s_reg==ARM64_REG_SP){
                            //暂时忽略sp
                            //printf("MOV--SP寄存器\n");
                            continue;
                        }
                        uint64_t *xx = getActualVarFromRegName(insn[j].address,s_reg);
                        if(!xx)
                            continue;
                        int f_seg = getFirstReg(handle,&insn[j]);
                        uint64_t *tar_xx = getActualVarFromRegName(insn[j].address,f_seg);
                        if(tar_xx){
                            *tar_xx = *xx;
                        }
                    }
                    else{
                        //MOV一个立即数到寄存器
                        int acount = cs_op_count(handle,&insn[j],ARM64_OP_IMM);
                        if(acount>0){
                            uint64_t *xx = NULL;
                            int64_t imm = getSingleIMM(handle,&insn[j]);
                            int f_reg = getFirstReg(handle,&insn[j]);
                            
                            xx = getActualVarFromRegName(insn[j].address,f_reg);
                            if(xx){
                                *xx = imm;
                            }
                            
                            //ARM64没有movt movw指令
                        }
                    }
                }
                
#pragma mark KER_DEBUG:ADD OP
                if(strstr(insn[j].mnemonic,"add")){
                    //printf("%s\n\n",insn[j].op_str);
                    int acount = cs_op_count(handle,&insn[j],ARM64_OP_REG);
                    if(acount==2){
                        
                        int imm_acount = cs_op_count(handle,&insn[j],ARM64_OP_IMM);
                        if(imm_acount==1){
                            //处理add指令2个寄存器,一个立即数情况
                            int f_reg = getFirstReg(handle,&insn[j]);
                            int s_reg = getSecondReg(handle,&insn[j]);
                            
                            if(s_reg==ARM64_REG_SP)
                                continue; //暂时不涉及栈指针
                            
                            uint64_t *xx = getActualVarFromRegName(insn[j].address,s_reg);
                            if(!xx)
                                continue;
                            uint64_t imm = getSingleIMM(handle,&insn[j]);
                            
                            uint64_t *tar_reg = getActualVarFromRegName(insn[j].address,f_reg);
                            if(tar_reg){
                                *tar_reg = *xx+imm;
                            }else{
                                continue;
                            }
                        }
                        else if(imm_acount>1){
                            printf("0x%llx add超过2个立即数存在\n",insn[j].address);
                            exit(1);
                        }
                        
                        int s_reg = getSecondReg(handle,&insn[j]);
                        //如果操作了两个寄存器...do
                    }
                    if(acount==1){
                        //add的立即数操作
                        printf("add 立即数\n");
                        exit(1);
                    }
                    //如果为add指令...do
                }
                
#pragma mark KER_DEBUG:ORR OP
                if(strstr(insn[j].mnemonic,"orr")){
                    int acount = cs_op_count(handle,&insn[j],ARM64_OP_REG);
                    if(acount==2){
                        int s_reg = getSecondReg(handle,&insn[j]);
                        if(s_reg==ARM64_REG_WZR){
                            int acount = cs_op_count(handle,&insn[j],ARM64_OP_IMM);
                            if(acount==1){
                                //orr的mov同义操作
                                //eg. orr x1, wzr, #0x10
                                //上面指令为0x10和0或运算,值付给x1
                                //所以和mov x1,#0x10 同义
                                uint64_t imm = getSingleIMM(handle,&insn[j]);
                                int f_reg = getFirstReg(handle,&insn[j]);
                                uint64_t *xx = getActualVarFromRegName(insn[j].address,f_reg);
                                if(xx){
                                    *xx = imm;
                                }
                                else{
                                    printf("orr的mov同义操作没有获得寄存器\n");
                                    exit(1);
                                }
                            }
                        }
                    }
                }
                
#pragma mark KER_DEBUG:BL OP
                if(strstr(insn[j].mnemonic,"bl")){
                    //每个mod_initFunc都会有个一个或者多个BL的立即数调用,间接跳转到OSMetaClass:OSMetaClass (待定)
                    int acount = cs_op_count(handle,&insn[j],ARM_OP_IMM);
                    if (acount){
                        uint64_t bl_addr = getSingleIMM(handle,&insn[j]);
                        
                        //检查是否为OSMetaClass
                        if(bl_addr==VM_OSMetaClassOSMetaClass){
                            class_self = x0;
                            class_super = x2;
                            
                            if(exportMode){
                                char *add_x1_str = getMemFromAddrOfVM(kr_bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,x1);
                                [export_allClass_relation setObject:[NSDictionary dictionaryWithObjects:@[[NSNumber numberWithUnsignedLongLong:class_self],[NSString stringWithFormat:@"%s",add_x1_str],[NSNumber numberWithUnsignedLongLong:x2],[NSNumber numberWithUnsignedLongLong:x3]] forKeys:@[@"class_self",@"class_name",@"class_super",@"class_size"]] forKey:[NSString stringWithFormat:@"0x%llx",x0]];
                            }
                            
                            if(KR_DEBUG_ENABLE){
                                if(printVMAddrOfBL)
                                    printf("(0x%llx)->OSMetaClass:OSMetaClass call 4 args list\n",insn[j].address);
                                if(printCallMC_r0)
                                    printf("x0:0x%llx\n",x0);
                            }
                            if(x1==0){
                                if(KR_DEBUG_ENABLE)
                                    if(printCallMC_r1)
                                        printf("x1:0x%llx\n",x1);
                                cn = "unknow classname";
                            }else{
                                char *x1_str = getMemFromAddrOfVM(kr_bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,x1);
                                if(KR_DEBUG_ENABLE&&printCallMC_r1)
                                    printf("x1:%s\n",x1_str);
                                cn = x1_str; //记录类名.待后面查找vtable(kr代码先留着)
                                
                                //下面部分用来搜集类信息,添加代码在下面
                                if(strcmp(x1_str,"IOUserClient")==0){
                                    VM_IOUserClient = x0;
                                    printf("\nIOUserClient -> 0x%llx\n",x0);
                                }
                                if(strcmp(x1_str,"IOService")==0){
                                    VM_IOService = x0;
                                    printf("\nIOService -> 0x%llx\n",x0);
                                }
                                //= = =划分线
                            }
                            if(KR_DEBUG_ENABLE){
                                if(printCallMC_r2)
                                    printf("x2:0x%llx\n",x2);
                                if(printCallMC_r3)
                                    printf("x3:0x%llx\n",x3);
                            }
                        }
                        
                        //printf("r0:0x%x\nr1:0x%x\nr2:0x%x\nr3:0x%x\n\n",r0,r1,r2,r3);
                        //printf("r0:0x%x\n",r1);
                    }
                }
                
                if(strstr(insn[j].mnemonic,"ldr")){
#pragma mark KEXT_DEBUG:LDR OP
                    int reg_acount = cs_op_count(handle,&insn[j],ARM64_OP_REG);
                    if(reg_acount==1){
                        //过滤: ldr指令只有一个寄存器
                        
                        int imm_acount = cs_op_count(handle,&insn[j],ARM64_OP_IMM);
                        //imm_acount是过滤掉了ldr r1,[r8,#4]的这种情况
                        if(imm_acount){
                            //ldr指令将第二个立即数指向的内存读取到第一个寄存器值
                            //eg. ldr x2,#FFFFFF801C14EDC8
                            uint64_t vm_addr = getSingleIMM(handle,&insn[j]);
                            
                            uint64_t *mem = getMemFromAddrOfVM(kr_bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,vm_addr);
                            
                            if(!check_PointerAddrInVM((uint64_t)mem)){
                                printf("0x%llx 指针指向位置在虚拟内存外,跳过该指令\n",insn[j].address);
                                continue;
                            }
                            
                            if(!mem){
                                printf("ldr 无法找到指定位置的内存\n");
                                exit(1);
                            }
                            
                            int f_reg = getFirstReg(handle,&insn[j]);
                            uint64_t *tar_reg = getActualVarFromRegName(insn[j].address,f_reg);
                            if(tar_reg){
                                *tar_reg = *mem;
                            }
                            
                        }
                    }
                }
                
                if(strstr(insn[j].mnemonic,"str")){
#pragma mark KEXT_DEBUG:STR OP
                    //str指令将第一个寄存器值拷贝到另一个寄存器指向的内存
                    //eg. str r1,[r0]
                    int offset = getMEMOPoffset(handle,&insn[j]);
                    if(offset<=0)
                        offset = 0;
                    
                    int reg = getMEMOPregister(handle,&insn[j]); //sec_reg:r0
                    uint64_t *xx = getActualVarFromRegName(insn[j].address,reg);
                    if(!xx)
                        continue;
                    
                    int f_seg = getFirstReg(handle,&insn[j]);
                    uint64_t *tar_reg = getActualVarFromRegName(insn[j].address,f_seg);
                    
                    if(!tar_reg){
                        printf("0x%llx str指令没有得到第一个寄存器\n",insn[j].address);
                        exit(1);
                    }
                    
                    if(*tar_reg<machoGetVMAddr(kr_bin,"__TEXT",NULL)){
                        //即第一个寄存器指向的vm地址不在可执行文件的范围内
                        continue;
                    }
                    
                    ParseConstFunc(&cn,class_self,class_super,kr_bin,*tar_reg,getfileoffFromAddrOfVM(curFunc_FilebaseAddr,curFunc_VMbaseAddr,*tar_reg));
                    
                    uint64_t *mem = getMemFromAddrOfVM(kr_bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,(*xx + offset));
                    
                    if(!check_PointerAddrInVM((uint64_t)mem)){
                        printf("0x%llx 指针指向位置在虚拟内存外,跳过该指令\n",insn[j].address);
                        continue;
                    }
                    
                    if(mem)
                        *mem = *tar_reg; //修改第二个寄存器指向内存处
                    else{
                        printf("str 无法找到指定位置的内存\n");
                        exit(1);
                    }
                    //printf("result:0x%x\n",*mem);
                }
                
#pragma mark KER_DEBUG:RET OP
                if(strstr(insn[j].mnemonic,"ret")){
                    //到pop指令处停止
                    break;
                }
                
                //printf("%s\n\n",insn[j].op_str);
            }
            cs_free(insn,count);
        }
        else{
            printf("ERROR: Failed to disassemble given code!\n");
        }
    }
    free(kr_bin);
    cs_close(&handle);
}

//分析每个内核扩展中的ModInit函数,主要的分析汇编代码的函数
#pragma mark imp:分析每个内核扩展中的ModInit函数,主要的分析汇编代码的函数
void AnalysisModInitOfKEXT(void *bin){
    int KEXT_PRINT_EACH_CLASS_INFO = 1;
    isInKEXTnow = 1;
    csh handle;
    cs_insn *insn;
    size_t count;
    
    if(cs_open(CS_ARCH_ARM64,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN,&handle)!=CS_ERR_OK){
        printf("AnalysisModInitOfKEXT cs_open出错\n");
        exit(1);
    }
    
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    uint64_t modInitVM = machoGetVMAddr(bin,__DATA,"__mod_init_func");
    uint64_t modInitFileoff = machoGetFileAddr(bin,__DATA,"__mod_init_func");
    uint64_t modInitSize = machoGetSize(bin,__DATA,"__mod_init_func");
    
    //printf("The kex's range of vm: 0x%llx-0x%llx\n",KEXT_vmStart,KEXT_vmEnd);
    
    if(printModInitQt)
        printf("\ntotal %llu modInit in %s\n",modInitSize/8,KextGetBundleID(bin)); //will 修改
    //printf("starting check each class...\n\n");
    
    /*if(FuzzIOKit_phase1_export){
        NSMutableDictionary *fuzz_new_class_list = [[NSMutableDictionary alloc]init];
        NSMutableDictionary *KEXT_INPUT_Mdic = [FuzzIOKit_phase1 objectForKey:@"KEXT_INPUT"];
        [KEXT_INPUT_Mdic setObject:fuzz_new_class_list forKey:[NSString stringWithUTF8String:KextGetBundleID(bin)]];
    }*/
    
    for(int ab=0;ab<modInitSize/8;ab++){
        uint64_t *eachModInitEntry = getMemFromAddrOfVM(bin,modInitFileoff,modInitVM,modInitVM+ab*8);
        uint64_t eachModInitFileoff = getfileoffFromAddrOfVM(modInitFileoff,modInitVM,*eachModInitEntry);
        
        int64_t curFunc_FilebaseAddr = eachModInitFileoff;//0x107c //0x278c //0x186b4
        int64_t curFunc_VMbaseAddr = (*eachModInitEntry);//0x90caa07c //0x90cab78c //0x90cc16b4
        
        if(KEXT_PRINT_EACH_CLASS_INFO&&printKEXTBundleとOR)
            printf("\n******** %d:%s *******\n",ab,KextGetBundleID(bin));
        count = cs_disasm(handle,bin+curFunc_FilebaseAddr,0xfff,curFunc_VMbaseAddr,0,&insn);
        if(count > 0){
            
            size_t j;
            
            x0 = 0;
            x1 = 0;
            x2 = 0;
            x3 = 0;
            x4 = 0;
            x5 = 0;
            x6 = 0;
            x7 = 0;
            x8 = 0;
            x9 = 0;
            x10 = 0;
            x11 = 0;
            x12 = 0;
            x13 = 0;
            x14 = 0;
            x15 = 0;
            x16 = 0;
            x17 = 0;
            x18 = 0;
            x19 = 0;
            x20 = 0;
            x21 = 0;
            x22 = 0;
            x23 = 0;
            x24 = 0;
            x25 = 0;
            x26 = 0;
            x27 = 0;
            x28 = 0;
            
            char *cn = "";
            uint64_t class_self = 0;
            uint64_t class_super = 0;
            for(j=0;j<count;j++){
#pragma mark KEXT_DEBUG:输出汇编
                //printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j].address,insn[j].mnemonic,insn[j].op_str);
                //printf("r0:0x%x r1:0x%x r2:0x%x r3:0x%x\n",r0,r1,r2,r3);
                
#pragma mark KEXT_DEBUG:ADRP OP
                if(strstr(insn[j].mnemonic,"adr")){
                    int acount = cs_op_count(handle,&insn[j],ARM64_OP_IMM);
                    if(acount>0){
                        //adrp指令将一个地址读进寄存器
                        //eg. adrp x19,#0xffffff801c137000
                        //只需要从有无立即数判断就好了,因为adrp没有多寄存器的形式
                        uint64_t *xx = NULL;
                        uint64_t imm = getSingleIMM(handle,&insn[j]);
                        
                        int i;
                        int s_reg = 0;
                        int acount = cs_op_count(handle,&insn[j],ARM64_OP_REG);
                        if (acount) {
                            if(acount>2){
                                printf("0x%llx adrp的立即数指令寄存器大于2个\n",insn[j].address);
                                exit(1);
                            }
                            for (i = 1; i < acount + 1;i++) {
                                int index = cs_op_index(handle,&insn[j],ARM64_OP_REG,i);
                                if(i==1){
                                    s_reg = insn[j].detail->arm64.operands[index].reg;
                                }
                            }
                        }
                        if(s_reg==0){
                            printf("0x%llx adrp的立即数指令没有获取到第一个寄存器\n",insn[j].address);
                            exit(1);
                        }
                        
                        xx = getActualVarFromRegName(insn[j].address,s_reg);
                        if(xx){
                            *xx = imm;
                        }
                    }
                }
                
#pragma mark KEXT_DEBUG:MOV OP
                if(strstr(insn[j].mnemonic,"mov")){
                    //movz 一样
                    int acount = cs_op_count(handle,&insn[j],ARM64_OP_REG);
                    if(acount==2){
                        //两个寄存器之间的MOV操作
                        int s_reg = getSecondReg(handle,&insn[j]);
                        if(s_reg==ARM64_REG_SP){
                            //暂时忽略sp
                            //printf("MOV--SP寄存器\n");
                            continue;
                        }
                        uint64_t *xx = getActualVarFromRegName(insn[j].address,s_reg);
                        if(!xx)
                            continue;
                        int f_seg = getFirstReg(handle,&insn[j]);
                        uint64_t *tar_xx = getActualVarFromRegName(insn[j].address,f_seg);
                        if(tar_xx){
                            *tar_xx = *xx;
                        }
                    }
                    else{
                        //MOV一个立即数到寄存器
                        int acount = cs_op_count(handle,&insn[j],ARM64_OP_IMM);
                        if(acount>0){
                            uint64_t *xx = NULL;
                            int64_t imm = getSingleIMM(handle,&insn[j]);
                            int f_reg = getFirstReg(handle,&insn[j]);
                            
                            xx = getActualVarFromRegName(insn[j].address,f_reg);
                            if(xx){
                                *xx = imm;
                            }
                            
                            //ARM64没有movt movw指令
                        }
                    }
                }
                
#pragma mark KEXT_DEBUG:ADD OP
                if(strstr(insn[j].mnemonic,"add")){
                    //printf("%s\n\n",insn[j].op_str);
                    int acount = cs_op_count(handle,&insn[j],ARM64_OP_REG);
                    if(acount==2){
                        
                        int imm_acount = cs_op_count(handle,&insn[j],ARM64_OP_IMM);
                        if(imm_acount==1){
                            //处理add指令2个寄存器,一个立即数情况
                            int f_reg = getFirstReg(handle,&insn[j]);
                            int s_reg = getSecondReg(handle,&insn[j]);
                            
                            if(s_reg==ARM64_REG_SP)
                                continue; //暂时不涉及栈指针
                            
                            uint64_t *xx = getActualVarFromRegName(insn[j].address,s_reg);
                            if(!xx)
                                continue;
                            uint64_t imm = getSingleIMM(handle,&insn[j]);
                            
                            uint64_t *tar_reg = getActualVarFromRegName(insn[j].address,f_reg);
                            if(tar_reg){
                                *tar_reg = *xx+imm;
                            }else{
                                continue;
                            }
                        }
                        else if(imm_acount>1){
                            printf("0x%llx add超过2个立即数存在\n",insn[j].address);
                            exit(1);
                        }
                        
                        int s_reg = getSecondReg(handle,&insn[j]);
                        //如果操作了两个寄存器...do
                    }
                    if(acount==1){
                        //add的立即数操作
                        printf("add 立即数\n");
                        exit(1);
                    }
                    //如果为add指令...do
                }
                
#pragma mark KER_DEBUG:ORR OP
                if(strstr(insn[j].mnemonic,"orr")){
                    int acount = cs_op_count(handle,&insn[j],ARM64_OP_REG);
                    if(acount==2){
                        int s_reg = getSecondReg(handle,&insn[j]);
                        if(s_reg==ARM64_REG_WZR){
                            int acount = cs_op_count(handle,&insn[j],ARM64_OP_IMM);
                            if(acount==1){
                                //orr的mov同义操作
                                //eg. orr x1, wzr, #0x10
                                //上面指令为0x10和0或运算,值付给x1
                                //所以和mov x1,#0x10 同义
                                uint64_t imm = getSingleIMM(handle,&insn[j]);
                                int f_reg = getFirstReg(handle,&insn[j]);
                                uint64_t *xx = getActualVarFromRegName(insn[j].address,f_reg);
                                if(xx){
                                    *xx = imm;
                                }
                                else{
                                    printf("orr的mov同义操作没有获得寄存器\n");
                                    exit(1);
                                }
                            }
                        }
                    }
                }
                
#pragma mark KEXT_DEBUG:BL OP
                if(strstr(insn[j].mnemonic,"bl")){
                    //printf("当前内核扩展的启示地址:0x%x\n",);
                    //每个mod_initFunc都会有个一个或者多个BL的立即数调用,间接跳转到OSMetaClass:OSMetaClass (待定)
                    int acount = cs_op_count(handle,&insn[j],ARM64_OP_IMM);
                    if (acount){
                        uint64_t bl_addr = getSingleIMM(handle,&insn[j]);
                        
                        uint64_t bl_fileoff = getfileoffFromAddrOfVM(curFunc_FilebaseAddr,curFunc_VMbaseAddr,bl_addr);
                        
                        uint64_t x16FuncCall = GetR12JumpFromAnalysis(bin,bl_addr,bl_fileoff);
                        
                        isUserClient = 0;
                        //检查是否为OSMetaClass
                        if(x16FuncCall==VM_OSMetaClassOSMetaClass){
                            if(KEXT_PRINT_EACH_CLASS_INFO){
                                if(printVMAddrOfBL)
                                    printf("(0x%llx)->OSMetaClass:OSMetaClass call 4 args list\n",insn[j].address);
                                class_self = x0;
                                class_super = x2;
                                if(printCallMC_r0)
                                    printf("x0:0x%llx\n",x0);
                                
                                if(exportMode){
                                    char *add_x1_str = getMemFromAddrOfVM(bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,x1);
                                    [export_allClass_relation setObject:[NSDictionary dictionaryWithObjects:@[[NSNumber numberWithUnsignedLongLong:class_self],[NSString stringWithFormat:@"%s",add_x1_str],[NSNumber numberWithUnsignedLongLong:x2],[NSNumber numberWithUnsignedLongLong:x3]] forKeys:@[@"class_self",@"class_name",@"class_super",@"class_size"]] forKey:[NSString stringWithFormat:@"0x%llx",x0]];
                                }
                            }
                            if(x1==0){
                                if(KEXT_PRINT_EACH_CLASS_INFO&&printCallMC_r1)
                                    printf("x1:0x%llx\n",x1);
                                cn = "unknow classname";
                            }else{
                                char *x1_str = getMemFromAddrOfVM(bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,x1);
                                [class_array addObject:[NSString stringWithFormat:@"%s",x1_str]];//添加类名
                                
                                /*if(FuzzIOKit_phase1_export){
                                    NSMutableDictionary *KEXT_INPUT_Mdic = [FuzzIOKit_phase1 objectForKey:@"KEXT_INPUT"];
                                    NSMutableDictionary *fuzz_new_class_list = [KEXT_INPUT_Mdic objectForKey:[NSString stringWithFormat:@"%s",KextGetBundleID(bin)]];
                                    [fuzz_new_class_list setObject:@"non" forKey:[NSString stringWithFormat:@"%s",x1_str]];
                                }//添加类名给FuzzIOKit*/
                                
                                if(KEXT_PRINT_EACH_CLASS_INFO&&printCallMC_r1)
                                    printf("x1:%s\n",x1_str);
                                
                                //添加更多基类信息,添加代码在下面
                                if(x2==VM_IOUserClient||strstr(x1_str,"UserClient")){
                                    isUserClient = 1;
                                    if(printUserClientTag)
                                        printf("%s is from IOUserClient\n",(char*)x1_str);
                                }
                                
                                //= = = 划分线
                                cn = x1_str; //记录类名.待后面查找vtable
                            }
                            if(KEXT_PRINT_EACH_CLASS_INFO){
                                if(printCallMC_r2)
                                    printf("x2:0x%llx\n",x2);
                                //char *x1_str = getMemFromAddrOfVM(bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,x1);
                                if(printCallMC_r3)
                                    printf("x3:0x%llx\n",x3);
                            }
                        }
                        
                        //printf("r0:0x%x\nr1:0x%x\nr2:0x%x\nr3:0x%x\n\n",r0,r1,r2,r3);
                        //printf("r0:0x%x\n",r1);
                    }
                }
                
                if(strstr(insn[j].mnemonic,"ldr")){
#pragma mark KEXT_DEBUG:LDR OP
                    int reg_acount = cs_op_count(handle,&insn[j],ARM64_OP_REG);
                    if(reg_acount==1){
                        //过滤: ldr指令只有一个寄存器
                        
                        int imm_acount = cs_op_count(handle,&insn[j],ARM64_OP_IMM);
                        //imm_acount是过滤掉了ldr r1,[r8,#4]的这种情况
                        if(imm_acount){
                            //ldr指令将第二个立即数指向的内存读取到第一个寄存器值
                            //eg. ldr x2,#FFFFFF801C14EDC8
                            uint64_t vm_addr = getSingleIMM(handle,&insn[j]);
                            
                            uint64_t *mem = getMemFromAddrOfVM(bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,vm_addr);
                            
                            if(!check_PointerAddrInVM((uint64_t)mem)){
                                printf("0x%llx 指针指向位置在虚拟内存外,跳过该指令\n",insn[j].address);
                                continue;
                            }
                            
                            if(!mem){
                                printf("ldr 无法找到指定位置的内存\n");
                                exit(1);
                            }
                            
                            int f_reg = getFirstReg(handle,&insn[j]);
                            uint64_t *tar_reg = getActualVarFromRegName(insn[j].address,f_reg);
                            if(tar_reg){
                                *tar_reg = *mem;
                            }
                            
                        }
                    }
                }
                
                if(strstr(insn[j].mnemonic,"str")){
#pragma mark KEXT_DEBUG:STR OP
                    //str指令将第一个寄存器值拷贝到另一个寄存器指向的内存
                    //eg. str r1,[r0]
                    int offset = getMEMOPoffset(handle,&insn[j]);
                    if(offset<=0)
                        offset = 0;
                    
                    int reg = getMEMOPregister(handle,&insn[j]); //sec_reg:r0
                    uint64_t *xx = getActualVarFromRegName(insn[j].address,reg);
                    if(!xx)
                        continue;
                    
                    int f_seg = getFirstReg(handle,&insn[j]);
                    uint64_t *tar_reg = getActualVarFromRegName(insn[j].address,f_seg);
                    
                    if(!tar_reg){
                        printf("0x%llx str指令没有得到第一个寄存器\n",insn[j].address);
                        exit(1);
                    }
                    
                    if(*tar_reg<machoGetVMAddr(bin,"__TEXT",NULL)){
                        //即第一个寄存器指向的vm地址不在可执行文件的范围内
                        continue;
                    }
                    
                    ParseConstFunc(&cn,class_self,class_super,bin,*tar_reg,getfileoffFromAddrOfVM(curFunc_FilebaseAddr,curFunc_VMbaseAddr,*tar_reg));
                    
                    uint64_t *mem = getMemFromAddrOfVM(bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,(*xx + offset));
                    
                    if(!check_PointerAddrInVM((uint64_t)mem)){
                        printf("0x%llx 指针指向位置在虚拟内存外,跳过该指令\n",insn[j].address);
                        continue;
                    }
                    
                    if(mem)
                        *mem = *tar_reg; //修改第二个寄存器指向内存处
                    else{
                        printf("str 无法找到指定位置的内存\n");
                        exit(1);
                    }
                    //printf("result:0x%x\n",*mem);
                }
                
                
                if(strstr(insn[j].mnemonic,"ret")){
#pragma mark KEXT_DEBUG:RET OP
                    //到pop指令处停止
                    break;
                }
                
                if(!strcmp(insn[j].mnemonic,"b")){
#pragma mark KEXT_DEBUG:B OP
                    //到b.w指令处停止
                    //这个检查只有在KEXT有.内核中的类不需要
                    //printf("有b指令!!!\n");
                    break;
                }
                
                //printf("%s\n\n",insn[j].op_str);
            }
            cs_free(insn,count);
        }
        else{
            printf("ERROR: Failed to disassemble given code!\n");
        }
    }
    cs_close(&handle);
}

//找出内核二进制中所有有效的内核扩展,并且调用函数开始分析(为解析KEXT的始函数)
#pragma mark imp:找出内核二进制中所有有效的内核扩展,并且调用函数开始分析(为解析KEXT的始函数)
void FindKEXTsThenAnalysis(char *kr_path){
    uint64_t kr_size = FilegetSize(kr_path);
    if(kr_size==0){
        printf("FilegetSize Error\n");
        exit(1);
    }
    
    void *kr_bin = malloc(kr_size);
    FILE *fp = fopen(kr_path,"ro");
    if(fread(kr_bin,1,kr_size,fp)!=kr_size){
        printf("read error\n");
        exit(1);
    }
    fclose(fp);
    
    uint64_t fileoff = machoGetFileAddr(kr_bin,"__PRELINK_TEXT",NULL);
    uint64_t filesize = machoGetSize(kr_bin,"__PRELINK_TEXT",NULL);
    uint64_t vmoff = machoGetVMAddr(kr_bin,"__PRELINK_TEXT",NULL);
    
    if(fileoff==0||filesize==0||vmoff==0){
        printf("FindKEXTsThenAnalysis 内核二进制__PRELINK_TEXT信息错误\n");
        exit(1);
    }
    
    char mh_Magic[] = {0xcf,0xfa,0xed,0xfe};
    uint64_t per_mh = (uint64_t)memmem(kr_bin+fileoff,filesize,mh_Magic,0x4);
    
    int i = 0;
    //real_kext = 0;
    while(1) {
        if(!per_mh)
            break;
        if(checkValidKEXTMachOH((void*)per_mh)){
            //下面的是经过检查后正确的内核扩展KEXTs(添加处理代码加在下面,比如名字过滤)
            char *kext_id = KextGetBundleID((void*)per_mh);
#pragma mark KEXT_LIST:列出所有内核扩展(添加过滤信息)
            //下面输出的per_mh是该程序内存中的地址..实际上没有什么意义
            //printf("%d.macho:0x%llx %s\n",i,per_mh,kext_id);
            //if(!strcmp(kext_id,"com.apple.iokit.IOHIDFamily"))
            
            //下面的几行代码
            uint64_t kext_start = machoGetVMAddr(per_mh,"__TEXT",NULL);
            uint64_t kext_end = machoGetVMAddr(per_mh,"__LINKEDIT",NULL) + machoGetSize(per_mh,"__LINKEDIT",NULL);
            uint64_t target_vm = 0xffffff801bff18d8; //target_vm为目标内存地址
            printf("%d.0x%llx - 0x%llx %s\n",i,kext_start,kext_end,kext_id);
            
            if(target_vm>=kext_start&&target_vm<=kext_end){
                printf("%d.0x%llx - 0x%llx %s\n",i,kext_start,kext_end,kext_id);
                exit(1);
            }
            
            AnalysisModInitOfKEXT(per_mh);
            //= = = 分割线
            i++;
        }
        //printf("%d: per_mh is 0x%llx,",i,per_mh);
        //printf("per_mh+4: 0x%llx, per_size: 0x%llx\n",per_mh+4,filesize-(per_mh-(uint64_t)seg_kexts+4));
        per_mh = (uint64_t)memmem((const void *)per_mh+4,filesize-((uint64_t)per_mh-(uint64_t)(kr_bin+fileoff)+4),mh_Magic,0x4);
    }
}

//检查是否为有效的内核扩展,有效的话返回1,无效的话返回0
#pragma mark imp:检查是否为有效的内核扩展,有效的话返回1,无效的话返回0
int checkValidKEXTMachOH(void *bin){
    struct mach_header *mh = (struct mach_header*)bin;
    
    //判断32还是64
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        printf("it's 32 bit mach-o file\n");
        //这个程序只适用于64内核二进制
        exit(1);
        
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        //printf("it's 64 bit mach-o file\n");
    }
    if(mh->flags!=1){
        //根据flags判断是否有效
        return 0;
    }
    
    uint64_t check_initFunc = machoGetVMAddr((void*)mh,__DATA,"__mod_init_func");
    if(check_initFunc==-1){
        //检查是否有类信息保存在__mod_init_func
        return 0;
    }
    
    return 1;
}

//辨认和解析KEXTs中的跳转块(如果不是R12跳转块,返回-1),返回R12跳转地址(ADD R12,PC ~ BX R12)
#pragma mark imp:辨认和解析KEXTs中的跳转块(如果不是R12跳转块,返回-1),返回R12跳转地址(ADD R12,PC ~ BX R12)
uint64_t GetR12JumpFromAnalysis(void* bin,uint64_t tar_VMAddr,uint64_t tar_fileoff){
    
    csh handle;
    cs_insn *insn;
    size_t count;
    
    if(cs_open(CS_ARCH_ARM64,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN,&handle)!=CS_ERR_OK)
        exit(1);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    count = cs_disasm(handle,bin+tar_fileoff,0xFFF,tar_VMAddr,0,&insn);
    //printf("bin+tar_fileoff = 0x%llx\n",bin+tar_fileoff);
    size_t j;
    
    for(j=0;j<count;j++){
        if(count > 0){
            
            //输出汇编
            //printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j].address,insn[j].mnemonic,insn[j].op_str);
            
            if(j==0){
                //判断第一行
                if(strstr(insn[j].mnemonic,"adr")){
                    int f_reg = getFirstReg(handle,&insn[j]);
                    if(f_reg!=ARM64_REG_X16){
                        cs_free(insn,count);
                        cs_close(&handle);
                        return 0;
                    }
                }
                else{
                    cs_free(insn,count);
                    cs_close(&handle);
                    return 0;
                }
            }
            
            if(strstr(insn[j].mnemonic,"adr")){
                int acount = cs_op_count(handle,&insn[j],ARM64_OP_IMM);
                if(acount>0){
                    //adrp指令将一个地址读进寄存器
                    //eg. adrp x19,#0xffffff801c137000
                    //只需要从有无立即数判断就好了,因为adrp没有多寄存器的形式
                    uint64_t *xx = NULL;
                    uint64_t imm = getSingleIMM(handle,&insn[j]);
                    
                    int i;
                    int s_reg = 0;
                    int acount = cs_op_count(handle,&insn[j],ARM64_OP_REG);
                    if (acount) {
                        if(acount>2){
                            printf("0x%llx adrp的立即数指令寄存器大于2个\n",insn[j].address);
                            exit(1);
                        }
                        for (i = 1; i < acount + 1;i++) {
                            int index = cs_op_index(handle,&insn[j],ARM64_OP_REG,i);
                            if(i==1){
                                s_reg = insn[j].detail->arm64.operands[index].reg;
                            }
                        }
                    }
                    if(s_reg==0){
                        printf("0x%llx adrp的立即数指令没有获取到第一个寄存器\n",insn[j].address);
                        exit(1);
                    }
                    
                    xx = getActualVarFromRegName(insn[j].address,s_reg);
                    if(xx){
                        *xx = imm;
                    }
                }
            }
            
            if(strstr(insn[j].mnemonic,"ldr")){
                int reg_acount = cs_op_count(handle,&insn[j],ARM64_OP_REG);
                if(reg_acount==1){
                    //过滤: ldr指令只有一个寄存器
                    
                    int imm_acount = cs_op_count(handle,&insn[j],ARM64_OP_MEM);
                    //过滤: ldr指令包含内存偏移操作
                    if(imm_acount){
                        //ldr指令将第二个立即数加上偏移指向的内存读取到第一个寄存器值
                        //eg. ldr x16, [x16,#0x80]
                        
                        int offset = getMEMOPoffset(handle,&insn[j]);
                        int reg = getMEMOPregister(handle,&insn[j]);
                        
                        uint64_t *xx = getActualVarFromRegName(insn[j].address,reg);
                        if(xx){
                            *xx = *xx + offset;
                        }
                        else{
                            printf("0x%llx,ldr指令寻址时无法获得被偏移的寄存器\n",insn[j].address);
                            exit(1);
                        }
                        
                        uint64_t *mem = getMemFromAddrOfVM(bin,tar_fileoff,tar_VMAddr,*xx);
                        
                        if(!check_PointerAddrInVM((uint64_t)mem)){
                            printf("0x%llx 指针指向位置在虚拟内存外,跳过该指令\n",insn[j].address);
                            continue;
                        }
                        
                        if(!mem){
                            printf("ldr 无法找到指定位置的内存\n");
                            exit(1);
                        }
                        
                        int f_reg = getFirstReg(handle,&insn[j]);
                        uint64_t *tar_reg = getActualVarFromRegName(insn[j].address,f_reg);
                        if(tar_reg){
                            *tar_reg = *mem;
                        }
                        
                    }
                }
            }
            
            if(strstr(insn[j].mnemonic,"br")){
                
                int acount = cs_op_count(handle,&insn[j],ARM64_OP_REG);
                if (acount==1){
                    int i,x16IF;
                    for (i = 1; i < acount + 1;i++) {
                        int index = cs_op_index(handle,insn,ARM64_OP_REG,i);
                        x16IF = insn[j].detail->arm64.operands[index].reg;
                        if(x16IF==ARM64_REG_X16){
                            cs_free(insn,count);
                            cs_close(&handle);
                            return x16;
                        }
                    }
                }
            }
            
            if(strstr(insn[j].mnemonic,"br")){
                //循环到第一个bx处停止
                break;
            }
        }
    }
    cs_free(insn,count);
    cs_close(&handle);
    return 0;
}

//得到str/ldr指令的内存偏移数
#pragma mark imp:得到str/ldr指令的内存偏移数
int32_t getMEMOPoffset(csh handle,const cs_insn *insn){
    int32_t i,offset;
    int acount = cs_op_count(handle,insn,ARM64_OP_MEM);
    if (acount) {
        if(acount>1)
            printf("getMEMOPoffset The offset more than one\n");
        for (i = 1; i < acount + 1;/*i++*/) {
            int index = cs_op_index(handle,insn,ARM64_OP_MEM,i);
            offset = insn->detail->arm64.operands[index].mem.disp;
            return offset;
        }
    }
    return 0;
}

//得到str/ldr指令的偏移寄存器
#pragma mark imp:得到str/ldr指令的偏移寄存器
int getMEMOPregister(csh handle,const cs_insn *insn){
    uint32_t i,offset;
    int acount = cs_op_count(handle,insn,ARM64_OP_MEM);
    if (acount) {
        if(acount>1)
            printf("getMEMOPregister The offset more than one\n");
        for (i = 1; i < acount + 1;/*i++*/) {
            int index = cs_op_index(handle,insn,ARM64_OP_MEM,i);
            offset = insn->detail->arm64.operands[index].mem.base;
            return offset;
        }
    }
    return 0;
}

//得到单条指令的立即数
#pragma mark imp:得到单条指令的立即数
uint64_t getSingleIMM(csh handle,const cs_insn *insn){
    int i;
    uint64_t imm;
    int acount = cs_op_count(handle,insn,ARM64_OP_IMM);
    if (acount) {
        if(acount>1)
            printf("getSingleIMM Immediate number more than one\n");
        for (i = 1; i < acount + 1;/*i++*/) {
            int index = cs_op_index(handle,insn,ARM64_OP_IMM,i);
            imm = insn->detail->arm64.operands[index].imm;
            return imm;
        }
    }
    return 0;
}

//得到第一个寄存器
#pragma mark imp:得到第一个寄存器
int getFirstReg(csh handle,const cs_insn *insn){
    int i,s_reg;
    int acount = cs_op_count(handle,insn,ARM64_OP_REG);
    if (acount) {
        for (i = 1; i < acount + 1;i++) {
            int index = cs_op_index(handle,insn,ARM64_OP_REG,i);
            if(i==1){
                s_reg = insn->detail->arm64.operands[index].reg;
                return s_reg;
            }
        }
    }
    return 0;
}

//得到第二个寄存器
#pragma mark imp:得到第二个寄存器
int getSecondReg(csh handle,const cs_insn *insn){
    int i,s_reg;
    int acount = cs_op_count(handle,insn,ARM64_OP_REG);
    if (acount) {
        if(acount<2)
            printf("getSecondReg Missing a register\n");
        for (i = 1; i < acount + 1;i++) {
            int index = cs_op_index(handle,insn,ARM64_OP_REG,i);
            if(i==2){
                s_reg = insn->detail->arm64.operands[index].reg;
                return s_reg;
            }
        }
    }
    return 0;
}

//根据寄存器名字得到对应的变量
#pragma mark imp:根据寄存器名字得到对应的变量
uint64_t* getActualVarFromRegName(uint64_t address,int RegName){
    switch (RegName) {
        case ARM64_REG_X0:
            return &x0;
            break;
        case ARM64_REG_X1:
            return &x1;
            break;
        case ARM64_REG_X2:
            return &x2;
            break;
        case ARM64_REG_X3:
            return &x3;
            break;
        case ARM64_REG_X4:
            return &x4;
            break;
        case ARM64_REG_X5:
            return &x5;
            break;
        case ARM64_REG_X6:
            return &x6;
            break;
        case ARM64_REG_X7:
            return &x7;
            break;
        case ARM64_REG_X8:
            return &x8;
            break;
        case ARM64_REG_X9:
            return &x9;
            break;
        case ARM64_REG_X10:
            return &x10;
            break;
        case ARM64_REG_X11:
            return &x11;
            break;
        case ARM64_REG_X12:
            return &x12;
            break;
        case ARM64_REG_X13:
            return &x13;
            break;
        case ARM64_REG_X14:
            return &x14;
            break;
        case ARM64_REG_X15:
            return &x15;
            break;
        case ARM64_REG_X16:
            return &x16;
            break;
        case ARM64_REG_X17:
            return &x17;
            break;
        case ARM64_REG_X18:
            return &x18;
            break;
        case ARM64_REG_X19:
            return &x19;
            break;
        case ARM64_REG_X20:
            return &x20;
            break;
        case ARM64_REG_X21:
            return &x21;
            break;
        case ARM64_REG_X22:
            return &x22;
            break;
        case ARM64_REG_X23:
            return &x23;
            break;
        case ARM64_REG_X24:
            return &x24;
            break;
        case ARM64_REG_X25:
            return &x25;
            break;
        case ARM64_REG_X26:
            return &x26;
            break;
        case ARM64_REG_X27:
            return &x27;
            break;
        case ARM64_REG_X28:
            return &x28;
            break;
        case ARM64_REG_X29:
            return &x29;
            break;
        case ARM64_REG_X30:
            return &x30;
            break;
        case ARM64_REG_XZR:
            return &xzr;
            break;
        case ARM64_REG_W0:
            return &x0;
            break;
        case ARM64_REG_W1:
            return &x1;
            break;
        case ARM64_REG_W2:
            return &x2;
            break;
        case ARM64_REG_W3:
            return &x3;
            break;
        case ARM64_REG_W4:
            return &x4;
            break;
        case ARM64_REG_W5:
            return &x5;
            break;
        case ARM64_REG_W6:
            return &x6;
            break;
        case ARM64_REG_W7:
            return &x7;
            break;
        case ARM64_REG_W8:
            return &x8;
            break;
        case ARM64_REG_W9:
            return &x9;
            break;
        case ARM64_REG_W10:
            return &x10;
            break;
        case ARM64_REG_W11:
            return &x11;
            break;
        case ARM64_REG_W12:
            return &x12;
            break;
        case ARM64_REG_W13:
            return &x13;
            break;
        case ARM64_REG_W14:
            return &x14;
            break;
        case ARM64_REG_W15:
            return &x15;
            break;
        case ARM64_REG_W16:
            return &x16;
            break;
        case ARM64_REG_W17:
            return &x17;
            break;
        case ARM64_REG_W18:
            return &x18;
            break;
        case ARM64_REG_W19:
            return &x19;
            break;
        case ARM64_REG_W20:
            return &x20;
            break;
        case ARM64_REG_W21:
            return &x21;
            break;
        case ARM64_REG_W22:
            return &x22;
            break;
        case ARM64_REG_W23:
            return &x23;
            break;
        case ARM64_REG_W24:
            return &x24;
            break;
        case ARM64_REG_W25:
            return &x25;
            break;
        case ARM64_REG_W26:
            return &x26;
            break;
        case ARM64_REG_W27:
            return &x27;
            break;
        case ARM64_REG_W28:
            return &x28;
            break;
        case ARM64_REG_W29:
            return &x29;
            break;
        case ARM64_REG_W30:
            return &x30;
            break;
        case ARM64_REG_WZR:
            return &xzr;
            break;
        default:
            break;
    }
    if(printWarnFromRegDidtSet)
        printf("0x%llx getActualVarFromRegName The corresponding register is not set\n",address);
    return NULL;
}


//转换汇编的虚拟内存地址,返回在内存中的实际内容
#pragma mark imp:转换汇编的虚拟内存地址,返回在内存中的实际内容
void* getMemFromAddrOfVM(void* bin,uint64_t CurFunc_FilebaseAddr,uint64_t CurFunc_VMbaseAddr,uint64_t cur_VMAddr){
    uint64_t offset = cur_VMAddr - CurFunc_VMbaseAddr;
    return bin+CurFunc_FilebaseAddr+offset;
}

//转换虚拟内存地址,返回文件中偏移地址
#pragma mark imp:转换虚拟内存地址,返回文件中偏移地址
uint64_t getfileoffFromAddrOfVM(uint64_t CurFunc_FilebaseAddr,uint64_t CurFunc_VMbaseAddr,uint64_t cur_VMAddr){
    return (uint64_t)((uint64_t)CurFunc_FilebaseAddr+((uint64_t)cur_VMAddr-(uint64_t)CurFunc_VMbaseAddr));
}

//计算返回根据thumb指令pc(+2/4)+offset的地址
#pragma mark imp:计算返回根据thumb指令pc(+2/4)+offset的地址
uint64_t getPCinThumboffset(uint64_t base,int offset){
    uint64_t result = 0;
    if(base%2!=0){
        printf("Memory alignment error\n");
        exit(1);
    }
    if(base%4==0){
        result = base+offset+0x4;
        //printf("---4\n");
    }
    else{
        result = base+offset+0x2;
        //printf("---2\n");
    }
    
    return result;
}

//分析该IO类的函数表等处在_const sec的内容
#pragma mark imp:分析该IO类的函数表等处在_const sec的内容
void ParseConstFunc(char **cn,uint64_t class_self,uint64_t class_super,void *bin,uint64_t VMaddr,uint64_t fileoff){
    
    if(!strcmp(*cn,"")){
        //非所需的str指令
        return;
    }
    else{
        if(!strcmp(*cn,"OSObject"))
            return;
        if(class_self==0){
            printf("class_self 为0\n");
            exit(1);
        }
        
        uint64_t __text_start = machoGetVMAddr(bin,"__TEXT","__text");
        uint64_t __text_end = __text_start + machoGetSize(bin,"__TEXT","__text");
        
        uint64_t __const_start = machoGetVMAddr(bin,"__DATA","__const");
        //uint64_t __const_end = __const_start + machoGetSize(bin,"__TEXT","__const");
        
        uint64_t vtable_start = 0; //为该类的vtable起始位置,可以用来分析重要的函数重写等
        uint64_t vtable_checkItSuperClassAddr = 0; //检查其父类地址
        
        //IOUserClent的特殊情况,IOUserClient的函数表最顶上没有自己的地址.自己的地址远在数个类之前....
        
        //update(3.29.2016): 现在对该函数进行arm64的适配
        
        //先找到该IO对象在__const section中的起始地址
        
        
        /*格式:
         IO类地址+0x8
         IO父类地址+0x10(2*0x8)
         IO类函数表
         */
        for(uint64_t cur_addr = VMaddr;cur_addr>=__const_start;){
            //这里是尝试在内存中找到自己类的地址的匹配
            uint32_t *check_curAddr = getMemFromAddrOfVM(bin,fileoff,VMaddr,cur_addr);
            if(!memcmp(check_curAddr,&class_self,0x4)){
                //保存起来
                vtable_start = cur_addr;
                break;
            }
            cur_addr = cur_addr - 0x4;
        }
        
        if(class_super!=0){
            for(uint64_t cur_addr = VMaddr;cur_addr>=__const_start;){
                //这里是经过IOUserClient后多出的检查,尝试在内存中找到父类地址的匹配,这样的话,通常和上面找到的地址应该相差0x4字节
                uint32_t *check_curAddr = getMemFromAddrOfVM(bin,fileoff,VMaddr,cur_addr);
                if(!memcmp(check_curAddr,&class_super,0x4)){
                    //找到,下面进行检查
                    vtable_checkItSuperClassAddr = cur_addr;
                    break;
                }
                cur_addr = cur_addr - 0x4;
            }
        }
        else{
            if(strcmp(*cn,"OSObject")&&strcmp(*cn,"OSMetaClass")){
                //过滤掉OSObject,还有个OSMetaClass同样没有父类
                printf("Doesn't have superclass\n");
                exit(1);
            }
        }
        
        if(vtable_start==0){
            //没找到的话....丢错
            
            //btw,能到这里的类都是下面的这种格式
            /*格式:
             IO类函数表
             (中间什么都没有,紧接上一个类函数表)
             IO类函数表
             */
            //所以也没有必要确认父类的值,父类的值离这里好远好远
            if(printAddrOfVtable&&printInfoOfKernel){
                //According to macro definition to skip check
                printf("name:%s Did't found head of vtable for this IOKit object\n",*cn);
                //exit(1);
                //如果需要停下来看清楚
                //sleep(3);
            }
#pragma mark part:白名单系统
            if(isInKEXTnow){
                //说明当前在分析内核扩展.如果没找到vtable的话.就得手动分析了...期待看到"- - - END - - -"
                printf("KEXT name:%s: This class didn't found vtable, so please manual analysis\n",*cn);
                //下面是过滤列表
                //按照格式if(strcmp(*cn,"xxx")&&strcmp(*cn,"xxx").....) 的写进去
                if(strcmp(*cn,"com_apple_AppleFSCompression_AppleFSCompressionTypeZlib")){
                    exit(1);
                }
                //- - - 分割线
                
            }
            
            return;
        }
        
        if(class_super&&vtable_checkItSuperClassAddr){
            if(vtable_start<vtable_checkItSuperClassAddr){
                
                //判读父类前4字节是否为自己的地址,不是的话就直接把这个父类的地址当作vtable_start.
                uint32_t *check_curAddr = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_checkItSuperClassAddr-0x8);
                if(check_PointerAddrInVM((uint64_t)check_curAddr)){
                    if(*check_curAddr==class_self){
                        //下面的注释仍然为32位程序时写的,仅作参考
                        /*正常情况:
                         IO类地址+0x4
                         IO父类地址+0x4
                         IO类函数表
                         */
                    }
                    else{
                        /*其他情况:
                         IO父类地址+0x8
                         IO类函数表
                         *///这个就是为IOUserClient准备的
                        vtable_start = vtable_checkItSuperClassAddr;
                    }
                }
                else{
                    printf("pointer goint wrong\n");
                    exit(1);
                }
                //printf("父类较大\n");
            }
            else if(vtable_start>vtable_checkItSuperClassAddr){
                /*格式:
                 IO类地址+0x8
                 (无父类地址)
                 IO类函数表
                 */
                //printf("自己较大\n");
                //正常的
            }
            else{
                printf("Strange error occur: Should't reach here\n");
                exit(1);
            }
        }
        
        //下面这些判断是根据二段结果,指向对象自己的指针的下方有一段为0的内存,继而找到0内存下面的函数表
        if(vtable_start){
            for(int i=0x0;i<0x28;i=i+0x8){
                uint64_t *check_curAddr = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start+i);
                if(check_PointerAddrInVM((uint64_t)check_curAddr)){
                    if(*check_curAddr==0x0){
                        vtable_start = vtable_start + i;
                        for(int z=0x0;z<0x28;z=z+0x8){
                            uint64_t *check_non_empty = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start+z);
                            if(check_PointerAddrInVM((uint64_t)check_non_empty)){
                                if(*check_non_empty!=0){
                                    vtable_start = vtable_start + z;
                                    break;
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
        
        if(printAddrOfVtable&&isInKEXTnow||(!isInKEXTnow&&printInfoOfKernel&&printAddrOfVtable))
            printf("vtable start from addr 0x%llx\n",vtable_start);
        uint64_t methods_start = 0;
        
        //待添加代码,上面部分得到了类的函数表.接下来应该获取被重写的函数等信息.
        
        //printf("%s MetaClassvtable:0x%x fileoff:0x%llx\n",*cn,VMaddr,fileoff);
        if(printMCFunc)
            printf("Meta vtable 0x%llx\n",VMaddr); //继承自OSMetaClass的基础函数表地址
        
#pragma mark part:对重写的函数进行过滤
        
        //下面判断类名,来得到基础类的函数信息赋值给全局变量
        
        if(!strcmp(*cn,"IOUserClient")){
            
            int vtable_count = sizeof(struct userclient_funcList)/sizeof(struct vtable_func);
            for(int i = 0;i<vtable_count;i++){
                void *ptr_funcList = &userclient_funcList;
                struct vtable_func *cur_func = ((struct vtable_func*)ptr_funcList+i);
                uint64_t *p1 = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + cur_func->func_offset);
                if(!check_PointerAddrInVM((uint64_t)p1)){
                    printf("创建IOUserClient函数表时失败 错误的指针:0x%llx\n",(uint64_t)p1);
                    exit(1);
                }
                (*cur_func).func_vm = *p1;
                /*
                 if(printFuncFinderOfKernel)
                 printf("IOUserClient::clientMemoryForType -> 0x%llx\n",*IOUserClient_clientMemoryForType);
                 */
            }
        }
        
        // - - -分割线
        
        int frIOUserClient = 0; //继承自xxx
        int frIOService = 0; //上も
        //int frIOHIDEventService = 0;
        if(isInKEXTnow){
            //关于vtable之前已经判断过了,所以这里就不做检查了.
            //前面获得了一个类的两个值可以确定函数表范围 vtable开始 - metaclass函数开始
            //根据父类继承来得到是否继承自IOService或者IOUserClient
            //再分析重要的重写函数
            printf("Inheritance relationship: ");
            NSString *cur_c = [NSString stringWithFormat:@"0x%llx",class_super];
            while(1){
                NSDictionary *s_dic = [allClass_relation objectForKey:cur_c];
                if(s_dic){
                    if(![cur_c isEqualToString:[NSString stringWithFormat:@"0x%llx",class_super]])
                        printf("->");
                    NSString *s_class = [NSString stringWithFormat:@"0x%llx",[[s_dic objectForKey:@"class_super"] unsignedLongLongValue]];
                    NSString *s_classN = [s_dic objectForKey:@"class_name"];
                    if([s_classN isEqualToString:@"IOUserClient"])
                        frIOUserClient = 1;
                    if([s_classN isEqualToString:@"IOService"])
                        frIOService = 1;
                    /*if([s_classN isEqualToString:@"IOHIDEventService"])
                     frIOHIDEventService = 1;*///供参考
                    
                    printf("%s",[s_classN cStringUsingEncoding:NSUTF8StringEncoding]);
                    cur_c = s_class;
                }
                else{
                    break;
                }
            }
            printf("\n");
        }
        else{
            //if(!vtable_start)
            //这里说明当前在分析内核的对象,那么无须分析重写的函数,因为内核的对象都是些基础类,况且前面已经判断过了.
        }
        
#pragma mark edit:判断类重写的函数
        //判断重写的函数
        printf("\n");
        if(frIOUserClient){
            
            /*int count = sizeof(struct userclient_funcList)/sizeof(struct vtable_func);
             for(int i=0;i<count;i++){
             void *ptr_funcList = &userclient_funcList;
             struct vtable_func *cur_func = ((struct vtable_func*)ptr_funcList+i);
             printf("%d - %s 0x%x 0x%llx\n",i,cur_func->func_name,cur_func->func_offset,cur_func->func_vm);
             }*///DEBUG:输出内存中的userclient_funcList结构体
            
            int vtable_count = sizeof(struct userclient_funcList)/sizeof(struct vtable_func);
            for(int i = 0;i<vtable_count;i++){
                void *ptr_funcList = &userclient_funcList;
                struct vtable_func *cur_func = ((struct vtable_func*)ptr_funcList+i);
                uint64_t *own_func = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + cur_func->func_offset);
                if(!check_PointerAddrInVM((uint64_t)own_func)){
                    printf("判断重写函数表时失败 错误的指针:0x%llx\n",(uint64_t)own_func);
                    exit(1);
                }
                
                if(*own_func!=cur_func->func_vm){
                    printf("override: %s loc:0x%llx imp:0x%llx\n",cur_func->func_name,vtable_start + cur_func->func_offset,*own_func);
                    //下面处理各别被重写函数,也是添加代码区,就是比如想过滤重写了某个重要函数的类
                }
                
                /*
                 if(printFuncFinderOfKernel)
                 printf("IOUserClient::clientMemoryForType -> 0x%llx\n",*IOUserClient_clientMemoryForType);
                 */
            }
            
        }
        
        if(frIOService){
            
            //list:
            for(int i = 0;i<IOService_vtable_limit+1;i++){
                void *ptr_funcList = &userclient_funcList;
                struct vtable_func *cur_func = ((struct vtable_func*)ptr_funcList+i);
                uint64_t *own_func = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + cur_func->func_offset);
                if(!check_PointerAddrInVM((uint64_t)own_func)){
                    printf("判断重写函数表时失败 错误的指针:0x%llx\n",(uint64_t)own_func);
                    exit(1);
                }
                
                if(*own_func!=cur_func->func_vm){
                    printf("override: %s loc:0x%llx imp:0x%llx\n",cur_func->func_name,vtable_start + cur_func->func_offset,*own_func);
                    //下面处理各别被重写函数,也是添加代码区,就是比如想过滤重写了某个重要函数的类
                    int needAdd_MK_NEW_USERCLIENT = 0;
                    if(!strcmp(cur_func->func_name,"IOService_newUserClientWithOSDic")){
                        
                        //find_openType(*cn,bin,*own_func,getfileoffFromAddrOfVM(fileoff,VMaddr,*own_func));//查找是否有特别的openType
                        needAdd_MK_NEW_USERCLIENT = 0;//暂时关掉这个功能
                        //下面是输出文件,记录下这个IO类
                        [class_newUserClientWithOSDic addObject:[NSString stringWithFormat:@"%s",*cn]];
                    }
                    if(!strcmp(cur_func->func_name,"IOService_newUserClient")){
                        
                        //find_openType(*cn,bin,*own_func,getfileoffFromAddrOfVM(fileoff,VMaddr,*own_func));//查找是否有特别的openType
                        needAdd_MK_NEW_USERCLIENT = 0;//暂时关掉这个功能
                        [class_newUserClientWithOSDic addObject:[NSString stringWithFormat:@"%s",*cn]];
                    }
                    
                    /*if(FuzzIOKit_phase1_export&&needAdd_MK_NEW_USERCLIENT){
                        NSMutableDictionary *KEXT_INPUT_Mdic = [FuzzIOKit_phase1 objectForKey:@"KEXT_INPUT"];
                        NSMutableDictionary *fuzz_new_class_list = [KEXT_INPUT_Mdic objectForKey:[NSString stringWithFormat:@"%s",KextGetBundleID(bin)]];
                        NSString *old_mark = [fuzz_new_class_list objectForKey:[NSString stringWithUTF8String:*cn]];
                        if(!old_mark){
                            printf("fuzz_new_class_list中居然没有把这个类添加进FuzzIOKit_phase1!\n");
                            exit(1);
                        }
                        if([old_mark isEqualToString:@"non"]){
                            //就是第一次添加属性
                            [fuzz_new_class_list setObject:@"MK_NEW_USERCLIENT" forKey:[NSString stringWithFormat:@"%s",*cn]];
                        }
                        else{
                            //已经添加过若干属性,以|分割
                            [fuzz_new_class_list setObject:[old_mark stringByAppendingString:@"|MK_NEW_USERCLIENT"] forKey:[NSString stringWithFormat:@"%s",*cn]];
                        }
                    }*/
                    
                    
                }
            }
            
            //printf("\nown_externalMethod: 0x%x\n",*own_externalMethod);
        }
        
        /*if(frIOHIDEventService){
         uint64_t addr = [[IOHIDEventService_copyEvent objectForKey:@"addr"] unsignedLongLongValue];
         uint32_t offset = [[IOHIDEventService_copyEvent objectForKey:@"offset"] unsignedIntValue];
         
         uint64_t *own_copyEvent = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + offset);
         if(*own_copyEvent!=addr){
         printf("copyEvent被重写!!!!! loc:0x%llx imp:0x%llx\n",vtable_start + offset,*own_copyEvent);
         //下面是输出文件
         //[class_newUserClient addObject:[NSString stringWithFormat:@"%s",*cn]];
         }
         }*/ //这是想知道有哪些类继承了IOHIDEventService的copyEvent函数添加的代码,供参考
        
        printf("\n");
        
        if(isUserClient==1||frIOUserClient){
            //为UserClinet类分析methods
            //selector 0
            
            if(!strcmp(*cn,"IOHIDLibUserClient")){
                printf("");
            }
            
            uint64_t *check_func_0 = 0;
            uint32_t *check_scalar_i_0 = 0;
            uint32_t *check_struct_i_0 = 0;
            uint32_t *check_scalar_o_0 = 0;
            uint32_t *check_struct_o_0 = 0;
            
            int vm_i = 0;
            
            for(vm_i = 0;vm_i<0x100;vm_i++){
                check_func_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*8);
                check_scalar_i_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*8+8);
                check_struct_i_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*8+12);
                check_scalar_o_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*8+16);
                check_struct_o_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*8+20);
                
                if(
                   ((*check_func_0 > __text_start)&&(*check_func_0 < __text_end))&&(*check_scalar_i_0 < 0xffff||*check_scalar_i_0 == 0xffffffff)&&(*check_struct_i_0 < 0xffff || *check_struct_i_0 == 0xffffffff)&&(*check_scalar_o_0 < 0xffff || *check_scalar_o_0 == 0xffffffff) && (*check_scalar_i_0 < 0xffff || *check_scalar_i_0 == 0xffffffff))
                {
                    //找到开头
                    methods_start = VMaddr+vm_i*4;
                    if(methods_start==0){
                        printf("methods_start 为0错误\n");
                        exit(1);
                    }
                    if(printAddrOfMethod)
                        printf("%s methods table in 0x%llx\n",*cn,methods_start);
                    break;
                }
            }
            
            if(methods_start!=0){
                NSMutableArray *methods_array = [[NSMutableArray alloc]init];
                for(int mi = 0;;){
                    check_func_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*8);
                    check_scalar_i_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*8+8);
                    check_struct_i_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*8+12);
                    check_scalar_o_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*8+16);
                    check_struct_o_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*8+20);
                    if(
                       ((*check_func_0 > __text_start)&&(*check_func_0 < __text_end))&&(*check_scalar_i_0 < 0xffff||*check_scalar_i_0 == 0xffffffff)&&(*check_struct_i_0 < 0xffff || *check_struct_i_0 == 0xffffffff)&&(*check_scalar_o_0 < 0xffff || *check_scalar_o_0 == 0xffffffff) && (*check_scalar_i_0 < 0xffff || *check_scalar_i_0 == 0xffffffff))
                    {
                        NSMutableDictionary *methods_each_detail_dic = [[NSMutableDictionary alloc]init];
                        [methods_each_detail_dic setObject:[NSNumber numberWithUnsignedLongLong:*check_func_0] forKey:@"func"];
                        [methods_each_detail_dic setObject:[NSNumber numberWithUnsignedInt:*check_scalar_i_0] forKey:@"scalar_i"];
                        [methods_each_detail_dic setObject:[NSNumber numberWithUnsignedInt:*check_struct_i_0] forKey:@"struct_i"];
                        [methods_each_detail_dic setObject:[NSNumber numberWithUnsignedInt:*check_scalar_o_0] forKey:@"scalar_o"];
                        [methods_each_detail_dic setObject:[NSNumber numberWithUnsignedInt:*check_struct_o_0] forKey:@"struct_o"];
                        [methods_array addObject:methods_each_detail_dic];
                        
                        if(printMethodsInfo){
                            printf("%d func:0x%llx  scalar_i:0x%x  struct_i:0x%x  scalar_o:0x%x  struct_o:0x%x\n",mi,*check_func_0,*check_scalar_i_0,*check_struct_i_0,*check_scalar_o_0,*check_struct_o_0);
                            //printf("%d scalar_i:0x%x  struct_i:0x%x  scalar_o:0x%x  struct_o:0x%x\n",mi,*check_scalar_i_0,*check_struct_i_0,*check_scalar_o_0,*check_struct_o_0); 没有函数地址显示(便于查找匹配的函数)
                        }
                        mi++;
                    }
                    else{
                        break;
                    }
                    vm_i = vm_i + 3;
                }
                if([methods_array count]>0){
                    /*if(FuzzIOKit_phase1_export){
                        NSMutableDictionary *KEXT_INPUT_Mdic = [FuzzIOKit_phase1 objectForKey:@"KEXT_INPUT"];
                        NSMutableDictionary *fuzz_new_class_list = [KEXT_INPUT_Mdic objectForKey:[NSString stringWithFormat:@"%s",KextGetBundleID(bin)]];
                        [fuzz_new_class_list setObject:methods_array forKey:[NSString stringWithFormat:@"%s",*cn]];
                    }*/
                    
                    [class_userCleint_methods setObject:methods_array forKey:[NSString stringWithFormat:@"%s",*cn]];
                }
            }
        }
    }
    *cn = "";
    class_self = 0;
    class_super = 0;
}

//查找重写了newUserClient的对象中,得到可能的OpenType值
#pragma mark imp:(X失败函数)查找重写了newUserClient的对象中,得到可能的OpenType值
void find_openType(char *class_name,void *bin,uint64_t newUserClient_vm,uint64_t newUserClient_fileoff){
    csh handle;
    cs_insn *insn;
    size_t count;
    
    if(cs_open(CS_ARCH_ARM64,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN,&handle)!=CS_ERR_OK)
        exit(1);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    count = cs_disasm(handle,bin+newUserClient_fileoff,0xFFF,newUserClient_vm,0,&insn);
    //printf("bin+tar_fileoff = 0x%llx\n",bin+tar_fileoff);
    size_t j;
    uint32_t W8 = 0;
    for(j=0;j<count;j++){
        if(count > 0){
            
            //输出汇编
            //printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j].address,insn[j].mnemonic,insn[j].op_str);
            if(!strcmp(insn[j].mnemonic,"movz")){
                int acount = cs_op_count(handle,&insn[j],ARM64_OP_REG);
                if(acount==1){
                    int f_reg = getFirstReg(handle,&insn[j]);
                    uint32_t imm = (uint32_t)getSingleIMM(handle,&insn[j]);
                    if(f_reg==ARM64_REG_W8&&imm){
                        W8 = imm;
                    }
                }
                //如果为mov指令...do
            }
            
            if(!strcmp(insn[j].mnemonic,"movk")){
                int acount = cs_op_count(handle,&insn[j],ARM64_OP_REG);
                if(acount==1){
                    int f_reg = getFirstReg(handle,&insn[j]);
                    uint16_t imm = (uint16_t)getSingleIMM(handle,&insn[j]);
                    if(f_reg==ARM64_REG_W8&&imm){
                        // W8 = W8+imm;
                    }
                }
                //如果为movk指令...do
            }
            
            if(strstr(insn[j].mnemonic,"cmp")){
                int acount = cs_op_count(handle,&insn[j],ARM64_OP_REG);
                if(acount==2){
                    
                    int f_reg = getFirstReg(handle,&insn[j]);
                    int s_reg = getSecondReg(handle,&insn[j]);
                    if(f_reg==ARM64_REG_W3&&s_reg==ARM64_REG_W8){
                        printf("0x%llx:Special OpenType:0x%x\n",insn[j].address,W8);
                    }
                }
                //如果为cmp指令...do
            }
            
            if(strstr(insn[j].mnemonic,"ret")){
                break;
                //到ret为止
            }
        }
    }
    cs_free(insn,count);
    cs_close(&handle);
}

//检查指针指向位置是否在已分配的虚拟内存内,正确返回1
#pragma mark imp:检查指针指向位置是否在已分配的虚拟内存内,正确返回1
int check_PointerAddrInVM(uint64_t tar_addr)
{
    //仅限使用64位程序,32位请修改
    int pid = 0;
    pid_for_task(mach_task_self(),&pid);
    
    vm_map_t task = 0;
    task_for_pid(mach_task_self(),pid,&task);
    
    int avai = 0;
    
    kern_return_t ret;
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    vm_address_t addr = 0;
    while (1) {
        ret = vm_region_recurse_64(task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count);
        
        if (ret != KERN_SUCCESS)
            break;
        if(addr>0x7fff00000000)
            break;
        if(tar_addr>=addr&&tar_addr<=addr+size){
            avai = 1;
        }
        //printf("region 0x%lx - 0x%lx\n",addr,addr+size);
        addr = addr + size;
    }
    
    if(avai==1)
        return 1;
    else
        return 0;
    
    return 0;
}

