# Keystone3 development kit 

This project provides quick & dirty very unofficial tools to turn your Keystone 3 Pro into a developer unit if it runs the right firmware (1.2.2 / 1.2.4 at the moment)

Python scripts are supposed to run in an environment with pyusb and secp256k1 packages installed

## Generating a firmware update key

Roll your own on secp256k1 or use **generateKeyPair.py** - the key should not be compressed

## Installing the firmware update key on your device

Connect your device and run **setUpdateKey.py** with the uncompressed secp256k1 public key

When prompted to continue, wait for the update message to disappear on the device then press return

If the operation was successful, the device will display "OK" and freeze - turn it off by pressing the power button for a loooong time

## Signing your own firmware

Use **signFirmware.py** and the firmware you want to sign and your private key

Note : this is obviously not a secure setup, but hey look at what you're doing already

## Uploading your own firmware

Use **uploadFirmware.py** and your signed firmware

Wait for a long time and press return when prompted

Note : the version check is still enforced by the bootloader, so you'll need to have a version superior to the one you're currently running in your firmware

## Reverting to the manufacturer key

Once you change the update key, you'll have to sign all firmware releases yourself 

If for any reason you want to revert to the original one, use the original update public key 04d9a5db6866364b7f55cf6f3c199a96265c6e717087be9da8f41deaf570bc7c2e0d484cb39f0ddeffb417f995f91406cbf0e156639ad8056d0ee351c25831f8d9

You can verify this key with **recoverFirmwarePublicKey.py** on at least 2 official versions

## How does it work ?

The affected firmware versions have a buffer overflow vulnerability, fixed in 1.2.6 (https://github.com/KeystoneHQ/keystone3-firmware/commit/1551c6421d2a4747c1a37edb70ebb324fb82ebb8)

The buffer might not seem too interesting at a first glance because it isn't on the stack


    20086b28 l     O .bss   00000004 g_fileTransTimeOutTimer
    20086b24 l     O .bss   00000001 g_isReceivingFile
    20086b20 l     O .bss   00000004 lastTick.19675
    20086b1c l     O .bss   00000004 currentParser.19677
    20085988 l     O .bss   00001194 g_protocolRcvBuffer

However g_fileTransTimeOutTimer is a FreeRTOS timer exposing a callback function

    typedef struct tmrTimerControl {                /* The old naming convention is used to prevent breaking kernel aware debuggers. */
        const char * pcTimerName;                   /*<< Text name.  This is not used by the kernel, it is included simply to make debugging easier. */ /*lint !e971 Unqualified char types are allowed for strings and single characters only. */
        ListItem_t xTimerListItem;                  /*<< Standard linked list item as used by all kernel features for event management. */
        TickType_t xTimerPeriodInTicks;             /*<< How quickly and often the timer expires. */
        void * pvTimerID;                           /*<< An ID to identify the timer.  This allows the timer to be identified when the same callback is used for multiple timers. */
        TimerCallbackFunction_t pxCallbackFunction; /*<< The function that will be called when the timer expires. */
    #if ( configUSE_TRACE_FACILITY == 1 )
        UBaseType_t uxTimerNumber;              /*<< An ID assigned by trace tools such as FreeRTOS+Trace */
    #endif
        uint8_t ucStatus;                           /*<< Holds bits to say if the timer was statically allocated or not, and if it is active or not. */  
    } xTIMER;

Which is used this way [when a firmware is uploaded to the device](https://github.com/KeystoneHQ/keystone3-firmware/blob/1.2.2/src/webusb_protocol/services/service_file_trans.c#L90)

    if (g_fileTransTimeOutTimer == NULL) {
        g_fileTransTimeOutTimer = osTimerNew(FileTransTimeOutTimerFunc, osTimerOnce, NULL, NULL);
    }
    g_isReceivingFile = true;
    osTimerStart(g_fileTransTimeOutTimer, FILE_TRANS_TIME_OUT);

An exploit can overwrite the pointer after the timer is allocated and make it point to a timer structure controlled by the attacker implementing a custom callback, which will kick in the next time the timer expires after it's restarted

In this case, the exploit just calls [SetUpdatePubKey](https://github.com/KeystoneHQ/keystone3-firmware/blob/1.2.2/src/presetting.c#L161)

Note that this works because FreeRTOS supports static timers, no memory protection is set and all areas are executable.

19.08.24 : Vulnerability reported

21.08.24 : Discussion with Keystone team, agreement to release early 2025

01.09.24 : Confidential vulnerability update reported (03cd9a0e86d7b768138c6eb29dea5a5911d6859fcab675c1b359b956bb796613) 

07.04.25 : Disclosure

## Parting words

Enjoy, please only use this for educational/research purposes and don't blame me if you brick your device, thank you :)

BTC tips : bc1qrd4jq367s299va3a97n09fvcde4hfr7heltqt4

EVM tips : btchip.sismo.eth

