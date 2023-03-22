#!/usr/bin/env node

(function(root) {
    "use strict";

    /*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
    /*global document, window, escape, unescape, module, require, Uint32Array */

    const SHE = require('./SHE_encrypt.js');

    test('SHE_decrypt: buildFrame ReSync (0x id)', () =>
        {
            var id = '0x6e0';
            var name = 'FVReSyncFrame_ATCU_FD';
            var fv = Buffer.from('740100b9e2c7000000674575000005d4bdc6000009482ea7000000000040000011998d8b', 'hex');
            var pad = Buffer.from('0000', 'hex');
            
	    var she = new SHE(id, name, fv, undefined, pad);
	    expect(she.buildFrame().toString('hex')).toBe('06e0740100b9e2c7000000674575000005d4bdc6000009482ea7000000000040000011998d8b0000');
        }
    );

    test('SHE_decrypt: buildFrame Sync (0x id)', () =>
        {
            var id = '0x697';
            var name = 'FVSyncFrame_BCM_FD';
            var fv = Buffer.from('740100c896c2', 'hex');
            var pad = Buffer.from('0000', 'hex');
            
	    var she = new SHE(id, name, fv, undefined, pad);
	    expect(she.buildFrame().toString('hex')).toBe('0697740100c896c20000');
        }
    );

    test('SHE_decrypt: buildFrame SC_FD (0x id)', () =>
        {
            var id = '0x453';
            var name = 'USM_A101SC_FD';
            var fv = Buffer.from('000005d4be4e', 'hex');
            var msb = Buffer.from('1234', 'hex');
            var payload = Buffer.from('00045308f1171567a02af6', 'hex');
            var pad = Buffer.from('000000', 'hex');
            
	    var she = new SHE(id, name, fv, payload, undefined, msb);
	    expect(she.buildFrame().toString('hex')).toBe('045300045308f1171567a02af61234000005d4be4e');
        }
    );

    test('SHE_decrypt: buildFrame ReSync (no 0x id)', () =>
        {
            var id = '6e0';
            var name = 'FVReSyncFrame_ATCU_FD';
            var fv = Buffer.from('740100b9e2c7000000674575000005d4bdc6000009482ea7000000000040000011998d8b', 'hex');
            var pad = Buffer.from('0000', 'hex');
            
	    var she = new SHE(id, name, fv, undefined, pad);
	    expect(she.buildFrame().toString('hex')).toBe('06e0740100b9e2c7000000674575000005d4bdc6000009482ea7000000000040000011998d8b0000');
        }
    );

    test('SHE_decrypt: buildFrame Sync (no 0x id)', () =>
        {
            var id = '697';
            var name = 'FVSyncFrame_BCM_FD';
            var fv = Buffer.from('740100c896c2', 'hex');
            var pad = Buffer.from('0000', 'hex');
            
	    var she = new SHE(id, name, fv, undefined, pad);
	    expect(she.buildFrame().toString('hex')).toBe('0697740100c896c20000');
        }
    );

    test('SHE_decrypt: buildFrame SC_FD (no 0x id)', () =>
        {
            var id = '453';
            var name = 'USM_A101SC_FD';
            var fv = Buffer.from('000005d4be4e', 'hex');
            var msb = Buffer.from('1234', 'hex');
            var payload = Buffer.from('00045308f1171567a02af6', 'hex');
            var pad = Buffer.from('000000', 'hex');
            
	    var she = new SHE(id, name, fv, payload, undefined, msb);
	    expect(she.buildFrame().toString('hex')).toBe('045300045308f1171567a02af61234000005d4be4e');
        }
    );

    test('SHE_decrypt: cipher ReSync frame (0x id)', () =>
        {
            var id = '0x6e0';
            var name = 'FVReSyncFrame_ATCU_FD';
            var fv = Buffer.from('740100b9e2c7000000674575000005d4bdc6000009482ea7000000000040000011998d8b', 'hex');
            var pad = Buffer.from('0000', 'hex');
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
	    var she = new SHE(id, name, fv, undefined, pad);
            var cipheredFrame = she.encrypt_Frame(she.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('2f93d02c5c218cf565dfe7a2ab0f87f4');
        }
    );

    test('SHE_decrypt: cipher ReSync frame (no 0x id)', () =>
        {
            var id = '6e0';
            var name = 'FVReSyncFrame_ATCU_FD';
            var fv = Buffer.from('740100b9e2c7000000674575000005d4bdc6000009482ea7000000000040000011998d8b', 'hex');
            var pad = Buffer.from('0000', 'hex');
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
	    var she = new SHE(id, name, fv, undefined, pad);
            var cipheredFrame = she.encrypt_Frame(she.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('2f93d02c5c218cf565dfe7a2ab0f87f4');
        }
    );

    test('SHE_decrypt: cipher Sync frame (0x id)', () =>
        {
            var id = '0x697';
            var name = 'FVSyncFrame_BCM_FD';
            var fv = Buffer.from('740100c896c2', 'hex');
            var pad = Buffer.from('0000', 'hex');
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
	    var she = new SHE(id, name, fv, undefined, pad);
            var cipheredFrame = she.encrypt_Frame(she.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('d1f55dadfb95d26e5304b5f1549479b9');
        }
    );

    test('SHE_decrypt: cipher Sync frame (no 0x id)', () =>
        {
            var id = '697';
            var name = 'FVSyncFrame_BCM_FD';
            var fv = Buffer.from('740100c896c2', 'hex');
            var pad = Buffer.from('0000', 'hex');
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
	    var she = new SHE(id, name, fv, undefined, pad);
            var cipheredFrame = she.encrypt_Frame(she.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('d1f55dadfb95d26e5304b5f1549479b9');
        }
    );

    test('SHE_decrypt: cipher SC_FD frame (0x id)', () =>
        {
            var id = '0x453';
            var name = 'USM_A101SC_FD';
            var fv = Buffer.from('000005d4be4e', 'hex');
            var msb = Buffer.from('1234', 'hex');
            var payload = Buffer.from('00045308f1171567a02af6', 'hex');
            var pad = Buffer.from('000000', 'hex');
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
	    var she = new SHE(id, name, fv, payload, pad, msb);
            var cipheredFrame = she.encrypt_Frame(she.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('911356cba7aa9c4af59554e863005efa');
        }
    );

    test('SHE_decrypt: cipher SC_FD frame (no 0x id)', () =>
        {
            var id = '453';
            var name = 'USM_A101SC_FD';
            var fv = Buffer.from('000005d4be4e', 'hex');
            var msb = Buffer.from('1234', 'hex');
            var payload = Buffer.from('00045308f1171567a02af6', 'hex');
            var pad = Buffer.from('000000', 'hex');
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
	    var she = new SHE(id, name, fv, payload, pad, msb);
            var cipheredFrame = she.encrypt_Frame(she.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('911356cba7aa9c4af59554e863005efa');
        }
    );

    test('SHE_decrypt: verify MAC for ciphered SC_FD frame', () =>
        {
            //  This is the Sync Frame of the Domain master ECU preceding the frame for which the MAC is computed
            //    0.035032 CANFD   3 Rx        697  FVSyncFrame_BCM_FD               1 0 a 16 00 00 05 d2 c4 86 00 00 34 e9 95 71 29 6b ee c1
            //    <------> <--->   ^ ^         <->  <---------------->                     D  <---------> <---> <---> <--------------------->
            //   TimeStamp  Net   /  \         Fr     Frame Name                           L      MSB      LSB   Pad            tMAC Sync
            //               NetId   CommWay   Id                                          C  <--- Ful FV ---->
            //
            // And the frame to rebuild for computing MAC
            //    0.035573 CANFD   3 Rx        5e7  BCM_A116SC_FD                    1 0 c 24 00 05 e7 07 72 40 f8 f9 00 01 3c 00 00 00 c4 86 e2 ad cc eb 81 92 e8 f4
            //    <------> <--->   ^ ^         <->  <----------->                          D  <------------------------------> <---> <------> <--------------------->  
            //   TimeStamp  Net   /  \         Fr    Frame Name                            L              Payload               PAD     LSB             tMAC  
            //              Net ID   CommWay   ID                                          C                                                                          

            var id = '5e7';
            var name = 'BCM_A116SC_FD';
            var fv = Buffer.from('c486', 'hex');
            var msb = Buffer.from('000005d2' ,'hex');
            var payload = Buffer.from('0005e7077240f8f900013c', 'hex');
            var pad = Buffer.from('000000', 'hex');
            var tMAC = Buffer.from('e2adcceb8192e8f4','hex');
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
	    var she = new SHE(id, name, fv, payload, pad, msb);
            var cipheredFrame = she.encrypt_Frame(she.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('e2adcceb8192e8f44220f3b961b64a6e');
            expect(cipheredFrame.subarray(0,8).toString('hex')).toBe(tMAC.toString('hex'));
        }
    );

    test('SHE_decrypt: verify MAC for ciphered Sync frame (CDM)', () =>
        {
            //   0.115460 CANFD   3 Rx        69d  FVSyncFrame_CDM_FD               1 0 a 16 00 00 09 43 06 4b 00 00 12 4f 49 e3 a4 23 4f 96
            //   <------> <--->   ^ ^         <->  <---------------->                     <> <---------------> <---> <--------------------->
            //  TimeStamp  Net   /   \       FrId     Frame Name                          D     Payload         Pad            tMAC
            //            Name NetId  Comm Way                                            L
            //                                                                            C

            var id = '69d';
            var name = 'FVSyncFrame_CDM_FD';
            var fv = Buffer.from('00000943064b', 'hex');
            var pad = Buffer.from('0000', 'hex');
            var tMAC = Buffer.from('124f49e3a4234f96', 'hex');

            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var she = new SHE(id, name, fv, undefined, pad);
            var cipheredFrame = she.encrypt_Frame(she.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('124f49e3a4234f96b30c9412ed5df3a6');
            expect(cipheredFrame.subarray(0,8).toString('hex')).toBe(tMAC.toString('hex'));            
        }
    );

    test('SHE_decrypt: verify MAC for ciphered ReSync frame (CDM)', () =>
        {
            // 1629.949878 CANFD   3 Rx        6e0  FVReSyncFrame_ATCU_FD            1 0 e 48 74 01 00 ca 84 b4 00 00 05 d8 8c 22 00 00 09 56 99 dc 00 00 02 09 69 af 00 00 00 00 00 00 00 00 11 b3 f1 d6 00 00 00 00 2f 30 8d f6 27 2a f5 db
            // <---------> <--->   ^  ^        <->  <------------------->                  <> <---------------------------------------------------------------------------------------------------------> <---------> <--------------------->
            //  TimeStamp   Net   /   \      Frame          name                           D  <---------------> <---------------> <---------------> <---------------> <---------------> <--------------->    
            //                   /     \      ID                                           L        FV1               FV2                 FV3               FV4               FV5               FV6           PAD                tMAC
            //                NetID     Comm way                                           C
            var id = '6e0';
            var name = 'FVReSyncFrame_ATCU_FD';
            var fv = Buffer.from('740100ca84b4000005d88c220000095699dc0000020969af000000000000000011b3f1d6', 'hex');
            var pad = Buffer.from('00000000', 'hex');
            var tMAC = Buffer.from('2f308df6272af5db', 'hex');

            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var she = new SHE(id, name, fv, undefined, pad);
            var cipheredFrame = she.encrypt_Frame(she.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('2f308df6272af5db7a1a62257c86392a');
            expect(cipheredFrame.subarray(0,8).toString('hex')).toBe(tMAC.toString('hex'));            
        }
    );

    test('SHE_decrypt: verify MAC for ciphered ReSync frame (CDM)', () =>
        {
            
            // 939.465237 CANFD   3 Rx        6e4  FVReSyncFrame_ADAS_FD            1 0 e 48 74 01 00 ca 48 13 00 00 00 68 73 fe 00 00 05 d6 d8 5b 00 00 09 4e 55 4b 00 00 00 00 00 40 00 00 11 a4 b4 01 00 00 00 00 7b 85 a2 c6 a8 26 4b 8e
            var id = '6e4';
            var name = 'FVReSyncFrame_ADAS_FD';
            var fv = Buffer.from('740100ca48130000006873fe000005d6d85b0000094e554b000000000040000011a4b401', 'hex');
            var pad = Buffer.from('00000000', 'hex');
            var tMAC = Buffer.from('7b85a2c6a8264b8e', 'hex');

            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var she = new SHE(id, name, fv, undefined, pad);
            var cipheredFrame = she.encrypt_Frame(she.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('7b85a2c6a8264b8e4e9d20ddf42ed562');
            expect(cipheredFrame.subarray(0,8).toString('hex')).toBe(tMAC.toString('hex'));            
        }
    );

    test('SHE_decrypt: verify MAC for ciphered Sync frame (CDM)', () =>
        {
            // 939.468032 CANFD   3 Rx        698  FVSyncFrame_PWT_FD               1 0 a 16 74 01 00 c9 48 16 00 00 6c 77 7c 2d 9e 11 93 5f

            var id = '698';
            var name = 'FVSyncFrame_PWT_FD';
            var fv = Buffer.from('740100c94816', 'hex');
            var pad = Buffer.from('0000', 'hex');
            var tMAC = Buffer.from('6c777c2d9e11935f', 'hex');

            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var she = new SHE(id, name, fv, undefined, pad);
            var cipheredFrame = she.encrypt_Frame(she.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('6c777c2d9e11935f694e3b1433c3ef77');
            expect(cipheredFrame.subarray(0,8).toString('hex')).toBe(tMAC.toString('hex'));            
        }
    );

            
})(this);

/*
 * vim: et:ts=4:sw=4:sts=4
 * -*- mode: JavaScript; coding: utf-8-unix; tab-width: 4 -*-
 */
