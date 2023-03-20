#!/usr/bin/env node

(function(root) {
    "use strict";

    /*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
    /*global document, window, escape, unescape, module, require, Uint32Array */

    const SHE = require('./SHE_encrypt.js');

    test('SHE_decrypt: buildFrame ReSync', () =>
        {
            var id = '6e0';
            var name = 'FVReSyncFrame_ATCU_FD';
            var fv = Buffer.from('740100b9e2c7000000674575000005d4bdc6000009482ea7000000000040000011998d8b', 'hex');
            var pad = Buffer.from('0000', 'hex');
            
	    var she = new SHE(id, name, fv, undefined, pad);
	    expect(she.buildFrame().toString('hex')).toBe('06e0740100b9e2c7000000674575000005d4bdc6000009482ea7000000000040000011998d8b0000');
        }
    );

    test('SHE_decrypt: buildFrame Sync', () =>
        {
            var id = '697';
            var name = 'FVSyncFrame_BCM_FD';
            var fv = Buffer.from('740100c896c2', 'hex');
            var pad = Buffer.from('0000', 'hex');
            
	    var she = new SHE(id, name, fv, undefined, pad);
	    expect(she.buildFrame().toString('hex')).toBe('0697740100c896c20000');
        }
    );

    test('SHE_decrypt: buildFrame SC_FD', () =>
        {
            var id = '453';
            var name = 'USM_A101SC_FD';
            var fv = Buffer.from('000005d4be4e', 'hex');
            var payload = Buffer.from('00045308f1171567a02af6', 'hex');
            var pad = Buffer.from('000000', 'hex');
            
	    var she = new SHE(id, name, fv, payload, undefined);
	    expect(she.buildFrame().toString('hex')).toBe('045300045308f1171567a02af6000005d4be4e');
        }
    );

    test('SHE_decrypt: cipher ReSync frame', () =>
        {
            var id = '6e0';
            var name = 'FVReSyncFrame_ATCU_FD';
            var fv = Buffer.from('740100b9e2c7000000674575000005d4bdc6000009482ea7000000000040000011998d8b', 'hex');
            var pad = Buffer.from('0000', 'hex');
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
	    var she = new SHE(id, name, fv, undefined, pad);
            console.log(she.buildFrame().toString('hex'));
            var cipheredFrame = she.encrypt_Frame(she.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('');
        }
    );

    test('SHE_decrypt: buildFrame Sync', () =>
        {
            var id = '697';
            var name = 'FVSyncFrame_BCM_FD';
            var fv = Buffer.from('740100c896c2', 'hex');
            var pad = Buffer.from('0000', 'hex');
            
	    var she = new SHE(id, name, fv, undefined, pad);
	    expect(she.buildFrame().toString('hex')).toBe('0697740100c896c20000');
        }
    );

    test('SHE_decrypt: buildFrame SC_FD', () =>
        {
            var id = '453';
            var name = 'USM_A101SC_FD';
            var fv = Buffer.from('000005d4be4e', 'hex');
            var payload = Buffer.from('00045308f1171567a02af6', 'hex');
            var pad = Buffer.from('000000', 'hex');
            
	    var she = new SHE(id, name, fv, payload, undefined);
	    expect(she.buildFrame().toString('hex')).toBe('045300045308f1171567a02af6000005d4be4e');
        }
    );

})(this);

/*
 * vim: et:ts=4:sw=4:sts=4
 * -*- mode: JavaScript; coding: utf-8-unix; tab-width: 4 -*-
 */
