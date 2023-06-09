#!/usr/bin/env node
/** @fileOverview Javascript cryptography implementation 
 * for MiyaguchiPreneel Compression function.
 *
 *
 */

(function(root) {
    "use strict";

    /*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
    /*global document, window, escape, unescape, module, require, Uint32Array */
    
    var aesjs = require('aes-js');
    //const AesCmac = require('aes-cmac').AesCmac;
    var aesCmac = require('node-aes-cmac').aesCmac;
    var MP = require('miyaguchipreneel');

    /*
     * dk = KDF(k)
     *
     * Key Derivation Function used in the SHE protocol specification
     * 
     */
    SHE_encrypt.prototype.KDF = (k) =>
    {
        return(
            SHE_encrypt.prototype.mp.comp(
                SHE_encrypt.prototype.bufferIV,
                Buffer.concat(
                    [
                        (k instanceof Buffer ?
                         Buffer.from(k) :
                         Buffer.from(k, 'hex')
                        ),
                        SHE_encrypt.prototype.KeyUpdateEncCte
                    ]
                )
            )
        );
    }

    /*
     * bufM2 = encrypt_Frame(msg, key)
     *
     * This method will cipher the SHE command M2 argument register 
     * provided for a Key Provisionning.
     * This register will also allows, when deciphered, to get CID, FID 
     * and Key. 
     * (see SHE protocol specification on AUTOSAR web site for details)
     *
     * Arguments:
     *   msg: The message ciphered transfered in a CAN/Eth frame
     *   key: The kMasterEcu key used for ciphering the frame
     *
     * Returns:
     *   The ciphered M2 register value for SHE (Secure Hardware Extension)
     */
    SHE_encrypt.prototype.encrypt_Frame = (msg, key) =>
    {
        var aescmac = aesCmac(key, msg, {returnAsBuffer: true});
        return(aescmac);
    }

        /*
     * SHE_decrypt constructor
     *
     */
    function SHE_encrypt(type, name, timestamp, ecuName, dlc, tmac, fv, payload, msb, lsb, pad)
    {
        const KeyUpdateEncCte = Buffer.from('010153484500800000000000000000b0', 'hex');
        const bufferIV = Buffer.from('00000000000000000000000000000000', 'hex');
        const mp = new MP();
        
        this.KeyUpdateEncCte = KeyUpdateEncCte;
        this.bufferIV = bufferIV;
        this.mp = mp;
        SHE_encrypt.prototype.KeyUpdateEncCte = KeyUpdateEncCte;
        SHE_encrypt.prototype.bufferIV = bufferIV;
        SHE_encrypt.prototype.mp = mp;
        SHE_encrypt.prototype.KDF = this.KDF;
        SHE_encrypt.prototype.encrypt_Frame = this.encrypt_Frame;

        this.type = type;
        if (this.type !== undefined)
        {
            var typeRegex = /^0x(?<type>[0-9a-fA-F]+)$/;
            var fields;
            if ((fields = typeRegex.exec(this.type)) != null)
                this.type = fields.groups.type;

            if (this.type.length == 2)
                this.type = '00' + this.type;
            else if (this.type.length == 3)
                this.type = '0' + this.type;                            
        }
        else
            this.type = '0000';

        this.type = Buffer.from(this.type, 'hex');

        this.name = (name === undefined ? Buffer.alloc(0) : name);
        this.ecuName = (ecuName === undefined ? Buffer.alloc(0) : ecuName);
        this.dlc = (dlc === undefined ? Buffer.alloc(0) : dlc);
        this.tmac = (tmac === undefined ? Buffer.alloc(0) : tmac);
        this.fv = (fv === undefined ? Buffer.alloc(0) : fv);
        this.payload = (payload === undefined ? Buffer.alloc(0) : payload);
        this.msb = (msb === undefined ? Buffer.alloc(0) : msb);
        this.lsb = (lsb === undefined ? Buffer.alloc(0) : lsb);
        this.pad = (pad === undefined ? Buffer.alloc(0) : pad);
        SHE_encrypt.prototype.type = this.type;
        SHE_encrypt.prototype.name = this.name;
        SHE_encrypt.prototype.ecuName = this.ecuName;
        SHE_encrypt.prototype.fv = this.fv;
        SHE_encrypt.prototype.payload = this.payload;
        SHE_encrypt.prototype.msb = this.msb;
        SHE_encrypt.prototype.lsb = this.lsb;
        SHE_encrypt.prototype.pad = this.pad;

        SHE_encrypt.prototype.buildFrame = () =>
        {
            var resyncRE = /^.*ReSync.*$/g;
            var syncRE = /^.*Sync.*$/g;
            var scfdRE = /^.*SC_FD.*$/g;

            var frame;
            // Rebuild a ReSync frame
            
            if (resyncRE.test(SHE_encrypt.prototype.name))
            {
                if (this.fv === undefined)
                    this.fv = Buffer.alloc(0);
                if (this.pad === undefined)
                    this.pad = Buffer.alloc(0);
                frame = Buffer.concat(
                    [this.type, this.fv, this.pad]
                );
            }
            // Rebuild a Sync frame
            else if (syncRE.test(this.name))
            {
                if (this.fv === undefined)
                    this.fv = Buffer.alloc(0);
                if (this.pad === undefined)
                    this.pad = Buffer.alloc(0);
                frame = Buffer.concat(
                    [this.type, this.fv, this.pad]
                );
            }
            // Rebuild a misc secured frame
            // (needing the prev Sync frame MSB)
            else if (scfdRE.test(this.name))
            {
                if (this.payload === undefined)
                    this.payload = Buffer.alloc(0);
                if (this.msb === undefined)
                    this.msb = Buffer.alloc(0);
                if (this.lsb === undefined)
                    this.lsb = Buffer.alloc(0);
                frame = Buffer.concat(
                    [this.type, this.payload, this.msb, this.lsb]
                );
            }
            else
            {
                frame = null;
            }
            return(frame);
        };

        SHE_encrypt.prototype.verifyMac = (key) =>
        {
            var cipheredFrame = this.encrypt_Frame(this.buildFrame(), key);
            return(cipheredFrame.subarray(0,8).toString('hex') == this.tmac.toString('hex'))
        }
    }

        
    // NodeJS
    if (typeof exports !== 'undefined')
    {
	exports.SHE_encrypt = SHE_encrypt;
	exports.KDF = SHE_encrypt.prototype.KDF;
	exports.encrypt_Frame = SHE_encrypt.prototype.encrypt_Frame;
	module.exports = SHE_encrypt;
    }
    // RequireJS/AMD
    // http://www.requirejs.org/docs/api.html
    // https://github.com/amdjs/amdjs-api/wiki/AMD
    else if (typeof(define) === 'function' && define.amd)
    {
	define([], function() { return SHE_encrypt; });
    }
    // Web Browsers
    else
    {
	
	root.SHE_encrypt = SHE_encrypt;
    }
})(this);

/*
 * vim: et:ts=4:sw=4:sts=4
 * -*- mode: JavaScript; coding: utf-8-unix; tab-width: 4 -*-
 */
