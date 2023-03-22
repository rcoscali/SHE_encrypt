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
    function SHE_encrypt(id, name, fv, payload, pad, msb)
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

        this.frameId = id;
        if (this.frameId !== undefined)
        {
            var idRegex = /^0x(?<id>[0-9a-fA-F]+)$/;
            var fields;
            if ((fields = idRegex.exec(this.frameId)) != null)
                this.frameId = fields.groups.id;

            if (this.frameId.length == 2)
                this.frameId = '00' + this.frameId;
            else if (this.frameId.length == 3)
                this.frameId = '0' + this.frameId;                            
        }
        else
            this.frameId = '0000';

        this.frameId = Buffer.from(this.frameId, 'hex');

        console.log("[3] this.frameId.toString('hex') = " + this.frameId.toString('hex'));

        this.name = name;
        this.fv = fv;
        this.payload = payload;
        this.pad = pad;
        this.msb = msb;
        SHE_encrypt.prototype.frameId = this.frameId;
        SHE_encrypt.prototype.name = this.name;
        SHE_encrypt.prototype.fv = this.fv;
        SHE_encrypt.prototype.payload = this.payload;
        SHE_encrypt.prototype.pad = this.pad;
        SHE_encrypt.prototype.msb = this.msb;

        SHE_encrypt.prototype.buildFrame = () =>
        {
            var resyncRE = /^.*ReSync.*$/g;
            var syncRE = /^.*Sync.*$/g;
            var scfdRE = /^.*SC_FD.*$/g;

            var frame;
            // Rebuild a ReSync frame
            if (resyncRE.test(SHE_encrypt.prototype.name))
            {
                frame = Buffer.concat(
                    [this.frameId, this.fv, this.pad]
                );
            }
            // Rebuild a Sync frame
            else if (syncRE.test(this.name))
            {
                frame = Buffer.concat(
                    [this.frameId, this.fv, this.pad]
                );
            }
            // Rebuild a misc secured frame
            // (needing the prev Sync frame MSB)
            else if (scfdRE.test(this.name))
            {
                frame = Buffer.concat(
                    [this.frameId, this.payload, this.msb, this.fv]
                );
            }
            else
            {
                frame = null;
            }
            return(frame);
        };
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
