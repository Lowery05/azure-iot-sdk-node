// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

'use strict';
import { errors } from 'azure-iot-common';
import * as machina from 'machina';
import * as tss from 'tss.js';
import { Tpm, TPM_HANDLE, TPM_ALG_ID, TPM_RC, TPM_PT, TPMA_OBJECT, TPMT_PUBLIC, TPM2B_PRIVATE } from 'tss.js';
import * as crypto from 'crypto';
import base32Encode = require('base32-encode');

import * as dbg from 'debug';

const debug = dbg('azure-iot-security-tpm:TpmSecurityClient');


const aes128SymDef = new tss.TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 128, TPM_ALG_ID.CFB);

const ekPersHandle: TPM_HANDLE = new TPM_HANDLE(0x81010001);
const srkPersHandle: TPM_HANDLE = new TPM_HANDLE(0x81000001);
const idKeyPersHandle: TPM_HANDLE = new TPM_HANDLE(0x81000100);

// Template of the Endorsement Key
const ekTemplate = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
  TPMA_OBJECT.restricted | TPMA_OBJECT.decrypt | TPMA_OBJECT.fixedTPM | TPMA_OBJECT.fixedParent | TPMA_OBJECT.adminWithPolicy | TPMA_OBJECT.sensitiveDataOrigin,
  new Buffer('837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa', 'hex'),
  new tss.TPMS_RSA_PARMS(aes128SymDef, new tss.TPMS_NULL_ASYM_SCHEME(), 2048, 0),
  new tss.TPM2B_PUBLIC_KEY_RSA());

// Template of the Storage Root Key
const srkTemplate = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
  TPMA_OBJECT.restricted | TPMA_OBJECT.decrypt | TPMA_OBJECT.fixedTPM | TPMA_OBJECT.fixedParent | TPMA_OBJECT.noDA | TPMA_OBJECT.userWithAuth | TPMA_OBJECT.sensitiveDataOrigin,
  null,
  new tss.TPMS_RSA_PARMS(aes128SymDef, new tss.TPMS_NULL_ASYM_SCHEME(), 2048, 0),
  new tss.TPM2B_PUBLIC_KEY_RSA());


interface PersistentKeyInformation {
  /**
   * Human readable name for debugging/logging purposes only
   */
  name: string;

  /**
   * The TPM hierarachy, to which the key belongs
   * @note All the keys are persisted in the owner hierarchy disregarding their mother one
   */
  hierarchy: TPM_HANDLE;

  /**
   * Handle value where the persistent key is expected to be found
   */
  handle: TPM_HANDLE;

  /**
   * Template to be used for key cretaion if the persistent key with the given handle does not exist
   */
  template: TPMT_PUBLIC;
}


export class TpmSecurityClient  {

  private _ek: TPMT_PUBLIC = null;
  private _srk: TPMT_PUBLIC = null;
  private _registrationId: string = '';
  private _tpm: Tpm;
  private _fsm: machina.Fsm;
  private _idKeyPub: TPMT_PUBLIC = null;


  constructor(registrationId?: string, customTpm?: any) {
    this._tpm = customTpm ? customTpm : new Tpm(false);
    if (registrationId) {
      this._registrationId = registrationId;
    }
    this._fsm = new machina.Fsm({
      initialState: 'disconnected',
      states: {
        disconnected: {
          _onEnter: (callback, err) => {
            this._ek = null;
            this._srk = null;
            if (callback) {
              if (err) {
                callback(err);
              } else {
                callback(null, null);
              }
            }
          },
          connect: (connectCallback) => this._fsm.transition('connecting', connectCallback),
          getEndorsementKey: (callback) => {
            this._fsm.handle('connect', (err, result) => {
              if (err) {
                callback(err);
              } else {
                this._fsm.handle('getEndorsementKey', callback);
              }
            });
          },
          getStorageRootKey: (callback) => {
            this._fsm.handle('connect', (err, result) => {
              if (err) {
                callback(err);
              } else {
                this._fsm.handle('getStorageRootKey', callback);
              }
            });
          },
          signWithIdentity: (dataToSign, callback) => {
            this._fsm.handle('connect', (err, result) => {
              if (err) {
                callback(err);
              } else {
                this._fsm.handle('signWithIdentity', dataToSign, callback);
              }
            });
          },
          activateSymmetricIdentityIdentity: (identityKey, callback) => {
            this._fsm.handle('connect', (err, result) => {
              if (err) {
                callback(err);
              } else {
                this._fsm.handle('activateSymmetricIdentityIdentity', identityKey, callback);
              }
            });
          },
          disconnect: (callback) => {
            if (callback) {
              callback();
            }
           }
        },
        connecting: {
          _onEnter: (callback) => {
            try {
              let self = this;
              this._tpm.connect(function (): void {
                self._createPersistentPrimary({ name: 'EK', hierarchy: tss.Endorsement, handle: ekPersHandle, template: ekTemplate }, (ekCreateErr, ekPublicKey) => {
                  if (ekCreateErr) {
                    self._fsm.transition('disconnected', callback, ekCreateErr);
                  } else {
                    self._ek = ekPublicKey;
                    self._createPersistentPrimary({ name: 'SRK', hierarchy: tss.Owner, handle: srkPersHandle, template: srkTemplate }, (srkCreateErr: Error, srkPublicKey: TPMT_PUBLIC) => {
                      if (srkCreateErr) {
                        self._fsm.transition('disconnected', callback, srkCreateErr);
                      } else {
                        self._srk = srkPublicKey;
                        self._fsm.transition('connected', callback);
                      }
                    });
                  }
                });
              });
            } catch (err) {
              this._fsm.transition('disconnected', callback, err);
            }
          },
          '*': () => this._fsm.deferUntilTransition()
        },
        connected: {
          _onEnter: (callback) => {
            callback(null);
          },
          getEndorsementKey: (callback) => {
            callback(null, this._ek.asTpm2B());
          },
          getStorageRootKey: (callback) => {
            callback(null, this._srk.asTpm2B());
          },
          signWithIdentity: (dataToSign, callback) => {
            this._signData(dataToSign, (err: Error, signedData: Buffer) => {
              if (err) {
                debug('Error from signing data: ' + err);
                this._fsm.transition('disconnected', callback, err);
              } else {
                callback(null, signedData);
              }
            });
          },
          activateSymmetricIdentity: (identityKey, callback) => {
            this._activateSymetricIdentity(identityKey, (err: Error) => {
              if (err) {
                debug('Error from activate: ' + err);
                this._fsm.transition('disconnected', callback, err);
              } else {
                callback(null);
              }
            });
          },
        }
      }
    });
  }

  getEndorsementKey(callback: (err: Error, endorsementKey: string) => void): void {
      this._fsm.handle('getEndorsementKey', callback);
  }

  getStorageRootKey(callback: (err: Error, storageKey: string) => void): void {
    this._fsm.handle('getStorageRootKey', callback);
  }

  signWithIdentity(dataToSign: Buffer, callback: (err: Error, signedData: Buffer) => void): void {
    if (dataToSign === null || dataToSign.length === 0) {
        throw new ReferenceError('\'dataToSign\' cannot be \'' + dataToSign + '\'');
    }
    if (this._idKeyPub == null) {
        throw new errors.InvalidOperationError('activateSymmetricIdentity must be invoked before any signing is attempted.');
    }
    this._fsm.handle('signWithIdentity', dataToSign, callback);
  }

  activateSymmetricIdentity(identityKey: Buffer, callback: (err: Error, returnedActivate: Buffer) => void): void {
    if (identityKey === null || identityKey.length === 0) {
      throw new ReferenceError('\'identityKey\' cannot be \'' + identityKey + '\'');
    }
    this._fsm.handle('activateSymmetricIdentiy', identityKey, callback);
  }

  getRegistrationId(callback: (err: Error, registrationId: string) => void): void {
    if (this._registrationId) {
      callback(null, this._registrationId);
    } else {
      this.getEndorsementKey( function (endorsementError: Error, endorsementKey: string): void {
        if (endorsementError) {
          callback(endorsementError, null);
        } else {
          let hasher = crypto.createHash('sha256');
          hasher.update(endorsementKey);
          this._registrationId = (base32Encode(hasher.digest(), 'RFC4648').toLowerCase()).replace(/=/g, '');
          callback(null, this._registrationId);
        }
      }.bind(this));
    }
  }

  private _createPersistentPrimary(pki: PersistentKeyInformation, callback: (err: Error, resultPublicKey: TPMT_PUBLIC) => void): void {
    this._tpm.allowErrors().ReadPublic(pki.handle, (resp: tss.ReadPublicResponse) => {
      let rc = this._tpm.getLastResponseCode();
      debug('ReadPublic(' + pki.name + ') returned ' + TPM_RC[rc] +  (rc === TPM_RC.SUCCESS ? '; PUB: ' + resp.outPublic.toString() : ''));
      if (rc !== TPM_RC.SUCCESS) {
        this._tpm.withSession(tss.NullPwSession).CreatePrimary(pki.hierarchy, new tss.TPMS_SENSITIVE_CREATE(), pki.template, null, null, (resp: tss.CreatePrimaryResponse) => {
          debug('CreatePrimary(' + pki.name + ') returned ' + TPM_RC[this._tpm.getLastResponseCode()] + '; pub size: ' + (resp.outPublic.unique as tss.TPM2B_PUBLIC_KEY_RSA).buffer.length);
          this._tpm.withSession(tss.NullPwSession).EvictControl(tss.Owner, resp.handle, pki.handle, () => {
            debug('EvictControl(0x' + resp.handle.handle.toString(16) + ', 0x' + pki.handle.handle.toString(16) + ') returned ' + TPM_RC[this._tpm.getLastResponseCode()]);
            this._tpm.FlushContext(resp.handle, () => {
              debug('FlushContext(TRANSIENT_' + pki.name + ') returned ' + TPM_RC[this._tpm.getLastResponseCode()]);
              callback(null, resp.outPublic);
            });
          });
        });
      } else {
        callback(null, resp.outPublic);
      }
    });
  }

  private _signData(dataToSign: Buffer, callback: (err: Error, signedData: Buffer) => void): void {

    let idKeyHashAlg: TPM_ALG_ID = (<tss.TPMS_SCHEME_HMAC>(<tss.TPMS_KEYEDHASH_PARMS>this._idKeyPub.parameters).scheme).hashAlg;

    this._tpm.GetCapability(tss.TPM_CAP.TPM_PROPERTIES, TPM_PT.INPUT_BUFFER, 1, (caps: tss.GetCapabilityResponse) => {
      let props = <tss.TPML_TAGGED_TPM_PROPERTY>caps.capabilityData;
      if (props.tpmProperty.length !== 1 || props.tpmProperty[0].property !== TPM_PT.INPUT_BUFFER) {
        callback(new errors.DeviceRegistrationFailedError('Unexpected result of TPM2_GetCapability(TPM_PT.INPUT_BUFFER)'), null);
      } else {
        let maxInputBuffer: number = props.tpmProperty[0].value;
        if (dataToSign.length <= maxInputBuffer) {
          this._tpm.withSession(tss.NullPwSession).HMAC(idKeyPersHandle, dataToSign, idKeyHashAlg, (signature: Buffer) => {
            callback(null, signature);
          });
        } else {
          let curPos: number = 0;
          let bytesLeft: number = dataToSign.length;
          let hSequence: TPM_HANDLE = null;
          let signature = new Buffer(0);
          let loopFn = () => {
            if (bytesLeft > maxInputBuffer) {
                this._tpm.withSession(tss.NullPwSession).SequenceUpdate(hSequence, dataToSign.slice(curPos, curPos + maxInputBuffer), loopFn);
                console.log('SequenceUpdate() invoked for slice [' + curPos + ', ' + (curPos + maxInputBuffer) + ']');
                bytesLeft -= maxInputBuffer;
                curPos += maxInputBuffer;
            } else {
              this._tpm.withSession(tss.NullPwSession).SequenceComplete(hSequence, dataToSign.slice(curPos, curPos + bytesLeft), new TPM_HANDLE(tss.TPM_RH.NULL), (resp: tss.SequenceCompleteResponse) => {
                console.log('SequenceComplete() succeeded; signature size ' + signature.length);
              });
            }
          };
          this._tpm.withSession(tss.NullPwSession).HMAC_Start(idKeyPersHandle, signature, idKeyHashAlg, (hSeq: TPM_HANDLE) => {
            console.log('HMAC_Start() returned ' + TPM_RC[this._tpm.getLastResponseCode()]);
            hSequence = hSeq;
            loopFn();
          });
        }
      }
    });
  }

  private _activateSymetricIdentity(activationBlob: Buffer, activateCallback: (err: Error) => void): void {

    let currentPosition = 0;
    let credentialBlob: tss.TPMS_ID_OBJECT;
    let encodedSecret = new tss.TPM2B_ENCRYPTED_SECRET();
    let idKeyDupBlob = new TPM2B_PRIVATE();
    let encWrapKey = new tss.TPM2B_ENCRYPTED_SECRET();

    //
    // Unmarshal components of the activation blob received from the provisioning service.
    //
    [credentialBlob, currentPosition] = tss.marshal.sizedFromTpm(tss.TPMS_ID_OBJECT, activationBlob, 2, currentPosition);
    debug('credentialBlob end: ' + currentPosition);
    currentPosition = encodedSecret.fromTpm(activationBlob, currentPosition);
    debug('encodedSecret end: ' + currentPosition);
    currentPosition = idKeyDupBlob.fromTpm(activationBlob, currentPosition);
    debug('idKeyDupBlob end: ' + currentPosition);
    currentPosition = encWrapKey.fromTpm(activationBlob, currentPosition);
    debug('encWrapKey end: ' + currentPosition);
    [this._idKeyPub, currentPosition] = tss.marshal.sizedFromTpm(TPMT_PUBLIC, activationBlob, 2, currentPosition);
    debug('idKeyPub end: ' + currentPosition);

    //
    // Start a policy session to be used with ActivateCredential()
    //

    this._tpm.GetRandom(20, (nonce: Buffer) => {
      this._tpm.StartAuthSession(null, null, nonce, null, tss.TPM_SE.POLICY, tss.NullSymDef, TPM_ALG_ID.SHA256, (resp: tss.StartAuthSessionResponse) => {
        debug('StartAuthSession(POLICY_SESS) returned ' + TPM_RC[this._tpm.getLastResponseCode()] + '; sess handle: ' + resp.handle.handle.toString(16));
        if (this._tpm.getLastResponseCode() !== TPM_RC.SUCCESS) {
          activateCallback(new errors.DeviceRegistrationFailedError('Authorization session unable to be created.'));
        } else {
          let policySession = new tss.Session(resp.handle, resp.nonceTPM);

          //
          // Apply the policy necessary to authorize an EK on Windows
          //

          this._tpm.withSession(tss.NullPwSession).PolicySecret(tss.Endorsement, policySession.SessIn.sessionHandle, null, null, null, 0, (resp: tss.PolicySecretResponse) => {
            debug('PolicySecret() returned ' + TPM_RC[this._tpm.getLastResponseCode()]);
            if (this._tpm.getLastResponseCode() !== TPM_RC.SUCCESS) {
              activateCallback(new errors.DeviceRegistrationFailedError('Upable to apply the necessary policy to authorize the EK.'));
            } else {

              //
              // Use ActivateCredential() to decrypt symmetric key that is used as an inner protector
              // of the duplication blob of the new Device ID key generated by DRS.
              //

              this._tpm.withSessions(tss.NullPwSession, policySession).ActivateCredential(srkPersHandle, ekPersHandle, credentialBlob, encodedSecret.secret, (innerWrapKey: Buffer) => {
                debug('ActivateCredential() returned ' + TPM_RC[this._tpm.getLastResponseCode()] + '; innerWrapKey size ' + innerWrapKey.length);
                if (this._tpm.getLastResponseCode() !== TPM_RC.SUCCESS) {
                  activateCallback(new errors.DeviceRegistrationFailedError('Upable to decrypt the symmetric key used to protect duplication blob.'));
                } else {

                  //
                  // Initialize parameters of the symmetric key used by DRS
                  // Note that the client uses the key size chosen by DRS, but other parameters are fixed (an AES key in CFB mode).
                  //
                  let symDef = new tss.TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, innerWrapKey.length * 8, TPM_ALG_ID.CFB);

                  //
                  // Import the new Device ID key issued by DRS to the device's TPM
                  //

                  this._tpm.withSession(tss.NullPwSession).Import(srkPersHandle, innerWrapKey, this._idKeyPub, idKeyDupBlob, encWrapKey.secret, symDef, (idKeyPriv: TPM2B_PRIVATE) => {
                    debug('Import() returned ' + TPM_RC[this._tpm.getLastResponseCode()] + '; idKeyPriv size ' + idKeyPriv.buffer.length);
                    if (this._tpm.getLastResponseCode() !== TPM_RC.SUCCESS) {
                      activateCallback(new errors.DeviceRegistrationFailedError('Upable to import the device id key into the TPM.'));
                    } else {

                      //
                      // Load the imported key into the TPM
                      //

                      this._tpm.withSession(tss.NullPwSession).Load(srkPersHandle, idKeyPriv, this._idKeyPub, (hIdKey: TPM_HANDLE) => {
                        debug('Load() returned ' + TPM_RC[this._tpm.getLastResponseCode()] + '; ID key handle: 0x' + hIdKey.handle.toString(16));
                        if (this._tpm.getLastResponseCode() !== TPM_RC.SUCCESS) {
                          activateCallback(new errors.DeviceRegistrationFailedError('Upable to load the device id key into the TPM.'));
                        } else {

                          //
                          // Remove possibly existing persistent instance of the previous Device ID key
                          //

                          this._tpm.allowErrors().withSession(tss.NullPwSession).EvictControl(tss.Owner, idKeyPersHandle, idKeyPersHandle, () => {

                            //
                            // Persist the new Device ID key
                            //

                            this._tpm.withSession(tss.NullPwSession).EvictControl(tss.Owner, hIdKey, idKeyPersHandle, () => {
                              console.log('EvictControl(0x' + hIdKey.handle.toString(16) + ', 0x' + idKeyPersHandle.handle.toString(16) + ') returned ' + TPM_RC[this._tpm.getLastResponseCode()]);
                              if (this._tpm.getLastResponseCode() !== TPM_RC.SUCCESS) {
                                activateCallback(new errors.DeviceRegistrationFailedError('Upable to persist the device id key into the TPM.'));
                              } else {

                                //
                                // Free the ID Key transient handle and the session object.  Doesn't matter if it "fails".  Go on at this point./
                                //

                                this._tpm.FlushContext(hIdKey, () => {
                                  debug('FlushContext(TRANS_ID_KEY) returned ' + TPM_RC[this._tpm.getLastResponseCode()]);
                                  this._tpm.FlushContext(policySession.SessIn.sessionHandle, () => {
                                    debug('FlushContext(POLICY_SESS) returned ' + TPM_RC[this._tpm.getLastResponseCode()]);
                                    activateCallback(null);
                                  });
                                });
                              }
                            });
                          });
                        }
                      });
                    }
                  });
                }
              });
            }
          });
        }
      });
    });
  }
}

