// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

'use strict';
var common = require("azure-iot-common");
var TpmSecurityClient  = require('../lib/tpm').TpmSecurityClient ;
var tss = require("tss.js");
var tss_js_1 = require("tss.js");
var sinon = require('sinon');


var assert = require('chai').assert;

var fakeSimpleTpmClient = {
  allowErrors: () => {return this},
  connect: (callback) => {callback();},
  ReadPublic: (handle, callback) => {
    callback(null,null);
  },
  fakeSimpleTpmClient: () => {},
  getLastResponseCode: () => {
    return tss_js_1.TPM_RC.SUCCESS;
  }

}
describe('tpm', function () {
  this.timeout(1000);

  // var obj = new TpmSecurityClient ('MYREGID');

  describe('getEndorsementKey', function() {
    it('returns the endorsement key', function(done) {
      var client = new TpmSecurityClient(undefined, fakeSimpleTpmClient );
      var persistStub = sinon.stub(client,'_createPersistentPrimary');
      persistStub.withArgs('EK').callsArgWith(4, null, TpmSecurityClient._ekTemplate);
      persistStub.withArgs('SRK').callsArgWith(4, null, TpmSecurityClient._srkTemplate);
      client.getEndorsementKey((err, localEk) => {
        assert.deepEqual(localEk, TpmSecurityClient._ekTemplate.asTpm2B(), 'Invalid endorsment key returned.');
        done();
      });
    });
  });

  describe('getStorageRootKey', function() {
    it('returns the storage root key', function(done) {
      var client = new TpmSecurityClient(undefined, fakeSimpleTpmClient );
      var persistStub = sinon.stub(client,'_createPersistentPrimary');
      persistStub.withArgs('EK').callsArgWith(4, null, TpmSecurityClient._ekTemplate);
      persistStub.withArgs('SRK').callsArgWith(4, null, TpmSecurityClient._srkTemplate);
      client.getStorageRootKey((err, localSrk) => {
        assert.deepEqual(localSrk, TpmSecurityClient._srkTemplate.asTpm2B(), 'Invalid storage root key returned.');
        done();
      });
    });
  });

  // describe('signWithIdentity', function() {
  //   it ('throws', function() {
  //     assert.throws(function() {
  //       obj.signWithIdentity();
  //     });
  //   });
  // });

  // describe('activateSymmetricIdentity', function() {
  //   it ('throws', function() {
  //     assert.throws(function() {
  //       obj.activateSymmetricIdentity();
  //     });
  //   });
  // });

  describe('getRegistrationId', function() {
    /*Tests_SRS_NODE_TPM_SECURITY_CLIENT_06_003: [If the TpmSecurityClient was given a `registrationId` at creation, that `registrationId` will be returned.] */
    it('returns original id', function(done) {
      var providedRegistrationClient = new TpmSecurityClient('MYREGID', fakeSimpleTpmClient );
      providedRegistrationClient.getRegistrationId((err, id) => {
        assert.strictEqual(id, 'MYREGID', 'Incorrect registration Id.' );
        done();
      });
    });

    it('returns constructed registration id', function(done) {
      /*Tests_SRS_NODE_TPM_SECURITY_CLIENT_06_004: [If not provided, the `registrationId` will be constructed and returned as follows:
        The endorsementKey will be queried.
        The endorsementKey will be hashed utilizing SHA256.
        The resultant digest will be bin32 encoded in conformance with the `RFC4648` specification.
        The resultant string will have terminating `=` characters removed.] */
      var providedRegistrationClient = new TpmSecurityClient(undefined, fakeSimpleTpmClient );
      sinon.stub(providedRegistrationClient,'getEndorsementKey').callsArgWith(0, null, 'MYREGID');
      providedRegistrationClient.getRegistrationId((err, id) => {
        assert.strictEqual(id, 'vfn2bxtbqwc3pcflozty5reiunt5qm4ztk4ulrszujmqj3zbei2a', 'Incorrect registration Id.' );
        done();
      });
    });

    it('handles an error', function(done) {
      /*Tests_SRS_NODE_TPM_SECURITY_CLIENT_06_005: [Any errors from interacting with the TPM hardware will cause an InvalidOperationError to be returned in the err parameter of the callback.] */
      var errorFromGetEndorsement = new common.errors.InvalidOperationError('Error from hardware');
      var providedRegistrationClient = new TpmSecurityClient(undefined, fakeSimpleTpmClient );
      sinon.stub(providedRegistrationClient,'getEndorsementKey').callsArgWith(0, errorFromGetEndorsement, null);
      providedRegistrationClient.getRegistrationId((err, id) => {
        assert.strictEqual(err, errorFromGetEndorsement, 'Improper error returned');
        done();
      });
    });

  });

});

