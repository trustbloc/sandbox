/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict';

const chapi = require('./chapi');
const wallet = require('./wallet');
const issuer = require('./issuer');
const verifier = require('./verifier');

const api = {};
module.exports = api;

api.chapi = chapi;
api.wallet = wallet;
api.issuer = issuer;
api.verifier = verifier;
