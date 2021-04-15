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

// TODO - get the values from environmental variables
api.WALLET_NAME = 'wallet.local.trustbloc.dev'
api.WALLET_URL = 'https://wallet.local.trustbloc.dev'
api.ISSUER_URL = 'https://issuer.local.trustbloc.dev'
api.VERIFIER_URL = 'https://rp.local.trustbloc.dev'
