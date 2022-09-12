
/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

"use strict";

const {config} = require('./wdio.shared.conf');
const domain = ".local.trustbloc.dev"

exports.config = {
    ...config,

    // Test files
    specs: [
        "./test/specs/oidc-flow.js",
    ],

    walletName: "vcwallet" + domain,
    walletURL: "https://vcwallet" + domain,
    applyPrCardURL: "https://demo-issuer" + domain + "/applyprcard",
    backgroundCheckURL: "https://demo-rp" + domain + "/backgroundcheck",
    isCHAPIEnabled: false
};