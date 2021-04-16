/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Digital Bazaar

Some part of the code in this repo was copied from https://github.com/w3c-ccg/chapi-interop-test-suite/blob/main/test/specs/2020-05-07-dhs-cmtr.js.
The license details are available at https://github.com/w3c-ccg/chapi-interop-test-suite#license.

SPDX-License-Identifier: Apache-2.0
*/

'use strict';

const {chapi, wallet, issuer, verifier} = require('../helpers');
const path = require('path');
const uuid = require('uuid-random');

const SCENARIO_KEY = path.parse(__filename).name;

var flows = new Map();
flows.set('PermanentResidentCard', {
    description: "Apply for Home Loan using Permanent Resident Card",
    profile: "trustbloc-ed25519signature2018-ed25519",
    skipStatusCheck: false
});
flows.set('VaccinationCertificate', {
    description: "Vaccination Certificate Verification",
    profile: "didkey-bbsblssignature2020-bls12381g2",
    skipStatusCheck: false
});
flows.set('UniversityDegreeCredential', {
    description: "Apply for University Grant using University Degree Credential",
    profile: "trustbloc-jsonwebsignature2020-ed25519",
    skipStatusCheck: false
});
flows.set('StudentCard', {
    description: "File Tax Return using Student Card",
    profile: "trustbloc-jsonwebsignature2020-p256",
    skipStatusCheck: false
});
flows.set('TravelCard', {
    description: "Get discount during Prescription Pickup showing Travel Card",
    profile: "didkey-ed25519signature2018-ed25519",
    skipStatusCheck: true
});
flows.set('CertifiedMillTestReport', {
    description: "Order Shipment for Raw Material using Certified Mill Test Report",
    profile: "elem-ed25519signature2018-ed25519",
    skipStatusCheck: true
});

describe("TrustBloc - Verifiable Credential Service (VCS) flows", () => {
    const ctx = {
        email: `${uuid()}@example.com`,
    };

    // runs once before the first test in this block
    before(async () => {
        await browser.reloadSession();
        await browser.maximizeWindow();
    });

    beforeEach(function () {
    });

    it('Register a Wallet', async function () {
        this.timeout(300000);

        // 1. Navigate to Wallet Website
        await browser.navigateTo(browser.config.walletURL);

        // 2. Initialize Wallet (register/sign-up/etc.)
        await wallet.init(ctx);
    });


    for (const [key, value] of flows.entries()) {
        describe(value.description, () => {
            it('issues a credential ' + key, async () => {
                // 1. Navigate to Issuer Website
                await browser.newWindow(browser.config.issuerURL);

                // 2. Authenticate at Issuer Website with Wallet
                await issuer.authenticate({credential: key, profile: value.profile});
                await chapi.chooseWallet({
                    name: browser.config.walletName,
                });
                await wallet.authenticate(ctx);
                await browser.switchToFrame(null);

                // 3. Issue credential to authenticated DID at Issuer Website
                await issuer.issue(ctx);

                // 4. Store credential with Wallet
                await chapi.chooseWallet({
                    name: browser.config.walletName,
                });
                await wallet.storeCredentials(ctx);
                await browser.switchToFrame(null);

                // 5. Show success message at Issuer Website
                await issuer.finish(ctx);

                // wait for any async operations to complete
                browser.executeAsync((done) => {
                    setTimeout(done, 10000)
                })
            })

            it('verifies a credential ' + key, async () => {
                // 1. Navigate to Verifier Website
                await browser.newWindow(browser.config.verifierURL);

                // 2. Verify credentials at Verifier Website with Wallet
                await verifier.verify({credential: key, skipStatusCheck: value.skipStatusCheck});
                await chapi.chooseWallet({
                    name: browser.config.walletName,
                });
                await wallet.presentCredentials(ctx);
                await browser.switchToFrame(null);

                // 3. Show success message at Verifier Website
                await verifier.finish(ctx);
            })
        })
    }
})

