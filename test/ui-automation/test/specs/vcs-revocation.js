/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict';

const { chapi, wallet, issuer, verifier } = require('../helpers');
const credentialKey = "PermanentResidentCard";


describe("TrustBloc - Verifiable Credential Service (VCS) revocation flow", () => {
    const ctx = {
        email: `ui-aut-${new Date().getTime()}@test.com`,
    };

    // runs once before the first test in this block
    before(async () => {
        await browser.reloadSession();
        await browser.maximizeWindow();
    });

    beforeEach(function () {
    });

    it(`Sign Up to TrustBloc Wallet (${ctx.email})`, async function () {
        // 1. Navigate to Wallet 
        await browser.navigateTo(browser.config.walletURL);

        // 2. Sign up
        await wallet.signUp(ctx);
    });

    it(`Save credential`, async function () {
        // 1. Navigate to Issuer Website
        await browser.newWindow(browser.config.issuerURL);

        // 2. Authenticate at Issuer Website with Wallet
        await issuer.authenticate({ credential: credentialKey });
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
    });

    it(`Verify credential (Success)`, async function () {
        // 1. Navigate to Verifier Website
        await browser.newWindow(browser.config.verifierURL);

        // 2. Verify credentials at Verifier Website with Wallet
        await verifier.verify({ credential: credentialKey, skipStatusCheck: false });
        await chapi.chooseWallet({
            name: browser.config.walletName,
        });
        await wallet.presentCredentials(ctx);
        await browser.switchToFrame(null);

        // 3. Show success message at Verifier Website
        await verifier.finish(ctx);
    });

    it(`Revoke credential`, async function () {
        // 1. Navigate to Issuer Website
        await browser.newWindow(browser.config.issuerURL);

        // 2. revoke vc
        const revokeVCBtn = await $('#revokeVCBtn');
        await revokeVCBtn.scrollIntoView()
        await revokeVCBtn.click()

        await chapi.chooseWallet({
            name: browser.config.walletName,
        });
        await wallet.presentCredentials(ctx);
        await browser.switchToFrame(null);

        // 4. validate success msg
        const successMsg = await $('h3*=VC is revoked');
        await successMsg.waitForExist();
    });

    it(`Verify revoked credential (Failure)`, async function () {
        // 1. Navigate to Verifier Website
        await browser.newWindow(browser.config.verifierURL);

        // 2. validate vc
        await verifier.verify({ credential: credentialKey, skipStatusCheck: false });
        await chapi.chooseWallet({
            name: browser.config.walletName,
        });
        await wallet.presentCredentials(ctx);
        await browser.switchToFrame(null);

        // 4. validate revoked error msg
        const successMsg = await $('p*=Oops verification is failed. VC is revoked');
        await successMsg.waitForExist();
    });
})


