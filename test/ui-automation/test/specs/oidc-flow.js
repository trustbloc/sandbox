/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

"use strict";

const {wallet, issuer} = require("../helpers");

describe("TrustBloc - [PRC] Background Check Use Case (OIDC Share flow)", async function () {
    const ctx = {
        email: `ui-aut-oidc-${new Date().getTime()}@test.com`,
    };

    // runs once before the first test in this block
    before(async () => {
        await browser.reloadSession();
        await browser.maximizeWindow();
    });

    beforeEach(function () {
    });

    afterEach(async function () {
        if (this.currentTest.state === "failed") {
            const logs = await browser.getLogs("browser");
            console.log(JSON.stringify(logs, null, 4));
        }
    });

    it(`User Sign up (${ctx.email})`, async function () {
        // 1. Navigate to Wallet Website
        await browser.navigateTo(browser.config.walletURL);

        // 2. Initialize Wallet (register/sign-up/etc.)
        await wallet.signUp(ctx);
    });

    // Todo #1417 Replace with the OIDC Issuance
    it('Save Permanent Resident Card (WACI Issuance - Redirect)', async function () {
        // 1. Navigate to Issuer Website
        await browser.newWindow(browser.config.issuerURL);

        // 2. Authenticate at Issuer Website with Wallet
        await issuer.authenticate({credential: 'PermanentResidentCardWACI', skipDIDAuth: true});

        const redirectMsg = await $('a*=Click here to redirect to your wallet');
        await redirectMsg.waitForClickable();
        await redirectMsg.click()

        // 3. preview and store vc at wallet
        const prCardCred = await $('div*=Permanent Resident Card');
        await prCardCred.waitForExist();

        const lastNameFieldName = await $('td*=Family Name');
        await lastNameFieldName.waitForExist();

        const lastName = await $('td*=Pasteur');
        await lastName.waitForExist();

        await new Promise((resolve) => setTimeout(resolve, 2000));

        const storeBtn = await $('#storeVCBtn');
        await storeBtn.waitForClickable();
        await storeBtn.click();

        const okBtn = await $("#issue-credentials-ok-btn");
        await okBtn.waitForExist();
        await okBtn.click()

        // 4. validate success message at the issuer
        const successMsg = await $('div*=Your credential(s) have been stored in your digital wallet.');
        await successMsg.waitForExist();
    })

    it('Validate Permanent Resident Card in Wallet', async function () {
        // 1. Navigate to Credentials page on Wallet Website
        await browser.newWindow(browser.config.walletURL);
        await browser.refresh();

        // 2. Validate PRC in wallet
        await wallet.checkStoredCredentials('Permanent Resident Card')
    });

    it(`Present Permanent Resident Card at Background check (OIDC Share - Redirect)`, async function () {
        // 1. Navigate background check verifier
        await browser.navigateTo(browser.config.backgroundCheckURL);

        // 2. click on share PRC button
        const getCredentialButton = await $('#prCard');
        await getCredentialButton.waitForClickable();
        await getCredentialButton.click();

        // 3. share prc
        const prCardCred = await $('div*=Permanent Resident Card');
        await prCardCred.waitForExist();

        const shareCredBtn = await $('#share-credentials');
        await shareCredBtn.waitForClickable();
        await shareCredBtn.click();

        // 4. validate success msg;
        const successMsg = await $("b*=Successfully Received OIDC verifiable Presentation");
        await successMsg.waitForExist();
    });

    it(`User signs out`, async function () {
        await browser.navigateTo(browser.config.walletURL);
        await wallet.signOut(ctx);
    });
});

