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

    it('Save Permanent Resident Card (OIDC Issuance - Redirect)', async function () {
        // 1. Navigate to oidc Issuer Website
        await browser.newWindow(browser.config.applyPrCardURL);

        // 2. Click on applying pr card
        const applyPrc = await $('#applyprc');
        await applyPrc.waitForClickable();
        await applyPrc.click()

        // 3. sign in into oidc login page
        const issuerLogin = await $('#issuer-login');
        await issuerLogin.waitForExist();
        await issuerLogin.click()

        const lastNameFieldName = await $('td*=Family Name');
        await lastNameFieldName.waitForExist();

        const lastName = await $('td*=SMITH');
        await lastName.waitForExist();

        await new Promise((resolve) => setTimeout(resolve, 2000));

        const storeBtn = await $('#storeVCBtn');
        await storeBtn.waitForClickable();
        await storeBtn.click();

        // 4. validate success message at the issuer
        const successMsg = await $('span*=Your Permanent Resident Card is now in your wallet.');
        await successMsg.waitForExist();

        const okBtn = await $("#issue-credentials-ok-btn");
        await okBtn.waitForExist();
        await okBtn.click()
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

        // TODO#1431 - OIDC share is giving connection closed error after clicking share button
        /*
        // 4. validate success msg;
        const successMsg = await $("b*=Successfully Received OIDC verifiable Presentation");
        await successMsg.waitForExist();*/
    });

    it(`User signs out`, async function () {
        await browser.navigateTo(browser.config.walletURL);
        await wallet.signOut(ctx);
    });
});

