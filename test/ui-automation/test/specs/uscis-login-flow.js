/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

"use strict";

const {wallet, issuer, chapi, verifier} = require("../helpers");

describe("TrustBloc - [PRC] Background Check Use Case (Third Party Login Flow)", async function () {
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

    it('Save Permanent Resident Card (Third Party Login Flow - Redirect)', async function () {

        if (browser.config.local === true){
            // 1. Navigate to pr card Issuer Website
            await browser.newWindow(browser.config.issuePrCardURL);

            // 2. Click on issuing pr card
            const issuePrc = await $('#permanentResidentCard');
            await issuePrc.waitForClickable();
            await issuePrc.click()

            // login
            const loginButton = await $('#accept');
            await loginButton.click();

            // consent
            const consentButton = await $('#accept');
            await consentButton.click();
        } else {
            // 1. Navigate to pr card Issuer Website
            await browser.newWindow(browser.config.issuePrCardURL);

            // 2. Click on issuing pr card
            const issuePrc = await $('#permanentResidentCard');
            await issuePrc.waitForClickable();
            await issuePrc.click()

            // 3. sign in into third party login
            const thirdPartyLogin = await $('h1*=Login with Username and Password');
            await thirdPartyLogin.waitForExist();

            const username = await $('#j_username');
            await username.setValue('louis');

            const password = await $('#j_password');
            await password.setValue('pasteur');

            const loginBtn = await $('[value="Login"]')
            await loginBtn.click();

            const rememberNotBtn = await $('#remember-not')
            await rememberNotBtn.waitForClickable();
            await rememberNotBtn.click()

            const authorizeBtn = await $('[value="Authorize"]')
            await authorizeBtn.click();
        }

        const authBtn = await $('#authBtn');
        await authBtn.waitForClickable();
        await authBtn.click();

        // 4. Store credential with Wallet
        await chapi.chooseWallet({
            name: browser.config.walletName,
        });
        await wallet.authenticate(ctx);
        await browser.switchToFrame(null);

        const storeBtn = await $('#storeVCBtn');
        await storeBtn.waitForExist();
        await storeBtn.waitForClickable();
        await storeBtn.click();

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
            setTimeout(done, 5000)
        })

    })

    it('Present Permanent Resident Card at Duty Free Shop (Third Party Login Flow - Redirect)', async function () {
        // 1. Navigate prc verifier
        await browser.newWindow(browser.config.dutyFreeShop);

        // 2. click on share PRC button
        const getCredentialButton = await $('#prCard');
        await getCredentialButton.waitForClickable();
        await getCredentialButton.click();

        // 3. use redirect flow
        const redirectMsg = await $('a*=Click here to redirect to your wallet');
        await redirectMsg.waitForClickable();
        await redirectMsg.click()

        // 4. share prc
        const prCardCred = await $('div*=Permanent Resident Card');
        await prCardCred.waitForExist();

        const shareCredBtn = await $('#share-credentials');
        await shareCredBtn.waitForClickable();
        await shareCredBtn.click();

        const sharedBtn = await $('#share-credentials-ok-btn');
        await sharedBtn.waitForClickable();
        await sharedBtn.click();

        // 5. validate success msg
        const verifySuccessMsg = await $('div*=Successfully Verified');
        await verifySuccessMsg.waitForExist();

        const lastNameFieldName = await $('td*=Family Name');
        await lastNameFieldName.waitForExist();

        const lastName = await $('td*=Pasteur');
        await lastName.waitForExist();

        const proceedBtn = await $('#proceedClick');
        await proceedBtn.waitForClickable();
        await proceedBtn.click();

        const successMsg = await $('div*=Your Permanent Resident Card Verified Successfully');
        await successMsg.waitForExist();
    })

    it(`User signs out`, async function () {
        await browser.navigateTo(browser.config.walletURL);
        await wallet.signOut(ctx);
    });
});

