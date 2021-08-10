/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/


'use strict';

const {chapi, wallet, issuer, verifier} = require('../helpers');
const profile= "trustbloc-ed25519signature2018-ed25519";
const credentialKey ="PermanentResidentCard";
const skipStatusCheck= false

/*
   Use Case handling the following flow in the sequence:
   1. User signup to the wallet.
   2. Issuer issues the credential and save the credential.
   3. User logout from the wallet.
   4. User sign in to the wallet.
   5. Check the saved credential present in the wallet.
   6. Verifies the saved credential.
   7. User logout from the wallet.
   8. User changes the locale
 */

describe("TrustBloc - SignUp and SignIn flow", () => {
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

    it(`User Sign up (${ctx.email})`, async function () {
        this.timeout(300000);

        // 1. Navigate to Wallet Website
        await browser.navigateTo(browser.config.walletURL);

        // 2. Initialize Wallet (register/sign-up/etc.)
        await wallet.init(ctx);
    });

    it('User issues and save credential', async () => {
        console.log("issue and save cred")
        // 1. Navigate to Issuer Website
        await browser.newWindow(browser.config.issuerURL);

        // 2. Authenticate at Issuer Website with Wallet
        await issuer.authenticate({credential: credentialKey, profile: profile});
        await chapi.chooseWallet({
            name: browser.config.walletName,
        });
        await wallet.authenticate(ctx);
        await browser.switchToFrame(null);
        console.log("issue and save cred")
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
            setTimeout(done, 5000)
        })
    });
    it(`User Logout (${ctx.email})`, async function () {
        this.timeout(300000);

        // 1. Navigate to Wallet Website
        await browser.navigateTo(browser.config.walletURL);

        // 2. Initialize Wallet (register/sign-up/etc.)
        await wallet.logout(ctx);
    });

    it(`User Sign in (${ctx.email})`, async function () {
        this.timeout(300000);

        // 1. Navigate to Wallet Website
        await browser.navigateTo(browser.config.walletURL);

        // 2. Sign In to the registered Wallet (register/sign-up/etc.)
        await wallet.signIn(ctx);
    });
    it(`Check if the credential is stored in the wallet (${ctx.email})`, async function () {
        this.timeout(300000);

        // 1. Navigate to Wallet Website
        await browser.navigateTo(browser.config.walletURL);

        // 2. Check if the credential is stored to the registered Wallet (register/sign-up/etc.)
        await wallet.checkStoredCredentials(ctx);
    });
    it('User verifies the stored credential', async () => {
        // 1. Navigate to Verifier Website
        await browser.newWindow(browser.config.verifierURL);

        // 2. Verify credentials at Verifier Website with Wallet
        await verifier.verify({credential: credentialKey, skipStatusCheck: skipStatusCheck});
        await chapi.chooseWallet({
            name: browser.config.walletName,
        });
        await wallet.presentCredentials(ctx);
        await browser.switchToFrame(null);

        // 3. Show success message at Verifier Website
        await verifier.finish(ctx);
    });
    it(`User Logout (${ctx.email})`, async function () {
        this.timeout(300000);

        // 1. Navigate to Wallet Website
        await browser.navigateTo(browser.config.walletURL);

        // 2. Initialize Wallet (register/sign-up/etc.)
        await wallet.logout(ctx);
    });
    it(`User changes locale (${ctx.email})`, async function () {
        this.timeout(300000);

        // 1. Navigate to Wallet Website
        await browser.navigateTo(browser.config.walletURL);

        // 2. Change locale
        await wallet.changeLocale();
    });
})


