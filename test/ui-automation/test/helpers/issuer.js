/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict';

const constants = require('./constants');

const timeout = 60000;

const FLOW_IDS = {
    'PermanentResidentCard': '#prCard',
    'VaccinationCertificate': '#vaccinationCertificate',
    'UniversityDegreeCredential': '#universityDegree',
    'StudentCard': '#studentCard',
    'TravelCard': '#travelCard',
    'CrudeProductCredential': '#cpr',
    'CertifiedMillTestReport': '#cmtr',
    'PermanentResidentCardWACI': '#prcWACI',
}

const ISSUER_PROFILES = {
    'trustbloc-ed25519signature2018-ed25519': '#trustbloc-ed',
    'trustbloc-jsonwebsignature2020-ed25519': '#trustbloc-jwse',
    'trustbloc-jsonwebsignature2020-p256': '#trustbloc-jwsp',
    'interop-ed25519signature2018-ed25519': '#interop-ed',
    'interop-jsonwebsignature2020-ed25519': '#interop-jwse',
    'interop-jsonwebsignature2020-p256': '#interop-jwsp',
    'elem-ed25519signature2018-ed25519': '#elem-ed',
    'didkey-ed25519signature2018-ed25519': '#didkey-ed',
    'didkey-bbsblssignature2020-bls12381g2': '#didkey-ed',
    'vc-issuer-interop-key': '#interop-didkey-ed',
}

/*************************** Public API ******************************/

exports.authenticate = async ({credential, profile, skipDIDAuth}) => {
    // profile setting if required
    await _changeProfile({profile})

    // dashboard
    const btnID = FLOW_IDS[credential]
    const issuePrcBtn = await $(btnID);
    await issuePrcBtn.waitForExist();
    await issuePrcBtn.click();

    // login
    const loginButton = await $('#accept');
    await loginButton.click();

    // consent
    const consentButton = await $('#accept');
    await consentButton.click();

    if (!skipDIDAuth) {
        // did auth
        const authenticateBtn = await $('#authBtn');
        await authenticateBtn.waitForClickable();
        await authenticateBtn.click();
    }
};

exports.loginConsent = async (btnID) => {
    await browser.pause(1000)

    // issue cred
    const issueButton = await $(btnID);
    await issueButton.waitForClickable();
    await issueButton.click();

    // login
    const loginButton = await $('#accept');
    await loginButton.click();

    // consent
    const consentButton = await $('#accept');
    await consentButton.click();
};

exports.selectBrowserWalletType = async () => {
    await browser.pause(3000)

    const selectBrowserButton = await $('button*=Browser Wallet');
    const displayed = await selectBrowserButton.isDisplayed()
    if (displayed) {
        await selectBrowserButton.waitForClickable();
        await selectBrowserButton.click();

        const proceedButton = await $('button*=Proceed');
        await proceedButton.waitForClickable();
        await proceedButton.click();
    }
};

exports.issue = async () => {
    const storeBtn = await $('#storeVCBtn');
    await storeBtn.waitForClickable();
    await storeBtn.click();
};

exports.finish = async () => {
    const successMsgIcon = await $('#success-img');
    await successMsgIcon.waitForExist();

    const successMsg = await $('div*=Credential is saved successfully');
    await successMsg.waitForExist();

    console.log('saved credential successfully !!')
};

/*************************** Helper functions ******************************/

async function _changeProfile({profile}) {
    if (profile) {
        const profileSettings = await $('#profileSettings')
        await profileSettings.waitForExist();
        await profileSettings.click();

        const btnID = ISSUER_PROFILES[profile]

        const selectProfile = await $(btnID);
        await selectProfile.waitForExist({timeout});
        await selectProfile.click();

        const saveProfile = await $('#saveProfile')
        await saveProfile.waitForExist();
        await saveProfile.click();
    }
}
