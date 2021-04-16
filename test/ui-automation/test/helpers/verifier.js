/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict';

const constants = require('./constants');

const FLOW_IDS = {
    'PermanentResidentCard': '#prCard',
    'VaccinationCertificate': '#vaccinationCertificate',
    'UniversityDegreeCredential': '#universityDegree',
    'StudentCard': '#studentCard',
    'TravelCard': '#travelCard',
    'CrudeProductCredential': '#cpr',
    'CertifiedMillTestReport': '#cmtr',
}

/*************************** Public API ******************************/

exports.verify = async ({skipStatusCheck, credential}) => {
    if (skipStatusCheck) {
        const settings = await $('#profileSettings');
        await settings.waitForExist();
        await settings.click();

        const skipStatusCheck = await $('#verify-cred-status');
        await skipStatusCheck.waitForExist();
        await skipStatusCheck.waitForClickable();
        await skipStatusCheck.click();
    }

    const btnID = FLOW_IDS[credential]
    const verifyButton = await $(btnID);
    await verifyButton.waitForClickable();
    await verifyButton.click();
};

exports.finish = async () => {
    const successMsg = await $('#successMsg');
    await successMsg.waitForExist();
    expect(successMsg).toHaveText('Successfully Verified');

    const successMsgH4 = await $('h4=Presented Digital ID');
    await successMsgH4.waitForExist();

    console.log('verified credential successfully !!')
};

exports.adapterCredentials = async (btnID) => {
    const getCredentialButton = await $(btnID);
    await getCredentialButton.waitForClickable();
    await getCredentialButton.click();

    const selectBrowserButton = await $('button*=Browser Wallet');
    await selectBrowserButton.waitForClickable();
    await selectBrowserButton.click();

    const proceedButton = await $('button*=Proceed');
    await proceedButton.waitForClickable();
    await proceedButton.click();
};
