/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import Login from "@/pages/views/Login";
import Consent from "@/pages/views/Consent";
import BankLogin from "@/pages/views/BankLogin";
import BankConsent from "@/pages/views/BankConsent";
import UploadCred from "@/pages/views/uploadCred";
import UploadCredConsent from "@/pages/views/uploadCredConsent";


const routes = [
    {
        path: "/login",
        component: Login,
        name: 'Login',
        meta: { title: 'Login Page' }
    },
    {
        path: '/consent',
        component: Consent,
        name: 'Consent',
        meta: { title: 'Consent Page' }
    },
    {
        path: '/banklogin',
        component: BankLogin,
        name: 'BankLogin',
        meta: { title: 'Bank Login Page' }
    },
    {
        path: '/bankconsent',
        component: BankConsent,
        name: 'BankConsent',
        meta: { title: 'Bank Consent Page' }
    },
    {
        path: '/uploadcred',
        component: UploadCred,
        name: 'UploadCred',
        meta: { title: 'Upload Credential' }
    },
    {
        path: '/uploadcredconsent',
        component: UploadCredConsent,
        name: 'UploadCredConsent',
        meta: { title: 'Consent Page' }
    } 
];

export default routes;
