/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import Login from "@/pages/Login.vue";
import Consent from "@/pages/Consent.vue";
const routes = [
    {
        path: "/login",
        component: Login
    },
    {
        path: "/consent",
        component: Consent
    }
];
export default routes;
