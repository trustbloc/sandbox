/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import Vue from 'vue';
import App from './App.vue';
import VueRouter from "vue-router";
import routes from "./router/index";

import "@fortawesome/fontawesome-free/css/all.min.css";

import '@/assets/styles/tailwind.css';

Vue.config.productionTip = false

// configure router
const router = new VueRouter({
  mode:'history',
  routes, // short for routes: routes
  linkExactActiveClass: "nav-item active"
});

Vue.use(VueRouter);

new Vue({
  el: "#app",
  render: h => h(App),
  router
});
