<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

<template>
    <div class="mx-auto bg-center bg">
        <router-view></router-view>
    </div>
</template>

<script>
    export default {
      name: 'App',
      watch: {
          $route: {
              immediate: true,
              handler(to) {
                  document.title = to.meta.title || 'Login Page';
              }
          },
      }
  };
</script>
