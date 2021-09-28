/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

CREATE USER loginconsent with encrypted password 'loginconsent-secret-pw';
CREATE DATABASE loginconsent;

CREATE USER strapi with encrypted password 'strapi-secret-pw';
CREATE DATABASE strapi;
