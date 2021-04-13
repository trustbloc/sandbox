/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

\! echo "Configuring MySQL users...";

-- Strapi
CREATE USER 'user'@'%' IDENTIFIED BY 'secret';
CREATE DATABASE strapi;
GRANT ALL PRIVILEGES ON strapi.* TO 'user'@'%';
