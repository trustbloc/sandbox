/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

\! echo "Configuring MySQL users...";

-- Strapi
CREATE USER 'user'@'%' IDENTIFIED BY 'secret';
CREATE DATABASE strapi;
GRANT ALL PRIVILEGES ON strapi.* TO 'user'@'%';

-- Hydra (RP Adapter)
CREATE USER 'rpadapterhydra'@'%' IDENTIFIED BY 'secret';
CREATE DATABASE rpadapter_hydra;
GRANT ALL PRIVILEGES ON rpadapter_hydra.* TO 'rpadapterhydra'@'%';

/*
RP Adapter
*/
CREATE USER 'rpadapter'@'%' IDENTIFIED BY 'rpadapter-secret-pw';
GRANT ALL PRIVILEGES ON `rpadapter\_%` . * TO 'rpadapter'@'%';

/*
Issuer Adapter
*/
CREATE USER 'issueradapter'@'%' IDENTIFIED BY 'issueradapter-secret-pw';
GRANT ALL PRIVILEGES ON `issueradapter\_%` . * TO 'issueradapter'@'%';

/*
Router
*/
CREATE USER 'router'@'%' IDENTIFIED BY 'router-secret-pw';
GRANT ALL PRIVILEGES ON * . * TO 'router'@'%';

