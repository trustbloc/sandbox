"use strict";
/**
 * An asynchronous bootstrap function that runs before
 * your application gets started.
 *
 * This gives you an opportunity to set up your data model,
 * run jobs, or perform some special logic.
 *
 * See more details here: https://strapi.io/documentation/3.0.0-beta.x/concepts/configurations.html#bootstrap
 */
const findAuthenticatedRole = async () => {
    const result = await strapi
        .query("role", "users-permissions")
        .findOne({type: "authenticated"});
    return result;
};

const setDefaultPermissions = async () => {
    const role = await findAuthenticatedRole();
    const permissions = await strapi
        .query("permission", "users-permissions")
        .find({type: "application", role: role.id});
    await Promise.all(
        permissions.map(p =>
            strapi
                .query("permission", "users-permissions")
                .update({id: p.id}, {enabled: true})
        )
    );
};

module.exports = async () => {
    await setDefaultPermissions();
};