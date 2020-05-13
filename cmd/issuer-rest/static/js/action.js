/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
 */

$(document).ready(function () {

    var profileVal = $('#vcsProfile').val()
    var actionRequested = $('#actionRequested').val()

    $('#profile').on('change', function () {
        if ($(this).val() != "") {
            $('#vcsProfile').val($(this).val());
        } else {
            $('#vcsProfile').val('');
        }
    });

    $('#chooseOption').on('change', function () {
        if ($(this).val() != "") {
            $('#actionRequested').val($(this).val());
        } else {
            $('#actionRequested').val('');
        }
    });

    $('#demoSetupForm').submit(function () {
        if ($('#chooseOption').val() == "studentCard") {
            $('#scope').val("StudentCard");

            $('#demoSetupForm').attr('action', '/login?');
        } else if ($('#chooseOption').val() == "travelCard") {
            $('#scope').val("TravelCard");

            $('#demoSetupForm').attr('action', '/login?');
        } else if ($('#chooseOption').val() == "universityDegree") {
            $('#scope').val("UniversityDegreeCredential");

            $('#demoSetupForm').attr('action', '/login?');
        } else if ($('#chooseOption').val() == "prCard") {
            $('#scope').val("PermanentResidentCard");

            $('#demoSetupForm').attr('action', '/login?');
        } else if ($('#chooseOption').val() == "cmtr") {
            $('#scope').val("CertifiedMillTestReport");

            $('#demoSetupForm').attr('action', '/login?');
        } else if ($('#chooseOption').val() == "cpr") {
            $('#scope').val("CrudeProductCredential");

            $('#demoSetupForm').attr('action', '/login?');
        } else if ($('#chooseOption').val() == "kiosk") {
            $('#demoSetupForm').attr('action', 'reader/qrReader.html');
        } else if ($('#chooseOption').val() == "revokeCard") {
            $('#demoSetupForm').attr('action', 'view/revoke.html');
        } else {
            $('#message').text("Profile or Action is not selected").show().fadeOut(2000);
            event.preventDefault();
        }
    });
});

