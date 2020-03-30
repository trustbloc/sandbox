/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
 */

$(document).ready(function () {

    var profileVal = $('#vcsProfile').val()
    var actionRequested = $('#actionRequested').val()
    $formSubmit =	$('#formSubmit');

    $('#profile').on('change', function(){
        if($(this).val() != ""){
            $('#vcsProfile').val($(this).val());
        }else{
            $('#vcsProfile').val('');
        }
    });

    $('#chooseOption').on('change', function(){
        if($(this).val() != ""){
            $('#actionRequested').val($(this).val());
        }else{
            $('#actionRequested').val('');
        }
    });


    $('#demoSetupForm').submit(function() {
        if ($('#chooseOption').val() == "studentCard") {
            $('#demoSetupForm').attr('action', 'view/college.html');
        } else if ($('#chooseOption').val() == "travelCard") {
            $('#demoSetupForm').attr('action', 'view/travel.html');
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

