#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

STRAPI_FOLDER="test/bdd/fixtures/cms/app"

# Strapi command can only be used inside a Strapi project
cd $STRAPI_FOLDER

SDIR=api/studentcards
if [ -d "$SDIR" ] ; then
    echo "$SDIR deleting!"
    rm -rf "$SDIR"
fi

TDIR=api/transcripts
if [ -d "$TDIR" ] ; then
    echo "$TDIR deleting!"
    rm -rf "$TDIR"
fi

#Make sure Node.js and npm are properly on machine
echo "Generating Strapi API"


echo "Inside app folder to install APIs"

# generate the student cards api and model
GENERATE_STUDENTAPI_COMMAND="npx strapi generate:api studentcards StudentID:string Name:string University:string Semester:string"

$GENERATE_STUDENTAPI_COMMAND

# generate the transcript api and model
GENERATE_TRANSCRIPT_COMMAND="npx strapi generate:api transcripts StudentID:string Name:string University:string Course:string Status:string TotalCredits:string"

$GENERATE_TRANSCRIPT_COMMAND

sleep 20s

# This is assuming strapi is running on default 1337 port
cd ../../../../../build/bin
./strapi-demo create-demo-data --host-url http://localhost:1337
