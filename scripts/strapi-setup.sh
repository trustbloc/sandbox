#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

STRAPI_FOLDER="cms/app"

#Make sure Node.js and npm are properly on machine
echo "Generating Strapi API"

# Strapi command can only be used inside a Strapi project
cd $STRAPI_FOLDER
echo "Inside app folder to install APIs"

# generate the student cards api and model
GENERATE_STUDENTAPI_COMMAND="npx strapi generate:api studentcards StudentID:string Name:string University:string Semester:integer IssueDate:date"

$GENERATE_STUDENTAPI_COMMAND

# generate the transcript api and model
GENERATE_TRANSCRIPT_COMMAND="npx strapi generate:api transcripts StudentID:string Name:string University:string Course:string IssueDate:date Status:string TotalCredits:integer"

$GENERATE_TRANSCRIPT_COMMAND

sleep 20s

# This is assuming strapi is running on default 1337 port
cd ../../build/bin
./strapi-demo create-demo-data --admin-url http://localhost:1337
