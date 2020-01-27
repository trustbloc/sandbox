#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#


/usr/local/bin/docker-entrypoint.sh strapi

# generate the student cards api and model
GENERATE_STUDENTAPI_COMMAND="strapi generate:api studentcards StudentID:string Name:string Email:string University:string Semester:string"

$GENERATE_STUDENTAPI_COMMAND

# generate the transcript api and model
GENERATE_TRANSCRIPT_COMMAND="strapi generate:api transcripts StudentID:string Name:string University:string Course:string Status:string TotalCredits:string"

$GENERATE_TRANSCRIPT_COMMAND
