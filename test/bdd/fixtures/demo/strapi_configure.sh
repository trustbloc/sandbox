#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

apk --no-cache add curl jq

# generate the student cards api and model
GENERATE_STUDENTAPI_COMMAND="strapi generate:api studentcards StudentID:string Name:string Email:string University:string Semester:string"

$GENERATE_STUDENTAPI_COMMAND

# generate the transcript api and model
GENERATE_TRANSCRIPT_COMMAND="strapi generate:api transcripts StudentID:string Name:string University:string Course:string Status:string TotalCredits:string"

$GENERATE_TRANSCRIPT_COMMAND

# generate the travel card api and model
GENERATE_TRAVELCARD_COMMAND="strapi generate:api travelcards TravelCardID:string GivenName:string Surname:string Sex:string Country:string DOB:string IssueDate:string CardExpires:string"

$GENERATE_TRAVELCARD_COMMAND

sleep 30

# Create admin user
n=0
until [ $n -ge 5 ]
do
   token=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"username":"strapi1","email":"user@strapi.io","password":"strapi"}' \
   http://strapi:1337/admin/auth/local/register | jq -r '.jwt')
   echo "token: $token"
   if [ -n "$token" ]
   then
     break
   fi
   n=$[$n+1]
   sleep 5
done

if [ -z "$token" ]
   then
     echo "strapi token is empty"
     exit
fi

# Add student card data
result=$(curl --header "Content-Type: application/json" --header "Authorization: Bearer $token" \
   --request POST \
   --data '{"studentid":"1234568","name":"Foo","email":"foo@bar.com","university":"Faber College","semester":"3"}' \
   http://strapi:1337/studentcards | jq  -r ".error")
# check for error
if [ "$result" != "null" ]
   then
        echo "error insert studentcards data in strapi: $result"
fi

# Add transcripts data
result=$(curl --header "Content-Type: application/json" --header "Authorization: Bearer $token" \
   --request POST \
   --data '{"studentid":"323456898","name":"Foo","university":"Faber College","status":"graduated","totalcredits":"100","course":"Bachelors in Computing Science"}' \
   http://strapi:1337/transcripts | jq  -r ".error")
# check for error
if [ "$result" != "null" ]
   then
        echo "error insert studentcards data in strapi: $result"
fi

# Add travel card data
result=$(curl --header "Content-Type: application/json" --header "Authorization: Bearer $token" \
   --request POST \
   --data '{"travelcardid":"123-456-765","givenname":"Foo","surname":"Bar","sex":"M","country":"Canada","dob":"12-06-1989","issuedate":"01-06-2018","cardexpires":"01-06-2023"}' \
   http://strapi:1337/travelcards | jq  -r ".error")
# check for error
if [ "$result" != "null" ]
   then
        echo "error insert travelcards data in strapi: $result"
fi

echo "STRAPI SETUP IS COMPLETED"


# Copy token to oathkeeper
sed -e "s/{TOKEN}/$token/g" /oathkeeper/rules/resource-server-template.json > /oathkeeper/rules/resource-server.json

echo "TOKEN IS COPIED"
