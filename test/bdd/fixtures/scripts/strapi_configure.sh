#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

apk --no-cache add curl jq

# generate the user api and model
GENERATE_USERAPI_COMMAND="strapi generate:api users UserID:string Name:string Email:string"

$GENERATE_USERAPI_COMMAND

# generate the student cards api and model
GENERATE_STUDENTAPI_COMMAND="strapi generate:api studentcards UserID:string StudentID:string Name:string Email:string University:string Semester:string"

$GENERATE_STUDENTAPI_COMMAND

# generate the transcript api and model
GENERATE_TRANSCRIPT_COMMAND="strapi generate:api transcripts UserID:string StudentID:string Name:string University:string Course:string Status:string TotalCredits:string"

$GENERATE_TRANSCRIPT_COMMAND

# generate the travel card api and model
GENERATE_TRAVELCARD_COMMAND="strapi generate:api travelcards UserID:string TravelCardID:string Name:string Sex:string Country:string DOB:string IssueDate:string CardExpires:string"

$GENERATE_TRAVELCARD_COMMAND

# generate the pr card api and model
GENERATE_PRCARD_COMMAND="strapi generate:api prcards UserID:string GivenName:string FamilyName:string Gender:string Image:string ResidentSince:string LPRCategory:string LPRNumber:string BirthCountry:string BirthDate:string"

$GENERATE_PRCARD_COMMAND

sleep 30

# Create admin user
n=0
until [ $n -ge 5 ]
do
   token=$(curl --header "Content-Type: application/json" \
   --request POST \
   --data '{"username":"strapi","email":"user@strapi.io","password":"strapi"}' \
   http://strapi:1337/admin/auth/local/register | jq -r '.jwt')
   echo "token: $token"
   if [ -n "$token" ]
   then
     break
   fi
   n=$((n+1))
   sleep 5
done

if [ -z "$token" ]
   then
     echo "strapi token is empty"
     exit
fi

# Add user data
result=$(curl --header "Content-Type: application/json" --header "Authorization: Bearer $token" \
   --request POST \
   --data '{"userid":"100","name":"Foo Bar","email":"foo@bar.com"}' \
   http://strapi:1337/users | jq  -r ".error")
# check for error
if [ "$result" != "null" ]
   then
        echo "error insert user data in strapi: $result"
fi

# Add student card data for above created user
result=$(curl --header "Content-Type: application/json" --header "Authorization: Bearer $token" \
   --request POST \
   --data '{"userid":"100","studentid":"1234568","name":"Foo","email":"foo@bar.com","university":"Faber College","semester":"3"}' \
   http://strapi:1337/studentcards | jq  -r ".error")
# check for error
if [ "$result" != "null" ]
   then
        echo "error insert studentcards data in strapi: $result"
fi

# Add transcripts data for above created user
result=$(curl --header "Content-Type: application/json" --header "Authorization: Bearer $token" \
   --request POST \
   --data '{"userid":"100","studentid":"323456898","name":"Foo","university":"Faber College","status":"graduated","totalcredits":"100","course":"Bachelors in Computing Science"}' \
   http://strapi:1337/transcripts | jq  -r ".error")
# check for error
if [ "$result" != "null" ]
   then
        echo "error insert studentcards data in strapi: $result"
fi

# Add travel card data for above created user
result=$(curl --header "Content-Type: application/json" --header "Authorization: Bearer $token" \
   --request POST \
   --data '{"userid":"100","travelcardid":"123-456-765","name":"Foo","sex":"M","country":"Canada","dob":"12-06-1989","issuedate":"01-06-2018","cardexpires":"01-06-2023"}' \
   http://strapi:1337/travelcards | jq  -r ".error")
# check for error
if [ "$result" != "null" ]
   then
        echo "error insert travelcards data in strapi: $result"
fi

# Add pr card data for above created user
result=$(curl --header "Content-Type: application/json" --header "Authorization: Bearer $token" \
   --request POST \
   --data '{"userid":"100","givenname":"Alice","familyname":"Smith","gender":"Female","image":"data:image/png;base64,iVBORw0KGgo...kJggg==","residentsince":"2015-01-01","lprcategory":"C09","lprnumber":"01-06-2023","birthcountry":"Bahamas","birthdate":"1958-08-17"}' \
   http://strapi:1337/prcards | jq  -r ".error")
# check for error
if [ "$result" != "null" ]
   then
        echo "error insert prcards data in strapi: $result"
fi

echo "STRAPI SETUP IS COMPLETED"

# Copy token to oathkeeper
sed -e "s/{TOKEN}/$token/g" /oathkeeper/rules/resource-server-template.json > /oathkeeper/rules/resource-server.json

echo "TOKEN IS COPIED"
